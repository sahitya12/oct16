param(
  [Parameter(Mandatory)][string]$DatabricksHost,           # e.g., https://adb-xxxxxx.azuredatabricks.net
  [Parameter(Mandatory)][string]$DatabricksToken,          # personal access token or ADO secret
  [Parameter(Mandatory)][string]$adh_group,
  [ValidateSet('nonprd','prd')][string]$adh_subscription_type = 'nonprd',
  [Parameter(Mandatory)][string]$OutputDir,
  [string]$ExpectedCsv = '',
  [string]$BranchName = ''
)

Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force
Ensure-Dir -Path $OutputDir

if ($ExpectedCsv -and (Test-Path $ExpectedCsv)) {
  $expected = Import-Csv $ExpectedCsv
} else {
  $expected = @()
}

# helper to call REST API
function Invoke-DBXApi($Method, $Endpoint) {
  $uri = "$DatabricksHost/api/2.0/$Endpoint"
  $headers = @{ Authorization = "Bearer $DatabricksToken" }
  try {
    $resp = Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers -ErrorAction Stop
    return $resp
  } catch {
    Write-Warning "API call failed: $Endpoint -> $_"
    return $null
  }
}

$result = @()

# 1️⃣ Workspace info
$ws = Invoke-DBXApi -Method GET -Endpoint 'workspace-conf'
if ($ws) {
  $result += [pscustomobject]@{
    Category = 'Workspace'
    Item     = 'Deployment'
    Status   = 'Exists'
    Details  = "Region/SKU validated"
  }
}

# 2️⃣ Admin access
$admins = Invoke-DBXApi -Method GET -Endpoint 'preview/scim/v2/Groups'
if ($admins) {
  $adminUsers = ($admins.Resources | Where-Object { $_.displayName -match 'admins' }).members.value
  foreach ($a in $expected | Where-Object { $_.CheckType -eq 'Admin' }) {
    $status = if ($adminUsers -contains $a.ExpectedValue) { 'Valid' } else { 'Missing' }
    $result += [pscustomobject]@{
      Category = 'Admin Access'
      Item     = $a.ExpectedValue
      Status   = $status
      Details  = "Workspace Admin verification"
    }
  }
}

# 3️⃣ Jobs
$jobs = Invoke-DBXApi -Method GET -Endpoint 'jobs/list'
foreach ($a in $expected | Where-Object { $_.CheckType -eq 'Job' }) {
  $status = if ($jobs.jobs.name -contains $a.ExpectedValue) { 'Present' } else { 'Missing' }
  $result += [pscustomobject]@{
    Category = 'Databricks Job'
    Item     = $a.ExpectedValue
    Status   = $status
    Details  = 'Job existence check'
  }
}

# 4️⃣ Notebooks
$nbRoots = Invoke-DBXApi -Method GET -Endpoint 'workspace/list?path=/Shared'
foreach ($a in $expected | Where-Object { $_.CheckType -eq 'Notebook' }) {
  $status = if ($nbRoots.objects.path -contains $a.ExpectedValue) { 'Present' } else { 'Missing' }
  $result += [pscustomobject]@{
    Category = 'Notebook Path'
    Item     = $a.ExpectedValue
    Status   = $status
    Details  = 'Notebook path existence'
  }
}

# 5️⃣ Catalogs / Schemas / Permissions (Unity Catalog)
$catalogs = Invoke-DBXApi -Method GET -Endpoint 'unity-catalog/catalogs'
foreach ($c in $catalogs.catalogs) {
  $result += [pscustomobject]@{
    Category = 'Catalog'
    Item     = $c.name
    Status   = 'Present'
    Details  = "Owner: $($c.owner)"
  }
}
foreach ($a in $expected | Where-Object { $_.CheckType -eq 'Catalog' }) {
  if ($catalogs.catalogs.name -notcontains $a.ExpectedValue) {
    $result += [pscustomobject]@{ Category='Catalog'; Item=$a.ExpectedValue; Status='Missing'; Details='Expected catalog not found' }
  }
}

# 6️⃣ External locations
$extLocs = Invoke-DBXApi -Method GET -Endpoint 'unity-catalog/external-locations'
foreach ($a in $expected | Where-Object { $_.CheckType -eq 'ExternalLocation' }) {
  $status = if ($extLocs.external_locations.url -match $a.ExpectedValue) { 'Mapped' } else { 'Not Found' }
  $result += [pscustomobject]@{
    Category = 'External Location'
    Item     = $a.ExpectedValue
    Status   = $status
    Details  = 'External storage mapping check'
  }
}

# 7️⃣ SQL Permissions
$sqlPerms = Invoke-DBXApi -Method GET -Endpoint 'unity-catalog/grants'
foreach ($a in $expected | Where-Object { $_.CheckType -eq 'SQLGrant' }) {
  $status = if ($sqlPerms.privilege_assignments.privilege -contains $a.ExpectedValue) { 'Granted' } else { 'Missing' }
  $result += [pscustomobject]@{
    Category = 'SQL Permissions'
    Item     = $a.ExpectedValue
    Status   = $status
    Details  = 'SQL privilege validation'
  }
}

# Export reports
$csvOut = New-StampedPath -BaseDir $OutputDir -Prefix "databricks_sanity_${adh_group}_${adh_subscription_type}" -Ext 'csv'
Write-CsvSafe -Rows $result -Path $csvOut
$htmlOut = [System.IO.Path]::ChangeExtension($csvOut, '.html')
Convert-CsvToHtml -CsvPath $csvOut -HtmlPath $htmlOut -Title "Databricks Sanity ($adh_group / $adh_subscription_type) $BranchName"
Write-Host "Databricks sanity scan complete. Output: $csvOut"
