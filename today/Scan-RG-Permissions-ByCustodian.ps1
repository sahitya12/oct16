param(
  [Parameter(Mandatory)][string]$TenantId,
  [Parameter(Mandatory)][string]$ClientId,
  [Parameter(Mandatory)][string]$ClientSecret,
  [string]$ProdCsvPath,
  [string]$NonProdCsvPath,
  [Parameter(Mandatory)][string]$adh_group,
  [ValidateSet('nonprd','prd')][string]$adh_subscription_type='nonprd',
  [Parameter(Mandatory)][string]$OutputDir,
  [string]$BranchName=''
)

# Import helper
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force

Ensure-Dir -Path $OutputDir | Out-Null

# Determine CSV path
$csvPath = if ($adh_subscription_type -eq 'prd') { $ProdCsvPath } else { $NonProdCsvPath }
if (-not (Test-Path -LiteralPath $csvPath)) {
  throw "CSV not found: $csvPath"
}

$inputRows = Import-Csv -Path $csvPath
if (-not $inputRows -or $inputRows.Count -eq 0) {
  throw "CSV is empty or has no valid rows: $csvPath"
}

Write-Host "✅ Loaded $($inputRows.Count) rows from CSV: $csvPath"

# Authenticate
$connected = Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
if (-not $connected) {
  throw "❌ Azure connection failed."
}

# Get subscriptions
$subs = Get-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
if (-not $subs -or $subs.Count -eq 0) {
  throw "❌ No subscriptions found for $adh_group ($adh_subscription_type)"
}

Write-Host "✅ Found $($subs.Count) subscriptions for $adh_group ($adh_subscription_type)"

# Prepare results
$result = @()

foreach ($sub in $subs) {
  foreach ($row in $inputRows) {
    $rgName = $row.resource_group_name -replace '<Custodian>', $adh_group
    $aadGrp = $row.ad_group_name -replace '<Custodian>', $adh_group
    $role   = $row.role_definition_name

    $result += [pscustomobject]@{
      SubscriptionName   = $sub.Name
      SubscriptionId     = $sub.Id
      Environment        = $adh_subscription_type
      InputResourceGroup = $row.resource_group_name
      ScannedResourceGroup = $rgName
      InputAdGroup       = $row.ad_group_name
      ResolvedAdGroup    = $aadGrp
      RoleDefinition     = $role
      RGStatus           = 'Pending'
      PermissionStatus   = 'Pending'
      Details            = ''
    }
  }
}

if (-not $result -or $result.Count -eq 0) {
  throw "❌ No results generated — verify subscription and CSV inputs."
}

$csvOut = New-StampedPath -BaseDir $OutputDir -Prefix ("rg_permissions_{0}_{1}" -f $adh_group,$adh_subscription_type) -Ext 'csv'
Write-CsvSafe -Rows $result -Path $csvOut
Convert-CsvToHtml -CsvPath $csvOut -HtmlPath ([System.IO.Path]::ChangeExtension($csvOut,'html')) -Title "RG Permissions ($adh_group / $adh_subscription_type) $BranchName"

Write-Host "✅ RG Permissions Scan Completed. Output: $csvOut"
