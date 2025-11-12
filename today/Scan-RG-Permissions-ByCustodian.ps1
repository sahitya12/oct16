param(
  [Parameter(Mandatory)][string]$TenantId,
  [Parameter(Mandatory)][string]$ClientId,
  [Parameter(Mandatory)][string]$ClientSecret,
  [string]$ProdCsvPath,
  [string]$NonProdCsvPath,
  [Parameter(Mandatory)][string]$adh_group,
  [ValidateSet('nonprd','prd')][string]$adh_subscription_type = 'nonprd',
  [Parameter(Mandatory)][string]$OutputDir,
  [string]$BranchName = ''
)

$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force
Ensure-Dir -Path $OutputDir | Out-Null

# --- Pick correct CSV ---
$csvPath = if ($adh_subscription_type -eq 'prd') { $ProdCsvPath } else { $NonProdCsvPath }
if (-not (Test-Path -LiteralPath $csvPath)) {
  throw "CSV not found: $csvPath"
}
$inputRows = Import-Csv -Path $csvPath

# --- Connect Azure ---
$connected = Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
if (-not $connected) {
  throw "Azure login failed – check service principal or credentials."
}

# --- Get subscriptions (correct helper) ---
$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
if (-not $subs -or $subs.Count -eq 0) {
  Write-Host "⚠ No subscriptions resolved for adh_group: $adh_group"
}

$result = @()

foreach ($sub in $subs) {
  Set-ScContext -Subscription $sub

  foreach ($row in $inputRows) {
    $rgName = $row.resource_group_name -replace '<Custodian>', $adh_group
    $aadGrp = $row.ad_group_name       -replace '<Custodian>', $adh_group
    $role   = $row.role_definition_name

    $rg = Get-AzResourceGroup -Name $rgName -ErrorAction SilentlyContinue
    $rgStatus = if ($rg) { 'EXISTS' } else { 'NOT_FOUND' }

    $roleAssignment = Get-AzRoleAssignment -ObjectId (Get-AzADGroup -DisplayName $aadGrp -ErrorAction SilentlyContinue).Id `
        -ResourceGroupName $rgName -ErrorAction SilentlyContinue |
        Where-Object { $_.RoleDefinitionName -eq $role }

    $permStatus = if ($roleAssignment) { 'EXISTS' } else { 'NOT_EXISTS' }

    $result += [pscustomobject]@{
      SubscriptionName     = $sub.Name
      SubscriptionId       = $sub.Id
      Environment          = $adh_subscription_type
      InputResourceGroup   = $row.resource_group_name
      ScannedResourceGroup = $rgName
      RoleDefinition       = $role
      InputAdGroup         = $row.ad_group_name
      ResolvedAdGroup      = $aadGrp
      RGStatus             = $rgStatus
      PermissionStatus     = $permStatus
      Details              = if ($rg) { 'OK' } else { 'RG not found' }
    }
  }
}

# --- Export results ---
$csvOut = New-StampedPath -BaseDir $OutputDir -Prefix ("rg_permissions_{0}_{1}" -f $adh_group, $adh_subscription_type) -Ext 'csv'
Write-CsvSafe -Rows $result -Path $csvOut
Convert-CsvToHtml -CsvPath $csvOut -HtmlPath ([System.IO.Path]::ChangeExtension($csvOut,'html')) -Title "RG Permissions ($adh_group / $adh_subscription_type) $BranchName"
