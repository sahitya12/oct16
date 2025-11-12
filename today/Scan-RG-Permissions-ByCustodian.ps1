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

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force

Ensure-Dir -Path $OutputDir | Out-Null

# pick CSV
$csvPath = if ($adh_subscription_type -eq 'prd') { $ProdCsvPath } else { $NonProdCsvPath }
if (-not (Test-Path -LiteralPath $csvPath)) { throw "CSV not found: $csvPath" }

$inputRows = Import-Csv -Path $csvPath

# login
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
  throw "Azure login failed."
}

# subscriptions (uses the new rules)
$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
$result = @()

if (-not $subs -or $subs.Count -eq 0) {
  $result += [pscustomobject]@{
    SubscriptionName     = ''
    SubscriptionId       = ''
    Environment          = $adh_subscription_type
    InputResourceGroup   = ''
    ScannedResourceGroup = ''
    RoleDefinition       = ''
    InputAdGroup         = ''
    ResolvedAdGroup      = ''
    RGStatus             = 'SKIPPED'
    PermissionStatus     = 'SKIPPED'
    Details              = 'No subscriptions returned'
  }
} else {
  foreach ($sub in $subs) {
    Set-ScContext -Subscription $sub

    foreach ($row in $inputRows) {
      $rgName = $row.resource_group_name -replace '<Custodian>', $adh_group
      $aadGrp = $row.ad_group_name       -replace '<Custodian>', $adh_group
      $role   = $row.role_definition_name

      $rg = Get-AzResourceGroup -Name $rgName -ErrorAction SilentlyContinue
      $rgStatus = if ($rg) { 'EXISTS' } else { 'NOT_FOUND' }

      $grp = Get-AzADGroup -DisplayName $aadGrp -ErrorAction SilentlyContinue
      $groupId = $grp?.Id

      $hasRole = $false
      if ($rg -and $groupId) {
        $hasRole = @( Get-AzRoleAssignment -ObjectId $groupId -ResourceGroupName $rgName -ErrorAction SilentlyContinue |
                      Where-Object { $_.RoleDefinitionName -eq $role } ).Count -gt 0
      }
      $permStatus = if ($hasRole) { 'EXISTS' } else { 'NOT_EXISTS' }

      $details =
        if (-not $rg) { 'RG not found' }
        elseif (-not $grp) { 'AD group not found' }
        elseif (-not $hasRole) { 'Role assignment missing' }
        else { 'OK' }

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
        Details              = $details
      }
    }
  }
}

$csvOut = New-StampedPath -BaseDir $OutputDir -Prefix ("rg_permissions_{0}_{1}" -f $adh_group,$adh_subscription_type) -Ext 'csv'
Write-CsvSafe     -Rows $result -Path $csvOut
Convert-CsvToHtml -CsvPath $csvOut -HtmlPath ([System.IO.Path]::ChangeExtension($csvOut,'html')) -Title "RG Permissions ($adh_group / $adh_subscription_type) $BranchName"
