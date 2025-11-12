#requires -Modules Az.Accounts,Az.Resources
param(
  [Parameter(Mandatory)][string]$TenantId,
  [Parameter(Mandatory)][string]$ClientId,
  [Parameter(Mandatory)][string]$ClientSecret,
  [Parameter()][string]$ProdCsvPath,
  [Parameter()][string]$NonProdCsvPath,
  [Parameter(Mandatory)][string]$adh_group,
  [ValidateSet('nonprd','prd')][string]$adh_subscription_type='nonprd',
  [Parameter(Mandatory)][string]$OutputDir,
  [string]$BranchName=''
)

# --- import shared helpers (Ensure-Dir, Write-CsvSafe, Convert-CsvToHtml, Get-ScSubscriptions, Set-ScContext, Connect-ScAz) ---
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

Ensure-Dir -Path $OutputDir | Out-Null

# Select the correct CSV for the chosen environment
$csvPath = if ($adh_subscription_type -eq 'prd') { $ProdCsvPath } else { $NonProdCsvPath }
if (-not (Test-Path -LiteralPath $csvPath)) {
  throw "CSV not found: $csvPath"
}

# Azure login
Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret

# Read input rows
$input = Import-Csv -Path $csvPath

# Resolve subscriptions for the ADH group + environment
$subs = Get-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type

$rows = @()

foreach ($sub in $subs) {
  Set-ScContext -Subscription $sub

  foreach ($r in $input) {
    # Replace placeholder with actual group (KTK, VTK, etc.)
    $resolvedRg  = ($r.resource_group_name  -replace '<Custodian>', $adh_group)
    $resolvedAad = ($r.ad_group_name        -replace '<Custodian>', $adh_group)
    $roleName    = $r.role_definition_name

    # Look up current role assignments (RG scope) for the resolved AAD group
    $scope = "/subscriptions/$($sub.Id)/resourceGroups/$resolvedRg"
    try {
      $assignments = Get-AzRoleAssignment -Scope $scope -ErrorAction Stop | Where-Object {
        $_.DisplayName -eq $resolvedAad -and $_.RoleDefinitionName -eq $roleName
      }
      $perm = if ($assignments) { 'Present' } else { 'Missing' }
      $detail = if ($assignments) { ($assignments | Select-Object -First 1).ObjectId } else { '' }
      $rgExists = (Get-AzResourceGroup -Name $resolvedRg -ErrorAction SilentlyContinue) -ne $null
      $rgStatus = if ($rgExists) { 'Exists' } else { 'NotFound' }
    }
    catch {
      $perm = 'Error'
      $rgStatus = 'Unknown'
      $detail = $_.Exception.Message
    }

    $rows += [pscustomobject]@{
      SubscriptionName    = $sub.Name
      SubscriptionId      = $sub.Id
      Environment         = $adh_subscription_type
      InputResourceGroup  = $r.resource_group_name
      ScannedResourceGroup= $resolvedRg
      RoleDefinition      = $roleName
      InputAdGroup        = $r.ad_group_name
      ResolvedAdGroup     = $resolvedAad
      RGStatus            = $rgStatus
      PermissionStatus    = $perm
      Details             = $detail
    }
  }
}

# Write CSV + HTML
$csvOut = New-StampedPath -BaseDir $OutputDir -Prefix ("rg_permissions_{0}_{1}" -f $adh_group,$adh_subscription_type) -Ext 'csv'
Write-CsvSafe -Rows $rows -Path $csvOut
Convert-CsvToHtml -CsvPath $csvOut -HtmlPath ([IO.Path]::ChangeExtension($csvOut,'html')) -Title "RG Permissions ($adh_group / $adh_subscription_type) $BranchName"
