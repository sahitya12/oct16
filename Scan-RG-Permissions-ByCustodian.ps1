<#PSScriptInfo
.VERSION 1.0.0
.GUID 5b7e0ac1-6e6a-4a1e-9b6f-1d0f0a8b9a11
.AUTHOR Platform Eng
#>

<#
.SYNOPSIS
  Scan all Resource Group role assignments for a given ADH custodian and environment.

.DESCRIPTION
  - Authenticates to Azure using a Service Principal.
  - Resolves the correct subscription(s) for the provided ADH custodian (adh_group) and environment
    using Resolve-AdhSubscriptions from Common.psm1 (e.g., KTK→ADHPlatform mapping, nonprd/prd prefixes).
  - Enumerates all Resource Groups and collects role assignments at the RG scope.
  - Exports results to timestamped CSV and HTML files in OutputDir.

.PARAMETER TenantId
  Entra ID tenant ID of the SPN.

.PARAMETER ClientId
  Application (client) ID of the SPN.

.PARAMETER ClientSecret
  Client secret of the SPN.

.PARAMETER ProdCsvPath
.PARAMETER NonProdCsvPath
  Optional. Accepted for pipeline compatibility. Not used by this scan script.

.PARAMETER adh_group
  ADH custodian key (e.g., KTK, MDM, NHH, …).

.PARAMETER adh_subscription_type
  'nonprd' or 'prd'. Defaults to 'nonprd'.

.PARAMETER OutputDir
  Directory where CSV/HTML outputs will be written.

.PARAMETER BranchName
  Optional string to decorate report titles (e.g., pipeline branch).

.OUTPUTS
  CSV + HTML files placed in OutputDir. The CSV contains:
    SubscriptionName, SubscriptionId, Environment, Custodian,
    ResourceGroup, RoleDefinition, PrincipalName, PrincipalType,
    PrincipalId, Scope

.EXAMPLE
  .\Scan-RG-Permissions-ByCustodian.ps1 `
      -TenantId $TENANT -ClientId $APPID -ClientSecret $SECRET `
      -adh_group KTK -adh_subscription_type nonprd `
      -OutputDir 'C:\a\_reports'
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$TenantId,
  [Parameter(Mandatory)][string]$ClientId,
  [Parameter(Mandatory)][string]$ClientSecret,

  # Accepted for pipeline compatibility; not used by this scan script.
  [string]$ProdCsvPath,
  [string]$NonProdCsvPath,

  [Parameter(Mandatory)][string]$adh_group,

  [ValidateSet('nonprd','prd')]
  [string]$adh_subscription_type = 'nonprd',

  [Parameter(Mandatory)][string]$OutputDir,
  [string]$BranchName = ''
)

Write-Host "Starting: Run sanitychecks/scripts/Scan-RG-Permissions-ByCustodian.ps1" -ForegroundColor Cyan
Write-Host "====================================================================="

# --- Modules & helpers --------------------------------------------------------
Import-Module Az.Accounts, Az.Resources -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

# --- Connect ------------------------------------------------------------------
try {
  Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
  Write-Host "Connected to Azure tenant: $TenantId" -ForegroundColor Green
}
catch {
  throw "Azure authentication failed. $($_.Exception.Message)"
}

# Informative: accept but ignore CSV parameters (scan mode)
if ($PSBoundParameters.ContainsKey('ProdCsvPath') -or
    $PSBoundParameters.ContainsKey('NonProdCsvPath')) {
  Write-Host "Info: ProdCsvPath/NonProdCsvPath were provided. This script performs a scan only and does not use them." -ForegroundColor Yellow
}

# --- Resolve target subscriptions ---------------------------------------------
$subs = @()
try {
  # Use your resolver; it returns a preferred single subscription.
  $sub = Resolve-AdhSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
  if ($null -ne $sub) { $subs = @($sub) }
}
catch {
  throw "Failed to resolve subscriptions for '$adh_group' ($adh_subscription_type). $($_.Exception.Message)"
}

if (-not $subs -or $subs.Count -eq 0) {
  throw "No matching subscriptions found for adh_group='$adh_group' environment='$adh_subscription_type'."
}

Write-Host "Found $($subs.Count) subscription(s) for $adh_group ($adh_subscription_type)." -ForegroundColor Yellow

# --- Prepare outputs -----------------------------------------------------------
Ensure-Dir -Path $OutputDir
$csvPath  = New-StampedPath -BaseDir $OutputDir -Prefix "rg_permissions_${adh_group}_$adh_subscription_type"
$htmlPath = $csvPath -replace '\.csv$', '.html'

Write-Host "CSV will be written to:  $csvPath"
Write-Host "HTML will be written to: $htmlPath"

# --- Scan ---------------------------------------------------------------------
$rows = New-Object System.Collections.Generic.List[object]

foreach ($sub in $subs) {
  Write-Host "Processing subscription: $($sub.Name) [$($sub.Id)]" -ForegroundColor Cyan
  try {
    Set-AzContext -SubscriptionId $sub.Id -ErrorAction Stop | Out-Null

    $rgs = Get-AzResourceGroup -ErrorAction Stop
    Write-Host "  Resource groups found: $($rgs.Count)" -ForegroundColor DarkGray

    foreach ($rg in $rgs) {
      $scope = $rg.ResourceId   # "/subscriptions/{id}/resourceGroups/{name}"

      # Role assignments at RG scope
      $assignments = Get-AzRoleAssignment -Scope $scope -ErrorAction SilentlyContinue

      if (-not $assignments) {
        # Still emit a line to show the RG was scanned, even if empty
        $rows.Add([pscustomobject]@{
          SubscriptionName = $sub.Name
          SubscriptionId   = $sub.Id
          Environment      = $adh_subscription_type
          Custodian        = $adh_group
          ResourceGroup    = $rg.ResourceGroupName
          RoleDefinition   = ''
          PrincipalName    = ''
          PrincipalType    = ''
          PrincipalId      = ''
          Scope            = $scope
        })
        continue
      }

      foreach ($a in $assignments) {
        $rows.Add([pscustomobject]@{
          SubscriptionName = $sub.Name
          SubscriptionId   = $sub.Id
          Environment      = $adh_subscription_type
          Custodian        = $adh_group
          ResourceGroup    = $rg.ResourceGroupName
          RoleDefinition   = $a.RoleDefinitionName
          PrincipalName    = $a.DisplayName
          PrincipalType    = $a.ObjectType
          PrincipalId      = $a.ObjectId
          Scope            = $scope
        })
      }
    }
  }
  catch {
    Write-Warning "Error while scanning subscription $($sub.Name): $($_.Exception.Message)"
  }
}

# --- Write outputs -------------------------------------------------------------
try {
  Write-CsvSafe -Rows $rows -Path $csvPath
  Convert-CsvToHtml -CsvPath $csvPath -HtmlPath $htmlPath -Title "RG Permissions – $adh_group ($adh_subscription_type) $BranchName"
  Write-Host "Scan complete." -ForegroundColor Green
  Write-Host "CSV:  $csvPath"
  Write-Host "HTML: $htmlPath"
}
catch {
  throw "Failed to write report files. $($_.Exception.Message)"
}

Write-Host "====================================================================="
Write-Host "Done: Scan-RG-Permissions-ByCustodian.ps1" -ForegroundColor Cyan
