<#
.SYNOPSIS
  Scans RG role assignments for a given ADH custodian across resolved subscriptions.
#>

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
$ProgressPreference    = 'SilentlyContinue'

Write-Host "Starting: Run sanitychecks/scripts/Scan-RG-Permissions-ByCustodian.ps1" -ForegroundColor Cyan
Write-Host "============================================================"

# --- Import Az modules ---
Import-Module Az.Accounts, Az.Resources -ErrorAction Stop

# --- Try to import Common.psm1 with a robust path probe ---
$moduleLoaded = $false
$tryPaths = @(
  (Join-Path $PSScriptRoot 'Common.psm1'),
  (Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts\Common.psm1'),
  (Join-Path (Split-Path $PSScriptRoot -Parent) 'Common.psm1')
)

foreach ($p in $tryPaths) {
  if (Test-Path -LiteralPath $p) {
    try {
      Import-Module $p -Force -ErrorAction Stop
      $moduleLoaded = $true
      break
    } catch {}
  }
}

# --- Minimal fallbacks if module import failed (so your demo never blocks) ---
if (-not $moduleLoaded) {
  Write-Warning "Common.psm1 not found or not exported. Using local fallback helpers."

  function Ensure-Dir {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
      New-Item -ItemType Directory -Path $Path | Out-Null
    }
  }

  function New-StampedPath {
    param(
      [Parameter(Mandatory)][string]$BaseDir,
      [Parameter(Mandatory)][string]$Prefix,
      [string]$Ext='csv'
    )
    $ts = Get-Date -Format 'yyyyMMdd_HHmmss'
    return (Join-Path $BaseDir "$($Prefix)_$ts.$Ext")
  }

  function Write-CsvSafe {
    param(
      [Parameter(Mandatory)]$Rows,
      [Parameter(Mandatory)][string]$Path
    )
    $dir = Split-Path $Path -Parent
    if ($dir) { if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null } }
    $Rows | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
  }

  function Convert-CsvToHtml {
    param(
      [Parameter(Mandatory)][string]$CsvPath,
      [Parameter(Mandatory)][string]$HtmlPath,
      [string]$Title = 'Report'
    )
    $table = Import-Csv $CsvPath | ConvertTo-Html -Title $Title -PreContent "<h2>$Title</h2>"
    Set-Content -Path $HtmlPath -Value $table -Encoding UTF8
  }

  function Resolve-AdhSubscriptions {
    [CmdletBinding()]
    param(
      [Parameter(Mandatory)][ValidatePattern('^[A-Za-z]{2,}$')][string]$AdhGroup,
      [ValidateSet('nonprd','prd')][string]$Environment='nonprd',
      [switch]$All,
      [switch]$Loose
    )

    $g = $AdhGroup.Trim().ToUpperInvariant()
    $envPrefix = if ($Environment -eq 'prd') { 'prd_azure_' } else { 'dev_azure_' }
    $specialMap = @{ 'KTK' = 'ADHPlatform' }

    $variants = New-Object System.Collections.Generic.List[string]
    if ($specialMap.ContainsKey($g)) {
      $variants.Add($specialMap[$g])
    } else {
      $first = $g.Substring(0,1)
      $variants.Add("ADH$g")
      $variants.Add("ADH$first$g")
      if ($Loose) { $variants.Add("ADH*$g*") }
    }

    $allSubs = Get-AzSubscription
    $matches = @()
    foreach ($v in $variants) {
      $pattern = "$envPrefix*_*$v"
      $matches += $allSubs | Where-Object { $_.Name -like $pattern }
    }
    $matches = $matches | Sort-Object Name -Unique
    if (-not $matches) { throw "No subscriptions matched for '$g' ($Environment). Tried: $($variants -join ', ')" }
    if ($All) { return $matches }

    function Get-Rank([string]$name) {
      if     ($name -like "$envPrefix*_ADH$g") { 0 }
      elseif ($name -like "$envPrefix*_ADH$($g.Substring(0,1))$g") { 1 }
      elseif ($name -like "$envPrefix*_ADHPlatform") { 2 }
      else { 9 }
    }
    return ($matches | Sort-Object @{Expression={ Get-Rank $_.Name }}, @{Expression='Name'} | Select-Object -First 1)
  }
}

# --- Login (Service Principal) ---
Write-Host "Connecting to Azure using Service Principal credentials..." -ForegroundColor Cyan
$secure = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
$cred   = [pscredential]::new($ClientId, $secure)
Connect-AzAccount -ServicePrincipal -Tenant $TenantId -Credential $cred | Out-Null
Write-Host "Connected successfully to tenant $TenantId" -ForegroundColor Green

# --- Resolve subscriptions for the ADH group / environment ---
$subs = @(Resolve-AdhSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type)
if (-not $subs -or $subs.Count -eq 0) {
  throw "No matching subscriptions found for adh_group='$adh_group' environment='$adh_subscription_type'."
}
Write-Host "Found $($subs.Count) subscription(s) for $adh_group ($adh_subscription_type)" -ForegroundColor Yellow

# --- Prepare outputs ---
Ensure-Dir -Path $OutputDir
$csvOut  = New-StampedPath -BaseDir $OutputDir -Prefix "rg_permissions_${adh_group}_$adh_subscription_type"
$htmlOut = [IO.Path]::ChangeExtension($csvOut, '.html')

$rows = @()

foreach ($sub in $subs) {
  Write-Host "Processing subscription: $($sub.Name)" -ForegroundColor Cyan
  try {
    Set-AzContext -SubscriptionId $sub.Id -Tenant $TenantId | Out-Null
    $rgs = Get-AzResourceGroup
    foreach ($rg in $rgs) {
      $assigns = Get-AzRoleAssignment -Scope $rg.ResourceId -ErrorAction SilentlyContinue
      foreach ($a in $assigns) {
        $rows += [pscustomobject]@{
          SubscriptionName = $sub.Name
          SubscriptionId   = $sub.Id
          Environment      = $adh_subscription_type
          ResourceGroup    = $rg.ResourceGroupName
          RoleDefinition   = $a.RoleDefinitionName
          PrincipalName    = $a.DisplayName
          PrincipalType    = $a.ObjectType
          Custodian        = $adh_group
        }
      }
    }
  } catch {
    Write-Warning "Error scanning subscription $($sub.Name): $($_.Exception.Message)"
  }
}

Write-CsvSafe -Rows $rows -Path $csvOut
Convert-CsvToHtml -CsvPath $csvOut -HtmlPath $htmlOut -Title "RG Permissions - $adh_group ($adh_subscription_type) $BranchName"

Write-Host "CSV:  $csvOut"
Write-Host "HTML: $htmlOut"
Write-Host "Completed RG Permission Scan for $adh_group ($adh_subscription_type)" -ForegroundColor Green
Write-Host "============================================================"
