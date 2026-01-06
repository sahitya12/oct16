[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$TenantId,
  [Parameter(Mandatory)][string]$ClientId,
  [Parameter(Mandatory)][string]$ClientSecret,

  [Parameter(Mandatory)][string]$SubscriptionsCsvPath,

  # RG permissions inputs
  [Parameter(Mandatory)][string]$RgPermsNonPrdCsvPath,
  [Parameter(Mandatory)][string]$RgPermsPrdCsvPath,

  # ADLS inputs (env-specific)
  [Parameter(Mandatory)][string]$AdlsNonPrdInputCsvPath,
  [Parameter(Mandatory)][string]$AdlsPrdInputCsvPath,

  # KV inputs
  [Parameter(Mandatory)][string]$KvSecretsInputCsvPath,
  [Parameter(Mandatory)][string]$KvPermInputCsvPath,

  [Parameter(Mandatory)][string]$OutputRootDir,

  # toggles (DO NOT pass from YAML; defaults are fine)
  [bool]$RunRgPermissions = $true,
  [bool]$RunRgTags        = $true,
  [bool]$RunKvSecrets     = $true,
  [bool]$RunKvPermissions = $true,
  [bool]$RunKvFirewall    = $true,
  [bool]$RunVnet          = $true,
  [bool]$RunAdls          = $true,
  [bool]$RunAdf           = $true,
  [bool]$RunDatabricks    = $true,

  [string]$BranchName = ''
)

$ErrorActionPreference = 'Stop'

function Ensure-Dir([string]$p) {
  if (-not (Test-Path -LiteralPath $p)) {
    New-Item -ItemType Directory -Path $p -Force | Out-Null
  }
  return (Get-Item -LiteralPath $p).FullName
}

function Invoke-ChildScript {
  param(
    [Parameter(Mandatory)][string]$Title,
    [Parameter(Mandatory)][string]$ScriptPath,
    [Parameter(Mandatory)][string[]]$Args
  )

  Write-Host ""
  Write-Host "==================== $Title ====================" -ForegroundColor Cyan
  Write-Host "Script: $ScriptPath"

  & pwsh -NoProfile -File $ScriptPath @Args
  $code = $LASTEXITCODE

  if ($code -ne 0) {
    Write-Host "❌ $Title FAILED (exit code $code)" -ForegroundColor Red
    return $code
  }

  Write-Host "✅ $Title OK" -ForegroundColor Green
  return 0
}

# ------------------- Repo-relative paths -------------------
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path  # sanitychecks/
$scanRoot = Join-Path $repoRoot 'scripts'

# Match your repo file names (NO "-1")
$scanRgPerms   = Join-Path $scanRoot 'Scan-RG-Permissions-ByCustodian.ps1'
$scanRgTags    = Join-Path $scanRoot 'Scan-RG-Tags.ps1'
$scanKvSecrets = Join-Path $scanRoot 'Scan-KV-Secrets.ps1'
$scanKvPerms   = Join-Path $scanRoot 'Scan-KV-Permissions.ps1'
$scanKvFw      = Join-Path $scanRoot 'Scan-KV-Networks.ps1'
$scanAdls      = Join-Path $scanRoot 'Scan-ADLS-Acls.ps1'
$scanAdf       = Join-Path $scanRoot 'Scan-DataFactory.ps1'
$scanDbx       = Join-Path $scanRoot 'Scan-Databricks.ps1'
$scanVnet      = Join-Path $scanRoot 'Scan-VNet-Monthly.ps1'

# ------------------- Validate required files -------------------
foreach ($p in @(
  $SubscriptionsCsvPath,
  $RgPermsNonPrdCsvPath, $RgPermsPrdCsvPath,
  $AdlsNonPrdInputCsvPath, $AdlsPrdInputCsvPath,
  $KvSecretsInputCsvPath, $KvPermInputCsvPath,
  $scanRgPerms, $scanRgTags, $scanKvSecrets, $scanKvPerms, $scanKvFw,
  $scanAdls, $scanAdf, $scanDbx, $scanVnet
)) {
  if (-not (Test-Path -LiteralPath $p)) { throw "Required file not found: $p" }
}

# ------------------- Output root per run -------------------
$outRoot = Ensure-Dir $OutputRootDir
$runStamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$runDir = Ensure-Dir (Join-Path $outRoot ("allsubs_{0}" -f $runStamp))

Write-Host "Login TenantId : $TenantId"
Write-Host "Login ClientId : $ClientId"
Write-Host "ClientSecret   : present (hidden)"
Write-Host ""
Write-Host "Toggle summary:"
Write-Host "  RunRgPermissions = $RunRgPermissions"
Write-Host "  RunRgTags        = $RunRgTags"
Write-Host "  RunKvSecrets     = $RunKvSecrets"
Write-Host "  RunKvPermissions = $RunKvPermissions"
Write-Host "  RunKvFirewall    = $RunKvFirewall"
Write-Host "  RunVnet          = $RunVnet"
Write-Host "  RunAdls          = $RunAdls"
Write-Host "  RunAdf           = $RunAdf"
Write-Host "  RunDatabricks    = $RunDatabricks"
Write-Host ""
Write-Host "ALL-SUBSCRIPTIONS SANITY CHECK STARTED"
Write-Host "Output directory: $runDir"
Write-Host "Branch: $BranchName"

# ------------------- Read subscriptions master -------------------
$rows = Import-Csv -LiteralPath $SubscriptionsCsvPath
if (-not $rows -or $rows.Count -eq 0) { throw "No rows found in: $SubscriptionsCsvPath" }

$failures = New-Object System.Collections.Generic.List[string]

foreach ($r in $rows) {
  $adh_group = ("$($r.adh_group)").Trim()
  $adh_sub_group = ("$($r.adh_sub_group)").Trim()
  $env = ("$($r.adh_subscription_type)").Trim().ToLower()

  if ([string]::IsNullOrWhiteSpace($adh_group) -or [string]::IsNullOrWhiteSpace($env)) {
    Write-Host "Skipping row (missing adh_group or adh_subscription_type): $($r | ConvertTo-Json -Compress)" -ForegroundColor Yellow
    continue
  }
  if ($env -notin @('nonprd','prd')) {
    Write-Host "Skipping row (invalid env '$env'): $($r | ConvertTo-Json -Compress)" -ForegroundColor Yellow
    continue
  }

  $custToken = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) { $adh_group } else { "${adh_group}_${adh_sub_group}" }
  $subOut = Ensure-Dir (Join-Path $runDir ("{0}_{1}" -f $custToken, $env))

  Write-Host ""
  Write-Host "############################################################" -ForegroundColor Magenta
  Write-Host "# Custodian: $custToken | Env: $env" -ForegroundColor Magenta
  Write-Host "############################################################" -ForegroundColor Magenta

  $adlsCsv = if ($env -eq 'prd') { $AdlsPrdInputCsvPath } else { $AdlsNonPrdInputCsvPath }

  $baseArgsWithSub = @(
    '-TenantId', $TenantId,
    '-ClientId', $ClientId,
    '-ClientSecret', $ClientSecret,
    '-adh_group', $adh_group,
    '-adh_sub_group', $adh_sub_group,
    '-adh_subscription_type', $env,
    '-OutputDir', $subOut,
    '-BranchName', $BranchName
  )

  $baseArgsNoSub = @(
    '-TenantId', $TenantId,
    '-ClientId', $ClientId,
    '-ClientSecret', $ClientSecret,
    '-adh_group', $adh_group,
    '-adh_subscription_type', $env,
    '-OutputDir', $subOut,
    '-BranchName', $BranchName
  )

  if ($RunRgPermissions) {
    $args = @(
      '-TenantId', $TenantId, '-ClientId', $ClientId, '-ClientSecret', $ClientSecret,
      '-adh_group', $adh_group, '-adh_sub_group', $adh_sub_group, '-adh_subscription_type', $env,
      '-ProdCsvPath', $RgPermsPrdCsvPath,
      '-NonProdCsvPath', $RgPermsNonPrdCsvPath,
      '-OutputDir', $subOut,
      '-BranchName', $BranchName
    )
    $code = Invoke-ChildScript -Title "RG Permissions ($custToken/$env)" -ScriptPath $scanRgPerms -Args $args
    if ($code -ne 0) { $failures.Add("RG Permissions $custToken/$env") | Out-Null }
  }

  if ($RunRgTags) {
    $code = Invoke-ChildScript -Title "RG Tags ($custToken/$env)" -ScriptPath $scanRgTags -Args $baseArgsWithSub
    if ($code -ne 0) { $failures.Add("RG Tags $custToken/$env") | Out-Null }
  }

  if ($RunKvSecrets) {
    $args = $baseArgsWithSub + @('-InputCsvPath', $KvSecretsInputCsvPath)
    $code = Invoke-ChildScript -Title "KV Secrets ($custToken/$env)" -ScriptPath $scanKvSecrets -Args $args
    if ($code -ne 0) { $failures.Add("KV Secrets $custToken/$env") | Out-Null }
  }

  if ($RunKvPermissions) {
    $args = $baseArgsWithSub + @('-KvPermCsvPath', $KvPermInputCsvPath)
    $code = Invoke-ChildScript -Title "KV Permissions ($custToken/$env)" -ScriptPath $scanKvPerms -Args $args
    if ($code -ne 0) { $failures.Add("KV Permissions $custToken/$env") | Out-Null }
  }

  if ($RunKvFirewall) {
    $code = Invoke-ChildScript -Title "KV Networks ($custToken/$env)" -ScriptPath $scanKvFw -Args $baseArgsWithSub
    if ($code -ne 0) { $failures.Add("KV Networks $custToken/$env") | Out-Null }
  }

  if ($RunVnet) {
    $code = Invoke-ChildScript -Title "VNet ($custToken/$env)" -ScriptPath $scanVnet -Args $baseArgsWithSub
    if ($code -ne 0) { $failures.Add("VNet $custToken/$env") | Out-Null }
  }

  if ($RunAdls) {
    $args = $baseArgsWithSub + @('-InputCsvPath', $adlsCsv)
    $code = Invoke-ChildScript -Title "ADLS ACL ($custToken/$env)" -ScriptPath $scanAdls -Args $args
    if ($code -ne 0) { $failures.Add("ADLS ACL $custToken/$env") | Out-Null }
  }

  if ($RunAdf) {
    $code = Invoke-ChildScript -Title "Data Factory ($custToken/$env)" -ScriptPath $scanAdf -Args $baseArgsNoSub
    if ($code -ne 0) { $failures.Add("Data Factory $custToken/$env") | Out-Null }
  }

  if ($RunDatabricks) {
    $code = Invoke-ChildScript -Title "Databricks ($custToken/$env)" -ScriptPath $scanDbx -Args $baseArgsWithSub
    if ($code -ne 0) { $failures.Add("Databricks $custToken/$env") | Out-Null }
  }
}

Write-Host ""
Write-Host "ALL-SUBS run completed. Output: $runDir" -ForegroundColor Green

if ($failures.Count -gt 0) {
  Write-Host ""
  Write-Host "Some checks failed:" -ForegroundColor Yellow
  $failures | Sort-Object | ForEach-Object { Write-Host " - $_" -ForegroundColor Yellow }
  exit 1
}

exit 0
