[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$TenantId,
  [Parameter(Mandatory)][string]$ClientId,
  [Parameter(Mandatory)][string]$ClientSecret,

  [Parameter(Mandatory)][string]$SubscriptionsCsvPath,

  # RG permissions inputs (same for all)
  [Parameter(Mandatory)][string]$RgPermsNonPrdCsvPath,
  [Parameter(Mandatory)][string]$RgPermsPrdCsvPath,

  # ADLS inputs (env-specific)
  [Parameter(Mandatory)][string]$AdlsNonPrdInputCsvPath,
  [Parameter(Mandatory)][string]$AdlsPrdInputCsvPath,

  # KV inputs
  [Parameter(Mandatory)][string]$KvSecretsInputCsvPath,
  [Parameter(Mandatory)][string]$KvPermInputCsvPath,

  [Parameter(Mandatory)][string]$OutputRootDir,

  # toggles
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
  if (-not (Test-Path -LiteralPath $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
  (Get-Item -LiteralPath $p).FullName
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
  try {
    & pwsh -NoProfile -File $ScriptPath @Args
    $code = $LASTEXITCODE
    if ($code -ne 0) {
      Write-Host "❌ $Title FAILED (exit code $code)" -ForegroundColor Red
    } else {
      Write-Host "✅ $Title OK" -ForegroundColor Green
    }
    return $code
  } catch {
    Write-Host "❌ $Title FAILED (exception)" -ForegroundColor Red
    Write-Host $_.Exception.Message
    return 1
  }
}

# ------------------- Repo-relative paths -------------------
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path  # sanitychecks/
$scanRoot = Join-Path $repoRoot 'scripts'

$scanRgPerms   = Join-Path $scanRoot 'Scan-RG-Permissions-ByCustodian.ps1'
$scanRgTags    = Join-Path $scanRoot 'Scan-RG-Tags.ps1'
$scanKvSecrets = Join-Path $scanRoot 'Scan-KV-Secrets.ps1'
$scanKvPerms   = Join-Path $scanRoot 'Scan-KV-Permissions-1.ps1'
$scanKvFw      = Join-Path $scanRoot 'Scan-KV-Networks-1.ps1'
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

Write-Host "ALL-SUBS run starting..."
Write-Host "RunDir: $runDir"
Write-Host "Branch: $BranchName"

# ------------------- Read subscriptions master -------------------
$rows = Import-Csv -LiteralPath $SubscriptionsCsvPath
if (-not $rows -or $rows.Count -eq 0) { throw "No rows found in: $SubscriptionsCsvPath" }

$failures = @()

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

  # ADLS input selection based on env
  $adlsCsv = if ($env -eq 'prd') { $AdlsPrdInputCsvPath } else { $AdlsNonPrdInputCsvPath }

  # Common args for scripts that accept adh_sub_group
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

  # Some scripts do not accept adh_sub_group (ADF)
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
    if ($code -ne 0) { $failures += "RG Permissions $custToken/$env" }
  }

  if ($RunRgTags) {
    $code = Invoke-ChildScript -Title "RG Tags ($custToken/$env)" -ScriptPath $scanRgTags -Args $baseArgsWithSub
    if ($code -ne 0) { $failures += "RG Tags $custToken/$env" }
  }

  if ($RunKvSecrets) {
    $args = $baseArgsWithSub + @('-InputCsvPath', $KvSecretsInputCsvPath)
    $code = Invoke-ChildScript -Title "KV Secrets ($custToken/$env)" -ScriptPath $scanKvSecrets -Args $args
    if ($code -ne 0) { $failures += "KV Secrets $custToken/$env" }
  }

  if ($RunKvPermissions) {
    $args = $baseArgsWithSub + @('-KvPermCsvPath', $KvPermInputCsvPath)
    $code = Invoke-ChildScript -Title "KV Permissions ($custToken/$env)" -ScriptPath $scanKvPerms -Args $args
    if ($code -ne 0) { $failures += "KV Permissions $custToken/$env" }
  }

  if ($RunKvFirewall) {
    $code = Invoke-ChildScript -Title "KV Networks ($custToken/$env)" -ScriptPath $scanKvFw -Args $baseArgsWithSub
    if ($code -ne 0) { $failures += "KV Networks $custToken/$env" }
  }

  if ($RunVnet) {
    $code = Invoke-ChildScript -Title "VNet ($custToken/$env)" -ScriptPath $scanVnet -Args $baseArgsWithSub
    if ($code -ne 0) { $failures += "VNet $custToken/$env" }
  }

  if ($RunAdls) {
    $args = $baseArgsWithSub + @('-InputCsvPath', $adlsCsv)
    $code = Invoke-ChildScript -Title "ADLS ACL ($custToken/$env)" -ScriptPath $scanAdls -Args $args
    if ($code -ne 0) { $failures += "ADLS ACL $custToken/$env" }
  }

  if ($RunAdf) {
    $code = Invoke-ChildScript -Title "Data Factory ($custToken/$env)" -ScriptPath $scanAdf -Args $baseArgsNoSub
    if ($code -ne 0) { $failures += "Data Factory $custToken/$env" }
  }

  if ($RunDatabricks) {
    $code = Invoke-ChildScript -Title "Databricks ($custToken/$env)" -ScriptPath $scanDbx -Args $baseArgsWithSub
    if ($code -ne 0) { $failures += "Databricks $custToken/$env" }
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
