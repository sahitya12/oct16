[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$TenantId,
  [Parameter(Mandatory)][string]$ClientId,
  [Parameter(Mandatory)][string]$ClientSecret,

  [Parameter(Mandatory)][string]$SubscriptionsCsvPath,

  # RG permissions inputs
  [Parameter(Mandatory)][string]$RgPermsNonPrdCsvPath,
  [Parameter(Mandatory)][string]$RgPermsPrdCsvPath,

  # ADLS inputs
  [Parameter(Mandatory)][string]$AdlsNonPrdInputCsvPath,
  [Parameter(Mandatory)][string]$AdlsPrdInputCsvPath,

  # KV inputs
  [Parameter(Mandatory)][string]$KvSecretsInputCsvPath,
  [Parameter(Mandatory)][string]$KvPermInputCsvPath,

  [Parameter(Mandatory)][string]$OutputRootDir,

  # -----------------------------
  # TOGGLES (MUST NOT BE [bool])
  # -----------------------------
  [object]$RunRgPermissions = $true,
  [object]$RunRgTags        = $true,
  [object]$RunKvSecrets     = $true,
  [object]$RunKvPermissions = $true,
  [object]$RunKvFirewall    = $true,
  [object]$RunVnet          = $true,
  [object]$RunAdls          = $true,
  [object]$RunAdf           = $true,
  [object]$RunDatabricks    = $true,

  [string]$BranchName = ''
)

$ErrorActionPreference = 'Stop'

# ------------------- Helpers -------------------
function Ensure-Dir([string]$p) {
  if (-not (Test-Path -LiteralPath $p)) {
    New-Item -ItemType Directory -Path $p -Force | Out-Null
  }
  (Get-Item -LiteralPath $p).FullName
}

function Convert-ToBool([object]$v, [bool]$default = $false) {
  if ($null -eq $v) { return $default }
  if ($v -is [bool]) { return $v }

  $s = "$v".Trim()

  if ($s -match '^(?i:true|1|yes|y|on)$')  { return $true }
  if ($s -match '^(?i:false|0|no|n|off)$') { return $false }

  # Azure DevOps sometimes passes "System.String"
  if ($s -eq 'System.String') { return $default }

  return $default
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

# ------------------- Normalize toggles -------------------
$RunRgPermissions = Convert-ToBool $RunRgPermissions $true
$RunRgTags        = Convert-ToBool $RunRgTags $true
$RunKvSecrets     = Convert-ToBool $RunKvSecrets $true
$RunKvPermissions = Convert-ToBool $RunKvPermissions $true
$RunKvFirewall    = Convert-ToBool $RunKvFirewall $true
$RunVnet          = Convert-ToBool $RunVnet $true
$RunAdls          = Convert-ToBool $RunAdls $true
$RunAdf           = Convert-ToBool $RunAdf $true
$RunDatabricks    = Convert-ToBool $RunDatabricks $true

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

# ------------------- Paths -------------------
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
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

# ------------------- Output root -------------------
$outRoot = Ensure-Dir $OutputRootDir
$runStamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$runDir = Ensure-Dir (Join-Path $outRoot "allsubs_$runStamp")

Write-Host "ALL-SUBSCRIPTIONS SANITY CHECK STARTED"
Write-Host "Output directory: $runDir"
Write-Host "Branch: $BranchName"

# ------------------- Read subscriptions -------------------
$rows = Import-Csv -LiteralPath $SubscriptionsCsvPath
if (-not $rows -or $rows.Count -eq 0) {
  throw "No rows found in $SubscriptionsCsvPath"
}

$failures = @()

foreach ($r in $rows) {

  $adh_group     = "$($r.adh_group)".Trim()
  $adh_sub_group = "$($r.adh_sub_group)".Trim()
  $env           = "$($r.adh_subscription_type)".Trim().ToLower()

  if (-not $adh_group -or $env -notin @('nonprd','prd')) {
    Write-Host "Skipping invalid row: $($r | ConvertTo-Json -Compress)" -ForegroundColor Yellow
    continue
  }

  $custToken = if ($adh_sub_group) { "${adh_group}_${adh_sub_group}" } else { $adh_group }
  $subOut = Ensure-Dir (Join-Path $runDir "${custToken}_$env")

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
    Invoke-ChildScript "RG Permissions ($custToken/$env)" $scanRgPerms @(
      '-TenantId', $TenantId,
      '-ClientId', $ClientId,
      '-ClientSecret', $ClientSecret,
      '-adh_group', $adh_group,
      '-adh_sub_group', $adh_sub_group,
      '-adh_subscription_type', $env,
      '-ProdCsvPath', $RgPermsPrdCsvPath,
      '-NonProdCsvPath', $RgPermsNonPrdCsvPath,
      '-OutputDir', $subOut,
      '-BranchName', $BranchName
    ) | ForEach-Object { if ($_ -ne 0) { $failures += "RG Permissions $custToken/$env" } }
  }

  if ($RunRgTags) {
    Invoke-ChildScript "RG Tags ($custToken/$env)" $scanRgTags $baseArgsWithSub
  }

  if ($RunKvSecrets) {
    Invoke-ChildScript "KV Secrets ($custToken/$env)" $scanKvSecrets ($baseArgsWithSub + @('-InputCsvPath', $KvSecretsInputCsvPath))
  }

  if ($RunKvPermissions) {
    Invoke-ChildScript "KV Permissions ($custToken/$env)" $scanKvPerms ($baseArgsWithSub + @('-KvPermCsvPath', $KvPermInputCsvPath))
  }

  if ($RunKvFirewall) {
    Invoke-ChildScript "KV Networks ($custToken/$env)" $scanKvFw $baseArgsWithSub
  }

  if ($RunVnet -and (Test-Path $scanVnet)) {
    Invoke-ChildScript "VNet ($custToken/$env)" $scanVnet $baseArgsWithSub
  }

  if ($RunAdls) {
    Invoke-ChildScript "ADLS ACL ($custToken/$env)" $scanAdls ($baseArgsWithSub + @('-InputCsvPath', $adlsCsv))
  }

  if ($RunAdf) {
    Invoke-ChildScript "Data Factory ($custToken/$env)" $scanAdf $baseArgsNoSub
  }

  if ($RunDatabricks) {
    Invoke-ChildScript "Databricks ($custToken/$env)" $scanDbx $baseArgsWithSub
  }
}

Write-Host ""
Write-Host "ALL-SUBSCRIPTIONS SANITY CHECK COMPLETED" -ForegroundColor Green
Write-Host "Output: $runDir"

if ($failures.Count -gt 0) {
  Write-Host "Failures detected:" -ForegroundColor Yellow
  $failures | Sort-Object | ForEach-Object { Write-Host " - $_" -ForegroundColor Yellow }
  exit 1
}

exit 0
