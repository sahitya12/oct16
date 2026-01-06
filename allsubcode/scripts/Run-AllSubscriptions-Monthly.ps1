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

  # toggles (MUST NOT be [bool] because ADO may pass strings)
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

function Ensure-Dir([string]$p) {
  if (-not (Test-Path -LiteralPath $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
  (Get-Item -LiteralPath $p).FullName
}

function Convert-ToBool([object]$v, [bool]$default = $false) {
  if ($null -eq $v) { return $default }
  if ($v -is [bool]) { return $v }

  $s = "$v".Trim()

  if ($s -match '^(?i:true|1|yes|y|on)$')  { return $true }
  if ($s -match '^(?i:false|0|no|n|off)$') { return $false }

  # if ADO passes weird token
  if ($s -eq 'System.String') { return $default }

  return $default
}

function Normalize-ArgsToArray([object]$ArgsObj) {
  # Convert: $null -> @()
  # Convert: ""   -> @()
  # Convert: single string -> @("x")
  # Convert: array -> array (unchanged)
  if ($null -eq $ArgsObj) { return @() }

  if ($ArgsObj -is [string] -and [string]::IsNullOrWhiteSpace($ArgsObj)) {
    return @()
  }

  if ($ArgsObj -is [System.Array]) {
    # If an array contains empty-string items, keep them ONLY if they are part of a named param value.
    # We will avoid creating those empties when building args (below).
    return @($ArgsObj)
  }

  return @($ArgsObj)
}

function Invoke-ChildScript {
  param(
    [Parameter(Mandatory)][string]$Title,
    [Parameter(Mandatory)][string]$ScriptPath,
    [Parameter()][object]$Args
  )

  $argList = Normalize-ArgsToArray $Args

  Write-Host ""
  Write-Host "==================== $Title ====================" -ForegroundColor Cyan
  Write-Host "Script: $ScriptPath"

  try {
    & pwsh -NoProfile -File $ScriptPath @argList
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

# ---- Normalize toggles to real bools ----
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

Write-Host "ALL-SUBSCRIPTIONS SANITY CHECK STARTED"
Write-Host "Output directory: $runDir"
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

  # -------- Build args WITHOUT passing empty adh_sub_group --------
  $baseArgsWithSub = @(
    '-TenantId', $TenantId,
    '-ClientId', $ClientId,
    '-ClientSecret', $ClientSecret,
    '-adh_group', $adh_group
  )
  if (-not [string]::IsNullOrWhiteSpace($adh_sub_group)) {
    $baseArgsWithSub += @('-adh_sub_group', $adh_sub_group)
  }
  $baseArgsWithSub += @(
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
      '-adh_group', $adh_group
    )
    if (-not [string]::IsNullOrWhiteSpace($adh_sub_group)) {
      $args += @('-adh_sub_group', $adh_sub_group)
    }
    $args += @(
      '-adh_subscription_type', $env,
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
Write-Host "ALL-SUBSCRIPTIONS SANITY CHECK COMPLETED. Output: $runDir" -ForegroundColor Green

if ($failures.Count -gt 0) {
  Write-Host ""
  Write-Host "Some checks failed:" -ForegroundColor Yellow
  $failures | Sort-Object | ForEach-Object { Write-Host " - $_" -ForegroundColor Yellow }
  exit 1
}

exit 0
