[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$TenantId,
  [Parameter(Mandatory)][string]$ClientId,
  [Parameter(Mandatory)][string]$ClientSecret,

  [Parameter(Mandatory)][string]$SubscriptionsCsvPath,

  [Parameter(Mandatory)][string]$RgPermsNonPrdCsvPath,
  [Parameter(Mandatory)][string]$RgPermsPrdCsvPath,

  [Parameter(Mandatory)][string]$AdlsNonPrdInputCsvPath,
  [Parameter(Mandatory)][string]$AdlsPrdInputCsvPath,

  [Parameter(Mandatory)][string]$KvSecretsInputCsvPath,
  [Parameter(Mandatory)][string]$KvPermInputCsvPath,

  [Parameter(Mandatory)][string]$OutputRootDir,

  # toggles (PASS FROM PIPELINE AS -RunX:$true / $false)
  [bool]$RunRgPermissions = $true,
  [bool]$RunRgTags        = $true,
  [bool]$RunKvSecrets     = $true,
  [bool]$RunKvPermissions = $true,
  [bool]$RunKvFirewall    = $true,
  [bool]$RunVnet          = $true,
  [bool]$RunAdls          = $true,
  [bool]$RunAdf           = $true,
  [bool]$RunDatabricks    = $true,

  # ✅ if false -> pipeline keeps running even if some custodians fail
  [bool]$FailOnErrors = $false,

  [string]$BranchName = ''
)

$ErrorActionPreference = 'Stop'

function Ensure-Dir([string]$p) {
  if (-not (Test-Path -LiteralPath $p)) {
    New-Item -ItemType Directory -Path $p -Force | Out-Null
  }
  (Get-Item -LiteralPath $p).FullName
}

function Resolve-ExistingPath {
  param(
    [Parameter(Mandatory)][string[]]$Candidates,
    [Parameter(Mandatory)][string]$Label
  )
  foreach ($c in $Candidates) {
    if ([string]::IsNullOrWhiteSpace($c)) { continue }
    if (Test-Path -LiteralPath $c) { return (Resolve-Path -LiteralPath $c).Path }
  }
  throw "Required $Label not found. Tried: $($Candidates -join ', ')"
}

function Invoke-ChildScript {
  param(
    [Parameter(Mandatory)][string]$Title,
    [Parameter(Mandatory)][string]$ScriptPath,
    [string[]]$Args = @()
  )

  Write-Host ""
  Write-Host ("=" * 60) -ForegroundColor DarkCyan
  Write-Host $Title -ForegroundColor Cyan
  Write-Host "Script: $ScriptPath"

  if (-not (Test-Path -LiteralPath $ScriptPath)) {
    Write-Host "❌ Script not found: $ScriptPath" -ForegroundColor Red
    return 1
  }

  if ($null -eq $Args) { $Args = @() }
  $Args = @($Args | Where-Object { $_ -ne $null }) # remove nulls

  try {
    if ($Args.Count -eq 0) {
      & pwsh -NoProfile -File $ScriptPath
    } else {
      & pwsh -NoProfile -File $ScriptPath @Args
    }

    $code = $LASTEXITCODE
    if ($code -ne 0) {
      Write-Host "❌ FAILED (exit code $code): $Title" -ForegroundColor Red
      return $code
    }

    Write-Host "✅ OK: $Title" -ForegroundColor Green
    return 0
  }
  catch {
    Write-Host "❌ FAILED (exception): $Title" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    return 1
  }
}

# -------------------- Print summary --------------------
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
Write-Host "  FailOnErrors     = $FailOnErrors"
Write-Host ""

# ---------------- Repo-relative paths ----------------
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path  # sanitychecks/
$scanRoot = Join-Path $repoRoot 'scripts'

# Your repo currently has these names (based on your screenshot)
$scanRgPerms   = Resolve-ExistingPath -Label "RG permissions scan script" -Candidates @((Join-Path $scanRoot 'Scan-RG-Permissions-ByCustodian.ps1'))
$scanRgTags    = Resolve-ExistingPath -Label "RG tags scan script"        -Candidates @((Join-Path $scanRoot 'Scan-RG-Tags.ps1'))
$scanKvSecrets = Resolve-ExistingPath -Label "KV secrets scan script"     -Candidates @((Join-Path $scanRoot 'Scan-KV-Secrets.ps1'))
$scanKvPerms   = Resolve-ExistingPath -Label "KV permissions scan script" -Candidates @(
  (Join-Path $scanRoot 'Scan-KV-Permissions.ps1'),
  (Join-Path $scanRoot 'Scan-KV-Permissions-1.ps1')
)
$scanKvFw      = Resolve-ExistingPath -Label "KV networks scan script"    -Candidates @(
  (Join-Path $scanRoot 'Scan-KV-Networks.ps1'),
  (Join-Path $scanRoot 'Scan-KV-Networks-1.ps1')
)
$scanAdls      = Resolve-ExistingPath -Label "ADLS ACL scan script"       -Candidates @((Join-Path $scanRoot 'Scan-ADLS-Acls.ps1'))
$scanAdf       = Resolve-ExistingPath -Label "ADF scan script"            -Candidates @((Join-Path $scanRoot 'Scan-DataFactory.ps1'))
$scanDbx       = Resolve-ExistingPath -Label "Databricks scan script"     -Candidates @((Join-Path $scanRoot 'Scan-Databricks.ps1'))
$scanVnet      = Resolve-ExistingPath -Label "VNet scan script"           -Candidates @((Join-Path $scanRoot 'Scan-VNet-Monthly.ps1'))

# ---------------- Validate input files ----------------
foreach ($p in @(
  $SubscriptionsCsvPath,
  $RgPermsNonPrdCsvPath, $RgPermsPrdCsvPath,
  $AdlsNonPrdInputCsvPath, $AdlsPrdInputCsvPath,
  $KvSecretsInputCsvPath, $KvPermInputCsvPath
)) {
  if (-not (Test-Path -LiteralPath $p)) { throw "Required file not found: $p" }
}

# ---------------- Output root per run ----------------
$outRoot = Ensure-Dir $OutputRootDir
$runStamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$runDir = Ensure-Dir (Join-Path $outRoot ("allsubs_{0}" -f $runStamp))

Write-Host "ALL-SUBSCRIPTIONS SANITY CHECK STARTED"
Write-Host "Output directory: $runDir"
Write-Host "Branch: $BranchName"
Write-Host ""

# ---------------- Read subscriptions master ----------------
$rows = Import-Csv -LiteralPath $SubscriptionsCsvPath
if (-not $rows -or $rows.Count -eq 0) { throw "No rows found in: $SubscriptionsCsvPath" }

$failures = New-Object System.Collections.Generic.List[string]

foreach ($r in $rows) {

  $adh_group     = ("$($r.adh_group)").Trim()
  $adh_sub_group = ("$($r.adh_sub_group)").Trim()
  $env           = ("$($r.adh_subscription_type)").Trim().ToLower()

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

  Write-Host "############################################################" -ForegroundColor Magenta
  Write-Host "# Custodian: $custToken | Env: $env" -ForegroundColor Magenta
  Write-Host "############################################################" -ForegroundColor Magenta

  $adlsCsv = if ($env -eq 'prd') { $AdlsPrdInputCsvPath } else { $AdlsNonPrdInputCsvPath }

  # Base args (common)
  $baseArgs = @(
    '-TenantId', $TenantId,
    '-ClientId', $ClientId,
    '-ClientSecret', $ClientSecret,
    '-adh_group', $adh_group,
    '-adh_subscription_type', $env,
    '-OutputDir', $subOut,
    '-BranchName', $BranchName
  )

  # Add adh_sub_group ONLY if present (prevents errors)
  $baseArgsWithSub = @($baseArgs)
  if (-not [string]::IsNullOrWhiteSpace($adh_sub_group)) {
    $baseArgsWithSub += @('-adh_sub_group', $adh_sub_group)
  }

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
    if ($code -ne 0) { $failures.Add("RG Permissions $custToken/$env") }
  }

  if ($RunRgTags) {
    $code = Invoke-ChildScript -Title "RG Tags ($custToken/$env)" -ScriptPath $scanRgTags -Args $baseArgsWithSub
    if ($code -ne 0) { $failures.Add("RG Tags $custToken/$env") }
  }

  if ($RunKvSecrets) {
    $args = @($baseArgsWithSub + @('-InputCsvPath', $KvSecretsInputCsvPath))
    $code = Invoke-ChildScript -Title "KV Secrets ($custToken/$env)" -ScriptPath $scanKvSecrets -Args $args
    if ($code -ne 0) { $failures.Add("KV Secrets $custToken/$env") }
  }

  if ($RunKvPermissions) {
    $args = @($baseArgsWithSub + @('-KvPermCsvPath', $KvPermInputCsvPath))
    $code = Invoke-ChildScript -Title "KV Permissions ($custToken/$env)" -ScriptPath $scanKvPerms -Args $args
    if ($code -ne 0) { $failures.Add("KV Permissions $custToken/$env") }
  }

  if ($RunKvFirewall) {
    $code = Invoke-ChildScript -Title "KV Networks ($custToken/$env)" -ScriptPath $scanKvFw -Args $baseArgsWithSub
    if ($code -ne 0) { $failures.Add("KV Networks $custToken/$env") }
  }

  if ($RunVnet) {
    $code = Invoke-ChildScript -Title "VNet ($custToken/$env)" -ScriptPath $scanVnet -Args $baseArgsWithSub
    if ($code -ne 0) { $failures.Add("VNet $custToken/$env") }
  }

  if ($RunAdls) {
    $args = @($baseArgsWithSub + @('-InputCsvPath', $adlsCsv))
    $code = Invoke-ChildScript -Title "ADLS ACL ($custToken/$env)" -ScriptPath $scanAdls -Args $args
    if ($code -ne 0) { $failures.Add("ADLS ACL $custToken/$env") }
  }

  if ($RunAdf) {
    # ADF script in your repo does not take adh_sub_group reliably => use baseArgs
    $code = Invoke-ChildScript -Title "Data Factory ($custToken/$env)" -ScriptPath $scanAdf -Args $baseArgs
    if ($code -ne 0) { $failures.Add("Data Factory $custToken/$env") }
  }

  if ($RunDatabricks) {
    $code = Invoke-ChildScript -Title "Databricks ($custToken/$env)" -ScriptPath $scanDbx -Args $baseArgsWithSub
    if ($code -ne 0) { $failures.Add("Databricks $custToken/$env") }
  }

  Write-Host ""
}

Write-Host "ALL-SUBSCRIPTIONS SANITY CHECK COMPLETED"
Write-Host "Output: $runDir" -ForegroundColor Green

if ($failures.Count -gt 0) {
  Write-Host ""
  Write-Host "Some checks failed (but pipeline can continue if FailOnErrors = false):" -ForegroundColor Yellow
  $failures | Sort-Object | ForEach-Object { Write-Host " - $_" -ForegroundColor Yellow }

  if ($FailOnErrors) { exit 1 } else { exit 0 }
}

exit 0
