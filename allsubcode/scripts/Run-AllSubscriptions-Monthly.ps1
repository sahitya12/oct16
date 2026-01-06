[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$TenantId,
  [Parameter(Mandatory)][string]$ClientId,
  [Parameter(Mandatory)][string]$ClientSecret,

  [Parameter(Mandatory)][string]$SubscriptionsCsvPath,

  # RG permissions
  [Parameter(Mandatory)][string]$RgPermsNonPrdCsvPath,
  [Parameter(Mandatory)][string]$RgPermsPrdCsvPath,

  # ADLS inputs
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

# ---------------- helpers ----------------
function Ensure-Dir($p) {
  if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
  (Resolve-Path $p).Path
}

function Invoke-Child {
  param($Title, $Script, $Args)
  Write-Host "`n===== $Title =====" -ForegroundColor Cyan
  & pwsh -NoProfile -File $Script @Args
  if ($LASTEXITCODE -ne 0) {
    throw "$Title failed"
  }
}

# ---------------- paths ----------------
$repoRoot  = Resolve-Path (Join-Path $PSScriptRoot '..')
$scripts   = Join-Path $repoRoot 'scripts'

$scanRgPerms   = Join-Path $scripts 'Scan-RG-Permissions-ByCustodian.ps1'
$scanRgTags    = Join-Path $scripts 'Scan-RG-Tags.ps1'
$scanKvSecrets = Join-Path $scripts 'Scan-KV-Secrets.ps1'
$scanKvPerms   = Join-Path $scripts 'Scan-KV-Permissions.ps1'
$scanKvFw      = Join-Path $scripts 'Scan-KV-Networks.ps1'
$scanAdls      = Join-Path $scripts 'Scan-ADLS-Acls.ps1'
$scanAdf       = Join-Path $scripts 'Scan-DataFactory.ps1'
$scanDbx       = Join-Path $scripts 'Scan-Databricks.ps1'
$scanVnet      = Join-Path $scripts 'Scan-VNet-Monthly.ps1'

# ---------------- validate ----------------
$required = @(
  $SubscriptionsCsvPath,
  $RgPermsNonPrdCsvPath, $RgPermsPrdCsvPath,
  $AdlsNonPrdInputCsvPath, $AdlsPrdInputCsvPath,
  $KvSecretsInputCsvPath, $KvPermInputCsvPath,
  $scanRgPerms, $scanRgTags, $scanKvSecrets, $scanKvPerms,
  $scanKvFw, $scanAdls, $scanAdf, $scanDbx, $scanVnet
)

foreach ($p in $required) {
  if (-not (Test-Path $p)) {
    throw "Required file not found: $p"
  }
}

# ---------------- output ----------------
$outRoot = Ensure-Dir $OutputRootDir
$runDir  = Ensure-Dir (Join-Path $outRoot "allsubs_$(Get-Date -Format yyyyMMdd_HHmmss)")

Write-Host "ALL-SUBSCRIPTIONS SANITY CHECK STARTED"
Write-Host "Output: $runDir"
Write-Host "Branch: $BranchName"

# ---------------- loop subscriptions ----------------
$subs = Import-Csv $SubscriptionsCsvPath

foreach ($s in $subs) {

  $adh_group = $s.adh_group.Trim()
  $adh_sub   = $s.adh_sub_group.Trim()
  $env       = $s.adh_subscription_type.Trim().ToLower()

  if ($env -notin @('nonprd','prd')) { continue }

  $token = if ($adh_sub) { "$adh_group`_$adh_sub" } else { $adh_group }
  $out   = Ensure-Dir (Join-Path $runDir "$token`_$env")

  $adlsCsv = if ($env -eq 'prd') { $AdlsPrdInputCsvPath } else { $AdlsNonPrdInputCsvPath }

  $base = @(
    '-TenantId', $TenantId,
    '-ClientId', $ClientId,
    '-ClientSecret', $ClientSecret,
    '-adh_group', $adh_group,
    '-adh_sub_group', $adh_sub,
    '-adh_subscription_type', $env,
    '-OutputDir', $out,
    '-BranchName', $BranchName
  )

  if ($RunRgPermissions) {
    Invoke-Child "RG Permissions" $scanRgPerms @(
      '-TenantId', $TenantId,
      '-ClientId', $ClientId,
      '-ClientSecret', $ClientSecret,
      '-adh_group', $adh_group,
      '-adh_sub_group', $adh_sub,
      '-adh_subscription_type', $env,
      '-ProdCsvPath', $RgPermsPrdCsvPath,
      '-NonProdCsvPath', $RgPermsNonPrdCsvPath,
      '-OutputDir', $out,
      '-BranchName', $BranchName
    )
  }

  if ($RunRgTags)        { Invoke-Child "RG Tags"        $scanRgTags    $base }
  if ($RunKvSecrets)    { Invoke-Child "KV Secrets"     $scanKvSecrets ($base + '-InputCsvPath' + $KvSecretsInputCsvPath) }
  if ($RunKvPermissions){ Invoke-Child "KV Permissions" $scanKvPerms   ($base + '-KvPermCsvPath' + $KvPermInputCsvPath) }
  if ($RunKvFirewall)   { Invoke-Child "KV Firewall"    $scanKvFw      $base }
  if ($RunVnet)         { Invoke-Child "VNET"           $scanVnet      $base }
  if ($RunAdls)         { Invoke-Child "ADLS ACLs"      $scanAdls      ($base + '-InputCsvPath' + $adlsCsv) }
  if ($RunAdf)          { Invoke-Child "ADF"            $scanAdf @(
                            '-TenantId', $TenantId,
                            '-ClientId', $ClientId,
                            '-ClientSecret', $ClientSecret,
                            '-adh_group', $adh_group,
                            '-adh_subscription_type', $env,
                            '-OutputDir', $out,
                            '-BranchName', $BranchName
                          )
                        }
  if ($RunDatabricks)   { Invoke-Child "Databricks"     $scanDbx $base }
}

Write-Host "`nALL CHECKS COMPLETED SUCCESSFULLY" -ForegroundColor Green
exit 0
