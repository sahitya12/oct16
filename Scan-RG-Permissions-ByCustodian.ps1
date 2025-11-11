<# ====================================================================
  Scan RG permissions for a given ADH group (custodian).
  INPUTS
    -TenantId              (string, mandatory)
    -ClientId              (string, mandatory)
    -ClientSecret          (string, mandatory)
    -ProdCsvPath           (string, optional)
    -NonProdCsvPath        (string, optional)
    -adh_group             (string, mandatory)  e.g. KTK, MDM, NHH
    -adh_subscription_type (nonprd|prd)         default: nonprd
    -OutputDir             (string, mandatory)
    -BranchName            (string, optional)

  OUTPUTS
    CSV and HTML files in OutputDir (name prefix: rg_permissions_<group>_<env>)
==================================================================== #>

[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$TenantId,
  [Parameter(Mandatory)][string]$ClientId,
  [Parameter(Mandatory)][string]$ClientSecret,

  [string]$ProdCsvPath,
  [string]$NonProdCsvPath,

  [Parameter(Mandatory)][string]$adh_group,

  [ValidateSet('nonprd','prd')]
  [string]$adh_subscription_type = 'nonprd',

  [Parameter(Mandatory)][string]$OutputDir,
  [string]$BranchName = ''
)

Write-Host "=== Scan-RG-Permissions-ByCustodian.ps1 ===" -ForegroundColor Cyan
Write-Host "Script path  : $PSCommandPath"
Write-Host "Bound params : $($PSBoundParameters.GetEnumerator() | Sort-Object Name | ForEach-Object { ""$($_.Name)='$($_.Value)'" } -join '; ' )"

# -------- helper (fallbacks if Common.psm1 is not found) ----------------
function Ensure-Dir {
  param([Parameter(Mandatory)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
}
function New-StampedPath {
  param([Parameter(Mandatory)][string]$BaseDir,[Parameter(Mandatory)][string]$Prefix)
  $ts = Get-Date -Format 'yyyyMMdd_HHmmss'
  Join-Path $BaseDir "$Prefix`_$ts.csv"
}
function Write-CsvSafe {
  param([Parameter(Mandatory)]$Rows,[Parameter(Mandatory)][string]$Path)
  ($Rows | Sort-Object SubscriptionName,ResourceGroup,RoleDefinition,PrincipalName) | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $Path
}
function Convert-CsvToHtml {
  param([Parameter(Mandatory)][string]$CsvPath,[Parameter(Mandatory)][string]$HtmlPath,[Parameter(Mandatory)][string]$Title)
  $data = Import-Csv $CsvPath
  $html = $data | ConvertTo-Html -Title $Title -PreContent "<h2>$Title</h2>" | Out-String
  Set-Content -Path $HtmlPath -Value $html -Encoding UTF8
}

# Try to import your shared module, but the script will still work
$common = Join-Path $PSScriptRoot 'Common.psm1'
if (Test-Path $common) {
  try { Import-Module $common -Force -ErrorAction Stop } catch { Write-Warning "Common.psm1 import failed: $($_.Exception.Message)" }
} else {
  Write-Warning "Common.psm1 not found next to the script; using inline helper functions."
}

# -------------------- connect to Azure --------------------
Write-Host "Connecting to Azure (Service Principal)..." -ForegroundColor Yellow
$secure = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
$cred   = [pscredential]::new($ClientId,$secure)
Connect-AzAccount -ServicePrincipal -Tenant $TenantId -Credential $cred -ErrorAction Stop | Out-Null
Write-Host "Connected to tenant: $TenantId" -ForegroundColor Green

# -------------------- pick input CSV ---------------------
$csvPath = if ($adh_subscription_type -eq 'prd') { $ProdCsvPath } else { $NonProdCsvPath }
if ([string]::IsNullOrWhiteSpace($csvPath)) {
  throw "No CSV path provided for '$adh_subscription_type'. Pass -ProdCsvPath / -NonProdCsvPath."
}
if (-not (Test-Path -LiteralPath $csvPath)) {
  throw "CSV not found: $csvPath"
}
Write-Host "Using permissions CSV: $csvPath"

# -------------------- discover subscriptions --------------
# Rules: for KTK → ADHPlatform; else dev_azure_*_ADH<GROUP> or ADH<First><GROUP>
$envPrefix = if ($adh_subscription_type -eq 'prd') { 'prd_azure_' } else { 'dev_azure_' }
$g = $adh_group.Trim().ToUpperInvariant()

$variants = [System.Collections.Generic.List[string]]::new()
if ($g -eq 'KTK') { $variants.Add('ADHPlatform') }
$first = $g.Substring(0,1)
$variants.Add("ADH$g")
$variants.Add("ADH$first$g")

$allSubs  = Get-AzSubscription
$subs = @()
foreach ($v in $variants) {
  $pattern = "$envPrefix*_*$v"
  $subs += $allSubs | Where-Object { $_.Name -like $pattern }
}
$subs = $subs | Sort-Object Name -Unique
if (-not $subs) { throw "No matching subscriptions for $adh_group ($adh_subscription_type). Tried: $($variants -join ', ')" }
Write-Host "Found $($subs.Count) subscription(s): $($subs.Name -join ', ')"

# -------------------- scan permissions --------------------
Ensure-Dir -Path $OutputDir
$csvOut  = New-StampedPath -BaseDir $OutputDir -Prefix "rg_permissions_${g}_$adh_subscription_type"
$htmlOut = $csvOut -replace '\.csv$','.html'

$rows = @()
$csv = Import-Csv -Path $csvPath
# normalise headers
$map = @{}
$firstRow = $csv[0]
$firstRow.PSObject.Properties.Name | ForEach-Object {
  $map[($_ -replace '\s|_','').ToLowerInvariant()] = $_
}
foreach ($s in $subs) {
  Write-Host ">> Subscription: $($s.Name)" -ForegroundColor Cyan
  Set-AzContext -SubscriptionId $s.Id | Out-Null

  foreach ($r in $csv) {
    $rgNameRaw = $r.$($map['resourcegroupname'])
    $role      = $r.$($map['roledefinitionname'])
    $aadRaw    = $r.$($map['adgroupname'])

    $rgName = $rgNameRaw -replace '<Custodian>',$g
    $aad    = $aadRaw    -replace '<Custodian>',$g

    $rg     = Get-AzResourceGroup -Name $rgName -ErrorAction SilentlyContinue
    $rgStat = if ($rg) { 'EXISTS' } else { 'NOT_FOUND' }
    $perm   = 'N/A'; $details = ''

    if ($rg) {
      $scope  = "/subscriptions/{0}/resourceGroups/{1}" -f $s.Id,$rgName
      $assign = Get-AzRoleAssignment -Scope $scope -ErrorAction SilentlyContinue |
                Where-Object { $_.RoleDefinitionName -eq $role -and $_.DisplayName -eq $aad }
      $perm   = if ($assign) { 'EXISTS' } else { 'MISSING' }
      if (-not $assign) { $details = 'Expected assignment not found at RG scope' }
    } else {
      $details = 'Resource group not found'
    }

    $rows += [pscustomobject]@{
      SubscriptionName     = $s.Name
      SubscriptionId       = $s.Id
      Environment          = $adh_subscription_type
      Custodian            = $g
      InputResourceGroup   = $rgNameRaw
      ScannedResourceGroup = $rgName
      RoleDefinition       = $role
      InputAdGroup         = $aadRaw
      ResolvedAdGroup      = $aad
      RGStatus             = $rgStat
      PermissionStatus     = $perm
      Details              = $details
    }
  }
}

Write-CsvSafe     -Rows $rows -Path $csvOut
Convert-CsvToHtml -CsvPath $csvOut -HtmlPath $htmlOut -Title "RG Permissions – $g ($adh_subscription_type) $BranchName"

Write-Host "CSV : $csvOut"
Write-Host "HTML: $htmlOut"
Write-Host "=== Completed ===" -ForegroundColor Green
