<#  Scan RG permissions for a given ADH group & environment (nonprd|prd)
    Outputs: timestamped CSV + HTML under OutputDir
#>

param(
  [Parameter(Mandatory)][string]$TenantId,
  [Parameter(Mandatory)][string]$ClientId,
  [Parameter(Mandatory)][string]$ClientSecret,

  [Parameter(Mandatory)][string]$adh_group,
  [ValidateSet('nonprd','prd')][string]$adh_subscription_type = 'nonprd',

  [Parameter(Mandatory)][string]$OutputDir,
  [string]$BranchName = ''
)

# ------------------------- helpers (embedded) -------------------------
function Ensure-Dir {
  param([Parameter(Mandatory)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    [System.IO.Directory]::CreateDirectory($Path) | Out-Null
  }
}

function New-StampedPath {
  param(
    [Parameter(Mandatory)][string]$BaseDir,
    [Parameter(Mandatory)][string]$Prefix,
    [string]$Ext = 'csv'
  )
  $stamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
  return (Join-Path $BaseDir "$Prefix`_$stamp.$Ext")
}

function Write-CsvSafe {
  param(
    [Parameter(Mandatory)][object[]]$Rows,
    [Parameter(Mandatory)][string]$Path
  )
  if (-not $Rows -or $Rows.Count -eq 0) {
    # always write a header (empty table)
    @([pscustomobject]@{Info='No rows'}) | Export-Csv -LiteralPath $Path -NoTypeInformation -Force
  } else {
    $Rows | Export-Csv -LiteralPath $Path -NoTypeInformation -Force
  }
}

function Convert-CsvToHtml {
  param(
    [Parameter(Mandatory)][string]$CsvPath,
    [Parameter(Mandatory)][string]$HtmlPath,
    [string]$Title = 'Report'
  )
  $data = Import-Csv -LiteralPath $CsvPath
  $html = $data | ConvertTo-Html -Title $Title -PreContent "<h2>$Title</h2>"
  $html | Set-Content -LiteralPath $HtmlPath -Encoding UTF8
}

function Resolve-AdhSubscriptions {
  <#
    Returns the matching subscription(s) for an ADH group.
    nonprd → dev_azure_*_ADH<suffix>
    prd    → prd_azure_*_ADH<suffix>
    Suffixes tried in order:
      - ADH<GROUP>       (ADHMDM, ADHJS, ...)
      - ADH<FIRST><GROUP> (ADHMMDM, ADHNNHH)
    Special map: KTK → ADHPlatform (single Platform subscription)
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z]{2,}$')][string]$AdhGroup,
    [ValidateSet('nonprd','prd')][string]$Environment = 'nonprd',
    [switch]$All
  )

  $g = $AdhGroup.Trim().ToUpperInvariant()
  $envPrefix = if ($Environment -eq 'prd') { 'prd_azure_' } else { 'dev_azure_' }
  $special = @{ 'KTK' = 'ADHPlatform' }

  $variants = New-Object System.Collections.Generic.List[string]
  if ($special.ContainsKey($g)) {
    [void]$variants.Add($special[$g])         # ADHPlatform
  } else {
    $first = $g.Substring(0,1)
    [void]$variants.Add("ADH$g")
    [void]$variants.Add("ADH$first$g")
  }

  $subs = Get-AzSubscription -ErrorAction Stop
  $matches = @()
  foreach ($v in $variants) {
    $pattern = "$envPrefix*_*$v"               # e.g. dev_azure_*_ADHMMDM
    $matches += $subs | Where-Object { $_.Name -like $pattern }
  }
  $matches = $matches | Sort-Object Name -Unique
  if (-not $matches) {
    $tried = $variants -join ', '
    throw "Resolve-AdhSubscriptions: no subscriptions matched for '$g' ($Environment). Tried: $tried"
  }

  if ($All) { return $matches }

  function Get-Rank([string]$name) {
    if ($name -like "$envPrefix*_ADH$g")                       { 0 }
    elseif ($name -like "$envPrefix*_ADH$($g.Substring(0,1))$g"){ 1 }
    elseif ($name -like "$envPrefix*_ADHPlatform")             { 2 }
    else                                                       { 9 }
  }

  $matches | Sort-Object @{e={Get-Rank $_.Name}}, Name | Select-Object -First 1
}
# ------------------------- /helpers -------------------------

Write-Host "Connecting to Azure using Service Principal credentials..." -ForegroundColor Cyan
try {
  $secure = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
  $cred   = New-Object System.Management.Automation.PSCredential ($ClientId, $secure)
  Connect-AzAccount -ServicePrincipal -Tenant $TenantId -Credential $cred -ErrorAction Stop | Out-Null
  Write-Host "Connected." -ForegroundColor Green
} catch {
  throw "Azure sign-in failed: $($_.Exception.Message)"
}

# subscriptions for the group/environment
$subs = @(Resolve-AdhSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type)
Write-Host "Found $($subs.Count) subscription(s) for $adh_group ($adh_subscription_type)."

# outputs
Ensure-Dir -Path $OutputDir
$csvPath  = New-StampedPath -BaseDir $OutputDir -Prefix "rg_permissions_${adh_group}_$adh_subscription_type" -Ext 'csv'
$htmlPath = [System.IO.Path]::ChangeExtension($csvPath, 'html')

$rows = @()

foreach ($sub in $subs) {
  Write-Host "Scanning subscription: $($sub.Name) [$($sub.Id)]" -ForegroundColor Yellow
  try {
    Set-AzContext -SubscriptionId $sub.Id -ErrorAction Stop | Out-Null
    $rgs = Get-AzResourceGroup -ErrorAction Stop
    foreach ($rg in $rgs) {
      $scope = "/subscriptions/{0}/resourceGroups/{1}" -f $sub.Id, $rg.ResourceGroupName
      $assigns = Get-AzRoleAssignment -Scope $scope -ErrorAction SilentlyContinue
      foreach ($a in ($assigns | Sort-Object RoleDefinitionName, DisplayName)) {
        $rows += [pscustomobject]@{
          SubscriptionName = $sub.Name
          SubscriptionId   = $sub.Id
          Environment      = $adh_subscription_type
          Custodian        = $adh_group
          ResourceGroup    = $rg.ResourceGroupName
          RoleDefinition   = $a.RoleDefinitionName
          PrincipalType    = $a.ObjectType
          PrincipalName    = $a.DisplayName
        }
      }
    }
  } catch {
    Write-Warning "Scan error on $($sub.Name): $($_.Exception.Message)"
    $rows += [pscustomobject]@{
      SubscriptionName = $sub.Name
      SubscriptionId   = $sub.Id
      Environment      = $adh_subscription_type
      Custodian        = $adh_group
      ResourceGroup    = '<error>'
      RoleDefinition   = '<error>'
      PrincipalType    = ''
      PrincipalName    = $_.Exception.Message
    }
  }
}

Write-CsvSafe -Rows $rows -Path $csvPath
Convert-CsvToHtml -CsvPath $csvPath -HtmlPath $htmlPath -Title "RG Permissions – $adh_group ($adh_subscription_type) $BranchName"

Write-Host "Output CSV : $csvPath"
Write-Host "Output HTML: $htmlPath"
