# Common.psm1
# --------------------------------------------------------------------
# Connect with SPN
function Connect-ScAz {
  param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$ClientId,
    [Parameter(Mandatory)][string]$ClientSecret
  )
  $sec = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
  $cred = New-Object System.Management.Automation.PSCredential($ClientId,$sec)
  Connect-AzAccount -ServicePrincipal -Tenant $TenantId -Credential $cred -WarningAction SilentlyContinue | Out-Null
}

# Map (adh_group, env) -> Subscriptions (array). We don’t assume exact names.
function Resolve-ScSubscriptions {
  param(
    [Parameter(Mandatory)][string]$AdhGroup,
    [ValidateSet('nonprd','prd')][string]$Environment = 'nonprd'
  )
  $subs = Get-AzSubscription

  # Special case: you asked for KTK to always use ADHPlatform subscription
  if ($AdhGroup -eq 'KTK') {
    $name = if ($Environment -eq 'prd') { 'prod_azure_20401_ADHPlatform' } else { 'dev_azure_20401_ADHPlatform' }
    $picked = $subs | Where-Object Name -eq $name
    if ($null -ne $picked) { return ,$picked }  # return as array
  }

  # Generic: tolerant matcher – must contain ADH and the group, and match env
  $envRegex = if ($Environment -eq 'prd') { '(?i)(prod|prd)' } else { '(?i)nonprod|nonprd|dev|test|tst|qa|stg' }
  $picked = $subs | Where-Object {
    $_.Name -match '(?i)ADH' -and
    $_.Name -match [Regex]::Escape($AdhGroup) -and
    $_.Name -match $envRegex
  }

  if (-not $picked) {
    throw "No subscriptions matched adh_group='$AdhGroup' env='$Environment'. Available: $($subs.Name -join ', ')"
  }
  ,$picked
}

function Set-ScContext {
  param([Parameter(Mandatory)]$Subscription)
  Set-AzContext -SubscriptionId $Subscription.Id | Out-Null
}

function Ensure-Dir { param([string]$Path) if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null } }

function New-StampedPath {
  param([string]$BaseDir,[string]$Prefix,[string]$Ext='csv')
  $ts = Get-Date -Format 'yyyyMMdd_HHmmss'
  Join-Path $BaseDir "$Prefix`_$ts.$Ext"
}

function Write-CsvSafe {
  param([object[]]$Rows,[string]$Path)
  if (-not $Rows) { $Rows = @() }
  $Rows | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
}

function Convert-CsvToHtml {
  param([string]$CsvPath,[string]$HtmlPath,[string]$Title)
  $dt = Import-Csv $CsvPath
  $html = $dt | ConvertTo-Html -Title $Title -PreContent "<h2>$Title</h2><p>Generated: $(Get-Date)</p>"
  Set-Content -Path $HtmlPath -Value $html -Encoding UTF8
}
# --------------------------------------------------------------------
Export-ModuleMember -Function *
