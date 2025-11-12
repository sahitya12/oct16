#requires -Modules Az.Accounts, Az.Resources

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Ensure-Dir {
  param([Parameter(Mandatory)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path | Out-Null }
  return (Resolve-Path -LiteralPath $Path).Path
}

function New-StampedPath {
  param(
    [Parameter(Mandatory)][string]$BaseDir,
    [Parameter(Mandatory)][string]$Prefix,
    [string]$Ext = 'csv'
  )
  $ts = Get-Date -Format 'yyyyMMdd_HHmm'
  $name = '{0}_{1}.{2}' -f $Prefix,$ts,$Ext
  Join-Path (Ensure-Dir $BaseDir) $name
}

function Write-CsvSafe {
  param(
    [Parameter(Mandatory)][object[]]$Rows,
    [Parameter(Mandatory)][string]$Path
  )
  $Rows | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
}

function Convert-CsvToHtml {
  param(
    [Parameter(Mandatory)][string]$CsvPath,
    [Parameter(Mandatory)][string]$HtmlPath,
    [string]$Title = 'Report'
  )
  $data = Import-Csv -Path $CsvPath
  $html = $data | ConvertTo-Html -Title $Title -PreContent "<h2>$Title</h2>"
  $html | Out-File -FilePath $HtmlPath -Encoding UTF8
}

function Connect-ScAz {
  param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$ClientId,
    [Parameter(Mandatory)][string]$ClientSecret
  )
  try {
    $sec = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential($ClientId,$sec)
    Connect-AzAccount -ServicePrincipal -Tenant $TenantId -Credential $cred -ErrorAction Stop | Out-Null
    return $true
  } catch {
    Write-Error "Azure login failed: $($_.Exception.Message)"
    return $false
  }
}

function Set-ScContext {
  param([Parameter(Mandatory)][object]$Subscription)
  if ($Subscription -is [string]) {
    Set-AzContext -SubscriptionId $Subscription | Out-Null
  } else {
    Set-AzContext -SubscriptionId $Subscription.Id | Out-Null
  }
}

# ------------ Subscription Resolution ------------
# Rules:
# - KTK => dev_azure_20401_ADHPlatform
# - Others => name contains adh_group and matches env tokens
function Resolve-ScSubscriptions {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$AdhGroup,
    [ValidateSet('nonprd','prd')][string]$Environment = 'nonprd'
  )

  $all = Get-AzSubscription -ErrorAction Stop

  if ($AdhGroup -ieq 'KTK') {
    $target = 'dev_azure_20401_ADHPlatform'
    $hit = $all | Where-Object { $_.Name -ieq $target }
    if (-not $hit) {
      Write-Warning "Expected subscription '$target' not found for KTK."
      return @()
    }
    return ,$hit   # single-item array
  }

  # Environment tokens
  $nonprdTokens = @('dev','test','tst','qa','uat','nonprd','nonproduction','sandbox')
  $prdTokens    = @('prod','production','prd')

  $tokens = if ($Environment -eq 'prd') { $prdTokens } else { $nonprdTokens }

  $regex = [string]::Join('|', ($tokens | ForEach-Object {[regex]::Escape($_)}))
  $adh   = [regex]::Escape($AdhGroup)

  $hits = $all | Where-Object {
    $_.Name -match "(?i)$regex" -and $_.Name -match "(?i)$adh"
  }

  if (-not $hits) {
    Write-Warning "No subscriptions matched adh_group='$AdhGroup' environment='$Environment'."
  }

  # deterministic order
  $hits | Sort-Object Name
}

# Back-compat alias (some scripts used this)
function Get-ScSubscriptions {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$AdhGroup,
    [ValidateSet('nonprd','prd')][string]$Environment = 'nonprd'
  )
  Resolve-ScSubscriptions -AdhGroup $AdhGroup -Environment $Environment
}
Export-ModuleMember -Function *-Sc*,Ensure-Dir,New-StampedPath,Write-CsvSafe,Convert-CsvToHtml
