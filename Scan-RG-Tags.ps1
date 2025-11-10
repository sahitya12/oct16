# sanitychecks/scripts/Scan-RG-Tags.ps1
param(
  [Parameter(Mandatory)][string]$TenantId,
  [Parameter(Mandatory)][string]$ClientId,
  [Parameter(Mandatory)][string]$ClientSecret,

  [Parameter(Mandatory)][string]$adh_group,
  [ValidateSet('nonprd','prd')][string]$adh_subscription_type = 'nonprd',

  # Optional: if you tag RGs with adh_group, fill these
  [string]$MatchTagKey   = 'adh_group',
  [string]$MatchTagValue = $null,     # defaults to $adh_group if not provided

  [Parameter(Mandatory)][string]$OutputDir,
  [string]$BranchName = ''
)

# --- helpers ---------------------------------------------------------------
function Connect-ScAz {
  param($TenantId,$ClientId,$ClientSecret)
  $sec = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
  $creds = New-Object System.Management.Automation.PSCredential($ClientId,$sec)
  Connect-AzAccount -ServicePrincipal -Tenant $TenantId -Credential $creds -WarningAction SilentlyContinue | Out-Null
}

function Resolve-Subscription {
  param($adh_group,$env)
  # 1) explicit mapping for KTK as requested
  if ($adh_group -ieq 'KTK' -and $env -eq 'nonprd') { return 'dev_azure_20401_ADHPlatform' }
  # Add your other hard overrides here if needed…

  # 2) generic: pick any subscription whose name includes both env and ADH<custodian>
  $needle = "(?i)$env.*ADH$adh_group"
  $sub = Get-AzSubscription | Where-Object { $_.Name -match $needle } | Select-Object -First 1
  if (-not $sub) { throw "No subscription matched regex: $needle" }
  return $sub.Name
}

function Ensure-Dir($Path){ if(-not (Test-Path -LiteralPath $Path)){ New-Item -Force -ItemType Directory -Path $Path | Out-Null } }

function Flatten-Tags {
  param($Tags)
  if (-not $Tags) { return 'NONE' }
  # $Tags can be Hashtable or IDictionary<string,string>
  $pairs = @()
  foreach ($k in $Tags.Keys) {
    $v = $Tags[$k]
    if ($null -eq $v) { $v = '' }
    $pairs += "{0}={1}" -f $k,$v
  }
  return ($pairs -join ';')
}

# --- run -------------------------------------------------------------------
Ensure-Dir -Path $OutputDir
Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret

# Which subscription
$targetSubName = Resolve-Subscription -adh_group $adh_group -env $adh_subscription_type
$sub = Get-AzSubscription -SubscriptionName $targetSubName
Set-AzContext -SubscriptionId $sub.Id | Out-Null

# Tag value default
if (-not $MatchTagValue) { $MatchTagValue = $adh_group }

# Pull ALL RGs, then filter by (tag match) OR (name contains custodian token)
$allRgs = Get-AzResourceGroup -ErrorAction Stop
$filtered = $allRgs | Where-Object {
  $rg = $_
  $hasTag = $false
  if ($rg.Tags -and $rg.Tags.ContainsKey($MatchTagKey)) {
    $hasTag = ($rg.Tags[$MatchTagKey] -eq $MatchTagValue)
  }
  $nameHasToken = ($rg.ResourceGroupName -match "(?i)$adh_group")
  return ($hasTag -or $nameHasToken)
}

# Build rows (one per RG)
$rows = foreach ($rg in $filtered) {
  [pscustomobject]@{
    SubscriptionName = $sub.Name
    SubscriptionId   = $sub.Id
    Environment      = $adh_subscription_type
    ResourceGroup    = $rg.ResourceGroupName
    TagsFlat         = Flatten-Tags $rg.Tags
  }
}

# Save CSV + a quick HTML view
$stamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
$csv  = Join-Path $OutputDir ("rg_tags_{0}_{1}_{2}.csv" -f $adh_group,$adh_subscription_type,$stamp)
$rows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csv

$html = [System.IO.Path]::ChangeExtension($csv, '.html')
$rows | ConvertTo-Html -Title "RG Tags ($($adh_group)/$($adh_subscription_type)) $BranchName" |
  Out-File -Encoding UTF8 $html

Write-Host "RGs scanned: $($rows.Count)"
Write-Host "CSV : $csv"
Write-Host "HTML: $html"
