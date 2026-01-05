[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$TenantId,
  [Parameter(Mandatory)][string]$ClientId,
  [Parameter(Mandatory)][string]$ClientSecret,

  [Parameter(Mandatory)][string]$adh_group,
  [string]$adh_sub_group = '',
  [ValidateSet('nonprd','prd')][string]$adh_subscription_type = 'nonprd',

  [Parameter(Mandatory)][string]$OutputDir,
  [string]$BranchName = ''
)

$ErrorActionPreference = "Stop"

Import-Module Az.Accounts, Az.Network, Az.Resources -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

Ensure-Dir -Path $OutputDir | Out-Null

$adh_sub_group = $adh_sub_group.Trim()
if ([string]::IsNullOrWhiteSpace($adh_sub_group)) { $adh_sub_group = "" }

if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
  throw "Azure connection failed."
}

# Use your existing subscription resolution rules
$sub = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
Set-ScContext -Subscription $sub

$vnets = Get-AzVirtualNetwork -ErrorAction SilentlyContinue
if (-not $vnets) { $vnets = @() }

$rows = @()
foreach ($v in $vnets) {
  $peeringCount = 0
  try { $peeringCount = (Get-AzVirtualNetworkPeering -VirtualNetworkName $v.Name -ResourceGroupName $v.ResourceGroupName -ErrorAction SilentlyContinue | Measure-Object).Count } catch {}

  $subnetCount = 0
  try { $subnetCount = ($v.Subnets | Measure-Object).Count } catch {}

  $addr = ""
  try { $addr = ($v.AddressSpace.AddressPrefixes -join ";") } catch {}

  $rows += [pscustomobject]@{
    SubscriptionName = $sub.Name
    SubscriptionId   = $sub.Id
    ResourceGroup    = $v.ResourceGroupName
    VNetName         = $v.Name
    Location         = $v.Location
    AddressSpaces    = $addr
    SubnetCount      = $subnetCount
    PeeringCount     = $peeringCount
    DnsServers       = (($v.DhcpOptions.DnsServers -join ";") ?? "")
  }
}

if (-not $rows -or $rows.Count -eq 0) {
  $rows = @([pscustomobject]@{
    SubscriptionName=''; SubscriptionId=''; ResourceGroup=''; VNetName=''; Location='';
    AddressSpaces=''; SubnetCount=''; PeeringCount=''; DnsServers=''
  })
}

$groupForFile = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) { $adh_group } else { "${adh_group}_${adh_sub_group}" }
$stamp = Get-Date -Format 'yyyyMMdd'
$csvName = "vnet_${groupForFile}_${adh_subscription_type}_${stamp}.csv"
$csvOut = Join-Path $OutputDir $csvName

$rows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvOut
Write-Host "VNet scan completed. CSV: $csvOut" -ForegroundColor Green
