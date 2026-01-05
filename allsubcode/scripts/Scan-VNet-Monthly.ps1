[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$TenantId,
  [Parameter(Mandatory)][string]$ClientId,
  [Parameter(Mandatory)][string]$ClientSecret,

  [Parameter(Mandatory)][string]$adh_group,
  [string]$adh_sub_group = '',

  [ValidateSet('nonprd','prd')]
  [string]$adh_subscription_type = 'nonprd',

  [Parameter(Mandatory)][string]$OutputDir,
  [string]$BranchName = ''
)

$ErrorActionPreference = "Stop"

Import-Module Az.Accounts, Az.Network -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

Ensure-Dir -Path $OutputDir | Out-Null

# Login + set subscription context using your existing helper logic
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
  throw "Azure login failed."
}

$sub = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
Set-ScContext -Subscription $sub

# Collect VNets
$vnets = @(Get-AzVirtualNetwork -ErrorAction SilentlyContinue)

$rows = @()
foreach ($v in $vnets) {
  $subnetCount = 0
  try { $subnetCount = @($v.Subnets).Count } catch {}

  $peeringCount = 0
  try {
    $peeringCount = @(Get-AzVirtualNetworkPeering -ResourceGroupName $v.ResourceGroupName -VirtualNetworkName $v.Name -ErrorAction SilentlyContinue).Count
  } catch {}

  $addr = ''
  try { $addr = ($v.AddressSpace.AddressPrefixes -join ';') } catch {}

  $dns = ''
  try { $dns = ($v.DhcpOptions.DnsServers -join ';') } catch {}

  $rows += [pscustomobject]@{
    SubscriptionName = $sub.Name
    SubscriptionId   = $sub.Id
    Environment      = $adh_subscription_type
    Custodian        = $adh_group
    ResourceGroup    = $v.ResourceGroupName
    VNetName         = $v.Name
    Location         = $v.Location
    AddressSpaces    = $addr
    DnsServers       = $dns
    SubnetCount      = $subnetCount
    PeeringCount     = $peeringCount
  }
}

if (-not $rows -or $rows.Count -eq 0) {
  $rows = @([pscustomobject]@{
    SubscriptionName=''; SubscriptionId=''; Environment=$adh_subscription_type; Custodian=$adh_group;
    ResourceGroup=''; VNetName=''; Location=''; AddressSpaces=''; DnsServers=''; SubnetCount=0; PeeringCount=0
  })
}

$custodianForFile = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) { $adh_group } else { "${adh_group}_${adh_sub_group}" }
$stamp = Get-Date -Format 'yyyyMMdd'
$csvName = "vnet_{0}_{1}_{2}.csv" -f $custodianForFile, $adh_subscription_type, $stamp
$csvOut = Join-Path $OutputDir $csvName

Write-CsvSafe -Rows $rows -Path $csvOut

Write-Host "VNet scan completed."
Write-Host "CSV : $csvOut"
exit 0
