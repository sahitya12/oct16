[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$TenantId,
  [Parameter(Mandatory)][string]$ClientId,
  [Parameter(Mandatory)][string]$ClientSecret,

  [Parameter(Mandatory)][string]$adh_group,
  [string]$adh_sub_group = '',

  # MUST be string (ADO passes strings)
  [string]$adh_subscription_type = 'nonprd',

  [Parameter(Mandatory)][string]$OutputDir,
  [string]$BranchName = ''
)

$ErrorActionPreference = 'Stop'

# Normalize env
$adh_subscription_type = $adh_subscription_type.ToLower()
if ($adh_subscription_type -notin @('nonprd','prd')) {
  throw "Invalid adh_subscription_type: $adh_subscription_type"
}

Import-Module Az.Accounts, Az.Network -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

Ensure-Dir -Path $OutputDir | Out-Null

# Login
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
  throw "Azure login failed"
}

$sub = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
Set-ScContext -Subscription $sub

$vnets = @(Get-AzVirtualNetwork -ErrorAction SilentlyContinue)

$cust = if ($adh_sub_group) { "$adh_group`_$adh_sub_group" } else { $adh_group }
$stamp = Get-Date -Format 'yyyyMMdd'

$summary  = @()
$subnets  = @()
$peerings = @()

foreach ($v in $vnets) {

  foreach ($s in ($v.Subnets ?? @())) {
    $subnets += [pscustomobject]@{
      SubscriptionName = $sub.Name
      SubscriptionId   = $sub.Id
      Environment      = $adh_subscription_type
      Custodian        = $adh_group
      CustodianSubGroup= $adh_sub_group
      ResourceGroup    = $v.ResourceGroupName
      VNetName         = $v.Name
      SubnetName       = $s.Name
      SubnetPrefix     = ($s.AddressPrefix -join ';')
      NSGId            = $s.NetworkSecurityGroup.Id
      RouteTableId     = $s.RouteTable.Id
    }
  }

  foreach ($p in (Get-AzVirtualNetworkPeering -ResourceGroupName $v.ResourceGroupName -VirtualNetworkName $v.Name -ErrorAction SilentlyContinue)) {
    $peerings += [pscustomobject]@{
      SubscriptionName = $sub.Name
      SubscriptionId   = $sub.Id
      Environment      = $adh_subscription_type
      Custodian        = $adh_group
      CustodianSubGroup= $adh_sub_group
      VNetName         = $v.Name
      PeeringName      = $p.Name
      PeeringState     = $p.PeeringState
    }
  }

  $summary += [pscustomobject]@{
    SubscriptionName = $sub.Name
    SubscriptionId   = $sub.Id
    Environment      = $adh_subscription_type
    Custodian        = $adh_group
    CustodianSubGroup= $adh_sub_group
    ResourceGroup    = $v.ResourceGroupName
    VNetName         = $v.Name
    Location         = $v.Location
    AddressSpaces    = ($v.AddressSpace.AddressPrefixes -join ';')
    SubnetCount      = $v.Subnets.Count
  }
}

Write-CsvSafe $summary  (Join-Path $OutputDir "vnet_monthly_summary_${cust}_${adh_subscription_type}_$stamp.csv")
Write-CsvSafe $subnets  (Join-Path $OutputDir "vnet_monthly_subnets_${cust}_${adh_subscription_type}_$stamp.csv")
Write-CsvSafe $peerings (Join-Path $OutputDir "vnet_monthly_peerings_${cust}_${adh_subscription_type}_$stamp.csv")

Write-Host "VNet Monthly scan completed successfully"
exit 0
