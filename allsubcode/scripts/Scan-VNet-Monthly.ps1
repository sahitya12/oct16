<#  Scan-VNet-Monthly.ps1
    ------------------------------------------------------------
    What this script produces (ALWAYS):
      1) vnet_monthly_summary_<cust>_<env>_<yyyymmdd>.csv
      2) vnet_monthly_subnets_<cust>_<env>_<yyyymmdd>.csv
      3) vnet_monthly_peerings_<cust>_<env>_<yyyymmdd>.csv

    Notes:
    - No ValidateSet on adh_subscription_type (prevents ADO "Argument types do not match")
    - Manual env validation + normalization (nonprd/prd)
    - Always writes all 3 CSVs (even if there are zero VNets/subnets/peerings)
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$TenantId,
  [Parameter(Mandatory)][string]$ClientId,
  [Parameter(Mandatory)][string]$ClientSecret,

  [Parameter(Mandatory)][string]$adh_group,
  [string]$adh_sub_group = '',

  # IMPORTANT: keep as string (ADO passes strings)
  [string]$adh_subscription_type = 'nonprd',

  [Parameter(Mandatory)][string]$OutputDir,
  [string]$BranchName = ''
)

$ErrorActionPreference = "Stop"

# ---------------- Normalize + validate env ----------------
$adh_subscription_type = ("$adh_subscription_type").Trim().ToLower()
if ($adh_subscription_type -notin @('nonprd','prd')) {
  throw "Invalid adh_subscription_type: '$adh_subscription_type'. Allowed values: nonprd, prd"
}

# ---------------- Imports ----------------
Import-Module Az.Accounts, Az.Network -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

# ---------------- Helpers ----------------
function SafeJoin([object]$arr, [string]$sep=';') {
  try {
    if ($null -eq $arr) { return '' }
    return (@($arr) | Where-Object { $_ -ne $null -and "$_".Trim() -ne '' } | ForEach-Object { "$_".Trim() }) -join $sep
  } catch { return '' }
}

function BoolStr($v) {
  if ($null -eq $v) { return '' }
  return [bool]$v
}

# Ensure output dir
Ensure-Dir -Path $OutputDir | Out-Null

# ---------------- Login + subscription context ----------------
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
  throw "Azure login failed."
}

$sub = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
Set-ScContext -Subscription $sub

# ---------------- Collect VNets ----------------
$vnets = @(Get-AzVirtualNetwork -ErrorAction SilentlyContinue)

$custodianForFile = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) { $adh_group } else { "${adh_group}_${adh_sub_group}" }
$stamp = Get-Date -Format 'yyyyMMdd'

$summaryRows = New-Object System.Collections.Generic.List[object]
$subnetRows  = New-Object System.Collections.Generic.List[object]
$peeringRows = New-Object System.Collections.Generic.List[object]

foreach ($v in $vnets) {

  $rg       = $v.ResourceGroupName
  $loc      = $v.Location
  $vnetName = $v.Name

  $addr = ''
  try { $addr = SafeJoin $v.AddressSpace.AddressPrefixes } catch {}

  $dns = ''
  try { $dns = SafeJoin $v.DhcpOptions.DnsServers } catch {}

  # -------- Subnets --------
  $subnets = @()
  try { $subnets = @($v.Subnets) } catch { $subnets = @() }

  foreach ($s in $subnets) {
    $nsgId = ''
    $rtId  = ''
    $deleg = ''
    $svcEp = ''
    $pvtEpPolicies = ''
    $pvtLinkSvcPolicies = ''

    try { $nsgId = "$($s.NetworkSecurityGroup.Id)" } catch {}
    try { $rtId  = "$($s.RouteTable.Id)" } catch {}

    try {
      if ($s.Delegations) { $deleg = SafeJoin ($s.Delegations | ForEach-Object { $_.ServiceName }) }
    } catch {}

    try {
      if ($s.ServiceEndpoints) { $svcEp = SafeJoin ($s.ServiceEndpoints | ForEach-Object { $_.Service }) }
    } catch {}

    try { $pvtEpPolicies = "$($s.PrivateEndpointNetworkPolicies)" } catch {}
    try { $pvtLinkSvcPolicies = "$($s.PrivateLinkServiceNetworkPolicies)" } catch {}

    # derive friendly names from IDs (optional)
    $nsgName = ''
    if ($nsgId -match '/networkSecurityGroups/([^/]+)$') { $nsgName = $Matches[1] }

    $rtName = ''
    if ($rtId -match '/routeTables/([^/]+)$') { $rtName = $Matches[1] }

    $subnetRows.Add([pscustomobject]@{
      SubscriptionName               = $sub.Name
      SubscriptionId                 = $sub.Id
      Environment                    = $adh_subscription_type
      Custodian                      = $adh_group
      CustodianSubGroup              = $adh_sub_group
      ResourceGroup                  = $rg
      VNetName                       = $vnetName
      Location                       = $loc
      SubnetName                     = $s.Name
      SubnetPrefix                   = (SafeJoin $s.AddressPrefix)
      NSGName                        = $nsgName
      NSGId                          = $nsgId
      RouteTableName                 = $rtName
      RouteTableId                   = $rtId
      Delegations                    = $deleg
      ServiceEndpoints               = $svcEp
      PrivateEndpointNetworkPolicies = $pvtEpPolicies
      PrivateLinkServicePolicies     = $pvtLinkSvcPolicies
    }) | Out-Null
  }

  # -------- Peerings --------
  $peerings = @()
  try {
    $peerings = @(Get-AzVirtualNetworkPeering -ResourceGroupName $rg -VirtualNetworkName $vnetName -ErrorAction SilentlyContinue)
  } catch { $peerings = @() }

  foreach ($p in $peerings) {
    $peeringRows.Add([pscustomobject]@{
      SubscriptionName        = $sub.Name
      SubscriptionId          = $sub.Id
      Environment             = $adh_subscription_type
      Custodian               = $adh_group
      CustodianSubGroup       = $adh_sub_group
      ResourceGroup           = $rg
      VNetName                = $vnetName
      PeeringName             = $p.Name
      PeeringState            = $p.PeeringState
      RemoteVNetId            = $p.RemoteVirtualNetwork.Id
      AllowVNetAccess         = BoolStr $p.AllowVirtualNetworkAccess
      AllowForwardedTraffic   = BoolStr $p.AllowForwardedTraffic
      AllowGatewayTransit     = BoolStr $p.AllowGatewayTransit
      UseRemoteGateways       = BoolStr $p.UseRemoteGateways
      DoNotVerifyRemoteGW     = BoolStr $p.DoNotVerifyRemoteGateways
    }) | Out-Null
  }

  # -------- Summary (per VNet) --------
  $summaryRows.Add([pscustomobject]@{
    SubscriptionName = $sub.Name
    SubscriptionId   = $sub.Id
    Environment      = $adh_subscription_type
    Custodian        = $adh_group
    CustodianSubGroup= $adh_sub_group
    ResourceGroup    = $rg
    VNetName         = $vnetName
    Location         = $loc
    AddressSpaces    = $addr
    DnsServers       = $dns
    SubnetCount      = @($subnets).Count
    PeeringCount     = @($peerings).Count
  }) | Out-Null
}

# Handle case: no VNets -> still write all 3 CSVs (with headers)
if ($summaryRows.Count -eq 0) {
  $summaryRows.Add([pscustomobject]@{
    SubscriptionName=''; SubscriptionId=''; Environment=$adh_subscription_type; Custodian=$adh_group; CustodianSubGroup=$adh_sub_group;
    ResourceGroup=''; VNetName=''; Location=''; AddressSpaces=''; DnsServers=''; SubnetCount=0; PeeringCount=0
  }) | Out-Null
}

# Ensure empty-but-valid collections so CSVs still get created
if ($subnetRows.Count -eq 0) {
  $subnetRows.Add([pscustomobject]@{
    SubscriptionName=''; SubscriptionId=''; Environment=$adh_subscription_type; Custodian=$adh_group; CustodianSubGroup=$adh_sub_group;
    ResourceGroup=''; VNetName=''; Location=''; SubnetName=''; SubnetPrefix=''; NSGName=''; NSGId=''; RouteTableName=''; RouteTableId='';
    Delegations=''; ServiceEndpoints=''; PrivateEndpointNetworkPolicies=''; PrivateLinkServicePolicies=''
  }) | Out-Null
}

if ($peeringRows.Count -eq 0) {
  $peeringRows.Add([pscustomobject]@{
    SubscriptionName=''; SubscriptionId=''; Environment=$adh_subscription_type; Custodian=$adh_group; CustodianSubGroup=$adh_sub_group;
    ResourceGroup=''; VNetName=''; PeeringName=''; PeeringState=''; RemoteVNetId='';
    AllowVNetAccess=''; AllowForwardedTraffic=''; AllowGatewayTransit=''; UseRemoteGateways=''; DoNotVerifyRemoteGW=''
  }) | Out-Null
}

# ---------------- Write CSVs ----------------
$summaryCsv = Join-Path $OutputDir ("vnet_monthly_summary_{0}_{1}_{2}.csv" -f $custodianForFile, $adh_subscription_type, $stamp)
$subnetCsv  = Join-Path $OutputDir ("vnet_monthly_subnets_{0}_{1}_{2}.csv"  -f $custodianForFile, $adh_subscription_type, $stamp)
$peeringCsv = Join-Path $OutputDir ("vnet_monthly_peerings_{0}_{1}_{2}.csv" -f $custodianForFile, $adh_subscription_type, $stamp)

Write-CsvSafe -Rows @($summaryRows) -Path $summaryCsv
Write-CsvSafe -Rows @($subnetRows)  -Path $subnetCsv
Write-CsvSafe -Rows @($peeringRows) -Path $peeringCsv

Write-Host "VNet Monthly scan completed."
Write-Host "Summary CSV : $summaryCsv"
Write-Host "Subnets CSV : $subnetCsv"
Write-Host "Peerings CSV: $peeringCsv"
exit 0
