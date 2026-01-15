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

# ---------------- Modules ----------------
Import-Module Az.Accounts -ErrorAction Stop
Import-Module Az.Network   -ErrorAction Stop

# Your repo helper module (used across sanitychecks)
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

# ---------------- Helpers ----------------
function SafeJoin([object]$arr, [string]$sep=';') {
  try {
    if ($null -eq $arr) { return '' }
    return (@($arr) | Where-Object { $_ -ne $null -and "$_".Trim() -ne '' } | ForEach-Object { "$_".Trim() }) -join $sep
  } catch { return '' }
}

function BoolStr($v) {
  try {
    if ($null -eq $v) { return '' }
    return [bool]$v
  } catch { return '' }
}

function Get-NameFromId([string]$id, [string]$segment) {
  if ([string]::IsNullOrWhiteSpace($id)) { return '' }
  $rx = "/$segment/([^/]+)$"
  if ($id -match $rx) { return $Matches[1] }
  return ''
}

# Ensure output dir exists
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
$fwRows      = New-Object System.Collections.Generic.List[object]

foreach ($v in $vnets) {

  $rg  = $v.ResourceGroupName
  $loc = $v.Location
  $vnetName = $v.Name

  $addr = ''
  try { $addr = SafeJoin $v.AddressSpace.AddressPrefixes } catch {}

  $dns = ''
  try { $dns = SafeJoin $v.DhcpOptions.DnsServers } catch {}

  # Subnets
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

    $nsgName = Get-NameFromId -id $nsgId -segment 'networkSecurityGroups'
    $rtName  = Get-NameFromId -id $rtId  -segment 'routeTables'

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

  # Peerings
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

  # Summary (per VNet)
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

# Handle case: no VNets
if ($summaryRows.Count -eq 0) {
  $summaryRows.Add([pscustomobject]@{
    SubscriptionName=''; SubscriptionId=''; Environment=$adh_subscription_type; Custodian=$adh_group; CustodianSubGroup=$adh_sub_group;
    ResourceGroup=''; VNetName=''; Location=''; AddressSpaces=''; DnsServers=''; SubnetCount=0; PeeringCount=0
  }) | Out-Null
}

# ---------------- Collect Azure Firewall details ----------------
# This is the "firewall details missing" part you asked for.
try {
  $firewalls = @(Get-AzFirewall -ErrorAction SilentlyContinue)
} catch {
  $firewalls = @()
}

foreach ($fw in $firewalls) {

  $fwRg  = $fw.ResourceGroupName
  $fwLoc = $fw.Location

  $policyId = ''
  try { $policyId = "$($fw.FirewallPolicy.Id)" } catch {}
  $policyName = Get-NameFromId -id $policyId -segment 'firewallPolicies'

  $vnetId = ''
  try { $vnetId = "$($fw.VirtualNetwork.Id)" } catch {}
  $vnetName = Get-NameFromId -id $vnetId -segment 'virtualNetworks'

  $skuName = ''
  $skuTier = ''
  try { $skuName = "$($fw.Sku.Name)" } catch {}
  try { $skuTier = "$($fw.Sku.Tier)" } catch {}

  $threatIntel = ''
  try { $threatIntel = "$($fw.ThreatIntelMode)" } catch {}

  # IP Configs (private/public)
  $privateIps = New-Object System.Collections.Generic.List[string]
  $publicIps  = New-Object System.Collections.Generic.List[string]
  $publicIpIds= New-Object System.Collections.Generic.List[string]
  $ipcfgNames = New-Object System.Collections.Generic.List[string]

  try {
    foreach ($ipc in @($fw.IpConfigurations)) {
      if ($ipc -and $ipc.Name) { $ipcfgNames.Add("$($ipc.Name)") | Out-Null }

      try {
        if ($ipc.PrivateIPAddress) { $privateIps.Add("$($ipc.PrivateIPAddress)") | Out-Null }
      } catch {}

      $pipId = ''
      try { $pipId = "$($ipc.PublicIpAddress.Id)" } catch {}
      if (-not [string]::IsNullOrWhiteSpace($pipId)) {
        $publicIpIds.Add($pipId) | Out-Null
        try {
          $pipName = Get-NameFromId -id $pipId -segment 'publicIPAddresses'
          $pipObj = Get-AzPublicIpAddress -ResourceGroupName $fwRg -Name $pipName -ErrorAction SilentlyContinue
          if ($pipObj -and $pipObj.IpAddress) {
            $publicIps.Add("$($pipObj.IpAddress)") | Out-Null
          } else {
            # fallback: store name if IP not allocated yet
            $publicIps.Add($pipName) | Out-Null
          }
        } catch {
          $publicIps.Add((Get-NameFromId -id $pipId -segment 'publicIPAddresses')) | Out-Null
        }
      }
    }
  } catch {}

  # Mgmt IP config (if present)
  $mgmtPrivateIp = ''
  $mgmtPublicIp  = ''
  $mgmtPipId     = ''
  try {
    if ($fw.ManagementIpConfiguration) {
      try { $mgmtPrivateIp = "$($fw.ManagementIpConfiguration.PrivateIPAddress)" } catch {}
      try { $mgmtPipId = "$($fw.ManagementIpConfiguration.PublicIpAddress.Id)" } catch {}
      if (-not [string]::IsNullOrWhiteSpace($mgmtPipId)) {
        try {
          $mgmtPipName = Get-NameFromId -id $mgmtPipId -segment 'publicIPAddresses'
          $mgmtPipObj = Get-AzPublicIpAddress -ResourceGroupName $fwRg -Name $mgmtPipName -ErrorAction SilentlyContinue
          if ($mgmtPipObj -and $mgmtPipObj.IpAddress) { $mgmtPublicIp = "$($mgmtPipObj.IpAddress)" }
          else { $mgmtPublicIp = $mgmtPipName }
        } catch {
          $mgmtPublicIp = Get-NameFromId -id $mgmtPipId -segment 'publicIPAddresses'
        }
      }
    }
  } catch {}

  $fwRows.Add([pscustomobject]@{
    SubscriptionName     = $sub.Name
    SubscriptionId       = $sub.Id
    Environment          = $adh_subscription_type
    Custodian            = $adh_group
    CustodianSubGroup    = $adh_sub_group
    ResourceGroup        = $fwRg
    Location             = $fwLoc
    FirewallName         = $fw.Name
    FirewallId           = $fw.Id
    SkuName              = $skuName
    SkuTier              = $skuTier
    ThreatIntelMode      = $threatIntel
    FirewallPolicyName   = $policyName
    FirewallPolicyId     = $policyId
    VirtualNetworkName   = $vnetName
    VirtualNetworkId     = $vnetId
    IpConfigurationNames = (SafeJoin $ipcfgNames ';')
    PrivateIPs           = (SafeJoin $privateIps ';')
    PublicIPIds          = (SafeJoin $publicIpIds ';')
    PublicIPs            = (SafeJoin $publicIps ';')
    MgmtPrivateIP        = $mgmtPrivateIp
    MgmtPublicIP         = $mgmtPublicIp
    MgmtPublicIPId       = $mgmtPipId
  }) | Out-Null
}

# If no firewalls exist, still output an empty CSV with headers
if ($fwRows.Count -eq 0) {
  $fwRows.Add([pscustomobject]@{
    SubscriptionName=$sub.Name; SubscriptionId=$sub.Id; Environment=$adh_subscription_type; Custodian=$adh_group; CustodianSubGroup=$adh_sub_group;
    ResourceGroup=''; Location=''; FirewallName=''; FirewallId=''; SkuName=''; SkuTier=''; ThreatIntelMode='';
    FirewallPolicyName=''; FirewallPolicyId=''; VirtualNetworkName=''; VirtualNetworkId='';
    IpConfigurationNames=''; PrivateIPs=''; PublicIPIds=''; PublicIPs='';
    MgmtPrivateIP=''; MgmtPublicIP=''; MgmtPublicIPId=''
  }) | Out-Null
}

# ---------------- Write CSVs ----------------
$summaryCsv = Join-Path $OutputDir ("vnet_monthly_summary_{0}_{1}_{2}.csv"  -f $custodianForFile, $adh_subscription_type, $stamp)
$subnetCsv  = Join-Path $OutputDir ("vnet_monthly_subnets_{0}_{1}_{2}.csv"  -f $custodianForFile, $adh_subscription_type, $stamp)
$peeringCsv = Join-Path $OutputDir ("vnet_monthly_peerings_{0}_{1}_{2}.csv" -f $custodianForFile, $adh_subscription_type, $stamp)
$fwCsv      = Join-Path $OutputDir ("vnet_monthly_firewalls_{0}_{1}_{2}.csv" -f $custodianForFile, $adh_subscription_type, $stamp)

Write-CsvSafe -Rows @($summaryRows) -Path $summaryCsv
Write-CsvSafe -Rows @($subnetRows)  -Path $subnetCsv
Write-CsvSafe -Rows @($peeringRows) -Path $peeringCsv
Write-CsvSafe -Rows @($fwRows)      -Path $fwCsv

Write-Host "VNet Monthly scan completed."
Write-Host "Summary CSV  : $summaryCsv"
Write-Host "Subnets CSV  : $subnetCsv"
Write-Host "Peerings CSV : $peeringCsv"
Write-Host "Firewalls CSV: $fwCsv"

exit 0
