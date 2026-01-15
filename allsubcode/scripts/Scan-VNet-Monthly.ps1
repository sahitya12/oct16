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

Ensure-Dir -Path $OutputDir | Out-Null

# ---------------- Login + subscription context ----------------
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
  throw "Azure login failed."
}

$sub = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
Set-ScContext -Subscription $sub

$custodianForFile = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) { $adh_group } else { "${adh_group}_${adh_sub_group}" }
$stamp = Get-Date -Format 'yyyyMMdd'

Write-Host "=== VNet Monthly Scan ==="
Write-Host "Subscription : $($sub.Name) ($($sub.Id))"
Write-Host "Custodian    : $custodianForFile"
Write-Host "Environment  : $adh_subscription_type"
Write-Host "Branch       : $BranchName"
Write-Host "OutputDir    : $OutputDir"
Write-Host "DateStamp    : $stamp"
Write-Host ""

# ---------------- Collect VNets ----------------
$vnets = @(Get-AzVirtualNetwork -ErrorAction SilentlyContinue)

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

    # Optional: derive names from IDs
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

  # Summary per VNet
  $summaryRows.Add([pscustomobject]@{
    SubscriptionName  = $sub.Name
    SubscriptionId    = $sub.Id
    Environment       = $adh_subscription_type
    Custodian         = $adh_group
    CustodianSubGroup = $adh_sub_group
    ResourceGroup     = $rg
    VNetName          = $vnetName
    Location          = $loc
    AddressSpaces     = $addr
    DnsServers        = $dns
    SubnetCount       = @($subnets).Count
    PeeringCount      = @($peerings).Count
  }) | Out-Null
}

# Handle case: no VNets
if ($summaryRows.Count -eq 0) {
  $summaryRows.Add([pscustomobject]@{
    SubscriptionName=''; SubscriptionId=''; Environment=$adh_subscription_type; Custodian=$adh_group; CustodianSubGroup=$adh_sub_group;
    ResourceGroup=''; VNetName=''; Location=''; AddressSpaces=''; DnsServers=''; SubnetCount=0; PeeringCount=0
  }) | Out-Null
}

# ---------------- Firewall scan (like Scan-VNet-Topology.ps1) ----------------
$fwRows = New-Object System.Collections.Generic.List[object]

try {
  $firewalls = @(Get-AzFirewall -ErrorAction SilentlyContinue)
} catch {
  $firewalls = @()
}

foreach ($fw in $firewalls) {

  $fwSku = ''
  try { $fwSku = "$($fw.Sku.Name)" } catch {}
  $tiMode = ''
  try { $tiMode = "$($fw.ThreatIntelMode)" } catch {}

  # If no IP configs -> still output one row
  if (-not $fw.IpConfigurations -or $fw.IpConfigurations.Count -eq 0) {
    $fwRows.Add([pscustomobject]@{
      SubscriptionName   = $sub.Name
      SubscriptionId     = $sub.Id
      Environment        = $adh_subscription_type
      Custodian          = $adh_group
      CustodianSubGroup  = $adh_sub_group
      ResourceGroup      = $fw.ResourceGroupName
      Location           = $fw.Location
      FirewallName       = $fw.Name
      FirewallSku        = $fwSku
      ThreatIntelMode    = $tiMode
      PublicIpName       = ''
      PublicIpAddress    = ''
      PublicIpSku        = ''
      PublicIpAllocation = ''
    }) | Out-Null
    continue
  }

  foreach ($ipc in $fw.IpConfigurations) {

    $pipName = ''
    $pipAddress = ''
    $pipSku = ''
    $pipAlloc = ''

    try {
      $pipId = $ipc.PublicIpAddress.Id
      if ($pipId -and $pipId -match '/publicIPAddresses/([^/]+)$') { $pipName = $Matches[1] }

      if ($pipId) {
        $pipObj = Get-AzPublicIpAddress -ResourceId $pipId -ErrorAction SilentlyContinue
        if ($pipObj) {
          $pipAddress = "$($pipObj.IpAddress)"
          $pipSku     = "$($pipObj.Sku.Name)"
          $pipAlloc   = "$($pipObj.PublicIpAllocationMethod)"
        }
      }
    } catch {}

    $fwRows.Add([pscustomobject]@{
      SubscriptionName   = $sub.Name
      SubscriptionId     = $sub.Id
      Environment        = $adh_subscription_type
      Custodian          = $adh_group
      CustodianSubGroup  = $adh_sub_group
      ResourceGroup      = $fw.ResourceGroupName
      Location           = $fw.Location
      FirewallName       = $fw.Name
      FirewallSku        = $fwSku
      ThreatIntelMode    = $tiMode
      PublicIpName       = $pipName
      PublicIpAddress    = $pipAddress
      PublicIpSku        = $pipSku
      PublicIpAllocation = $pipAlloc
    }) | Out-Null
  }
}

# If no firewalls, still create file with one blank row (helps downstream tooling)
if ($fwRows.Count -eq 0) {
  $fwRows.Add([pscustomobject]@{
    SubscriptionName=''; SubscriptionId=''; Environment=$adh_subscription_type; Custodian=$adh_group; CustodianSubGroup=$adh_sub_group;
    ResourceGroup=''; Location=''; FirewallName=''; FirewallSku=''; ThreatIntelMode='';
    PublicIpName=''; PublicIpAddress=''; PublicIpSku=''; PublicIpAllocation=''
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
Write-Host "Summary  : $summaryCsv"
Write-Host "Subnets  : $subnetCsv"
Write-Host "Peerings : $peeringCsv"
Write-Host "Firewalls: $fwCsv"
exit 0
