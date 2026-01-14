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

  # ✅ IMPORTANT: Run-AllSubscriptions passes this; keep it to avoid "Argument types do not match"
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

function TryGet-NameFromId([string]$id, [string]$token) {
  # token example: 'routeTables' or 'networkSecurityGroups'
  if ([string]::IsNullOrWhiteSpace($id)) { return '' }
  if ($id -match "/$token/([^/]+)$") { return $Matches[1] }
  return ''
}

function TryGet-DefaultRouteInfo {
  param(
    [string]$RouteTableId
  )
  # Returns @{ DefaultRouteName=...; DefaultRouteNextHopType=...; DefaultRouteNextHopIp=... }
  $result = @{
    DefaultRouteName        = ''
    DefaultRouteNextHopType = ''
    DefaultRouteNextHopIp   = ''
  }

  try {
    if ([string]::IsNullOrWhiteSpace($RouteTableId)) { return $result }

    # Parse RG + RT name from resource ID
    # /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Network/routeTables/<name>
    if ($RouteTableId -notmatch "/resourceGroups/([^/]+)/providers/.*/routeTables/([^/]+)$") {
      return $result
    }
    $rg = $Matches[1]
    $rtName = $Matches[2]

    $rt = Get-AzRouteTable -ResourceGroupName $rg -Name $rtName -ErrorAction Stop
    if (-not $rt -or -not $rt.Routes) { return $result }

    # Prefer default route 0.0.0.0/0
    $default = $rt.Routes | Where-Object { $_.AddressPrefix -eq '0.0.0.0/0' } | Select-Object -First 1
    if (-not $default) {
      # If no 0.0.0.0/0, pick first route as fallback (still useful evidence)
      $default = $rt.Routes | Select-Object -First 1
    }

    if ($default) {
      $result.DefaultRouteName        = "$($default.Name)"
      $result.DefaultRouteNextHopType = "$($default.NextHopType)"
      $result.DefaultRouteNextHopIp   = "$($default.NextHopIpAddress)"
    }

    return $result
  }
  catch {
    # swallow - do not fail VNet scan because of RT read errors
    return $result
  }
}

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

    $nsgName = TryGet-NameFromId -id $nsgId -token 'networkSecurityGroups'
    $rtName  = TryGet-NameFromId -id $rtId  -token 'routeTables'

    # ✅ Firewall/UDR evidence from Route Table
    $rtInfo = TryGet-DefaultRouteInfo -RouteTableId $rtId

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

      # ✅ Extra routing evidence (often points to Azure Firewall IP)
      DefaultRouteName               = $rtInfo.DefaultRouteName
      DefaultRouteNextHopType        = $rtInfo.DefaultRouteNextHopType
      DefaultRouteNextHopIp          = $rtInfo.DefaultRouteNextHopIp

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

# Handle case: no VNets (still produce CSVs)
if ($summaryRows.Count -eq 0) {
  $summaryRows.Add([pscustomobject]@{
    SubscriptionName=''; SubscriptionId=''; Environment=$adh_subscription_type; Custodian=$adh_group; CustodianSubGroup=$adh_sub_group;
    ResourceGroup=''; VNetName=''; Location=''; AddressSpaces=''; DnsServers=''; SubnetCount=0; PeeringCount=0
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
