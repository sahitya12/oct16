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

# Import modules safely (separate imports avoids odd module-load issues)
Import-Module Az.Accounts -ErrorAction Stop
Import-Module Az.Network   -ErrorAction Stop

Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

# ---------------- Helpers ----------------
function SafeJoin([object]$arr, [string]$sep=';') {
  try {
    if ($null -eq $arr) { return '' }
    return (@($arr) |
      Where-Object { $_ -ne $null -and "$_".Trim() -ne '' } |
      ForEach-Object { "$_".Trim() }
    ) -join $sep
  } catch { return '' }
}

function BoolStr($v) {
  if ($null -eq $v) { return '' }
  return [bool]$v
}

function Extract-NameFromId([string]$id, [string]$segment) {
  if ([string]::IsNullOrWhiteSpace($id)) { return '' }
  $pattern = "/$segment/([^/]+)$"
  if ($id -match $pattern) { return $Matches[1] }
  return ''
}

Ensure-Dir -Path $OutputDir | Out-Null

# ---------------- Login + subscription context ----------------
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
  throw "Azure login failed."
}

$sub = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
Set-ScContext -Subscription $sub

Write-Host "Context subscription:"
Write-Host "  Name: $($sub.Name)"
Write-Host "  Id  : $($sub.Id)"
Write-Host ""

# ---------------- Collect Firewall inventory in THIS subscription (if any) ----------------
$firewallRows = New-Object System.Collections.Generic.List[object]
$firewallIpToName = @{}   # map private IP -> firewall name

$firewalls = @()
try { $firewalls = @(Get-AzFirewall -ErrorAction SilentlyContinue) } catch { $firewalls = @() }

foreach ($fw in $firewalls) {
  $fwPrivIps = @()
  try {
    # IpConfigurations holds PrivateIPAddress
    $fwPrivIps = @($fw.IpConfigurations | ForEach-Object { $_.PrivateIPAddress } | Where-Object { $_ })
  } catch { $fwPrivIps = @() }

  foreach ($ip in $fwPrivIps) {
    if (-not $firewallIpToName.ContainsKey($ip)) {
      $firewallIpToName[$ip] = $fw.Name
    }
  }

  $pubIpIds = @()
  try {
    $pubIpIds = @($fw.IpConfigurations | ForEach-Object { $_.PublicIpAddress.Id } | Where-Object { $_ })
  } catch { $pubIpIds = @() }

  $pubIpNames = @($pubIpIds | ForEach-Object { Extract-NameFromId $_ 'publicIPAddresses' })

  $fwPolicyId = ''
  $fwPolicyName = ''
  try { $fwPolicyId = "$($fw.FirewallPolicy.Id)" } catch {}
  if ($fwPolicyId) { $fwPolicyName = Extract-NameFromId $fwPolicyId 'firewallPolicies' }

  $fwVnetId = ''
  $fwVnetName = ''
  try { $fwVnetId = "$($fw.VirtualNetwork.Id)" } catch {}
  if ($fwVnetId) { $fwVnetName = Extract-NameFromId $fwVnetId 'virtualNetworks' }

  $firewallRows.Add([pscustomobject]@{
    SubscriptionName = $sub.Name
    SubscriptionId   = $sub.Id
    Environment      = $adh_subscription_type
    Custodian        = $adh_group
    CustodianSubGroup= $adh_sub_group
    FirewallName     = $fw.Name
    ResourceGroup    = $fw.ResourceGroupName
    Location         = $fw.Location
    FirewallSku      = "$($fw.Sku.Name)"
    FirewallTier     = "$($fw.Sku.Tier)"
    VNetName         = $fwVnetName
    VNetId           = $fwVnetId
    PrivateIPs       = SafeJoin $fwPrivIps
    PublicIpNames    = SafeJoin $pubIpNames
    PublicIpIds      = SafeJoin $pubIpIds
    FirewallPolicyName = $fwPolicyName
    FirewallPolicyId   = $fwPolicyId
  }) | Out-Null
}

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

    $nsgName = Extract-NameFromId $nsgId 'networkSecurityGroups'
    $rtName  = Extract-NameFromId $rtId  'routeTables'

    # -------- Firewall evidence via UDRs (Route Table) --------
    $udrHasVirtualAppliance = $false
    $udrVirtualApplianceIps = @()
    $udrRoutesSummary = @()
    $udrFirewallNamesGuess = @()

    if ($rtName) {
      try {
        $rt = Get-AzRouteTable -ResourceGroupName $rg -Name $rtName -ErrorAction SilentlyContinue
        if ($rt -and $rt.Routes) {
          foreach ($route in $rt.Routes) {
            $nhType = "$($route.NextHopType)"
            $nhIp   = "$($route.NextHopIpAddress)"
            $udrRoutesSummary += ("{0}:{1}:{2}" -f $route.Name, $nhType, $nhIp)

            if ($nhType -eq 'VirtualAppliance' -and -not [string]::IsNullOrWhiteSpace($nhIp)) {
              $udrHasVirtualAppliance = $true
              $udrVirtualApplianceIps += $nhIp

              # If firewall is in same sub and we discovered it, map IP -> FW name
              if ($firewallIpToName.ContainsKey($nhIp)) {
                $udrFirewallNamesGuess += $firewallIpToName[$nhIp]
              }
            }
          }
        }
      } catch {
        # ignore route table read failure, still export subnet row
      }
    }

    $udrVirtualApplianceIps = @($udrVirtualApplianceIps | Select-Object -Unique)
    $udrFirewallNamesGuess  = @($udrFirewallNamesGuess  | Select-Object -Unique)

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

      # Firewall evidence fields (works even if FW is in HUB subscription)
      HasUDRVirtualAppliance         = $udrHasVirtualAppliance
      UDRVirtualApplianceIPs         = (SafeJoin $udrVirtualApplianceIps)
      UDRFirewallNameGuess           = (SafeJoin $udrFirewallNamesGuess)
      UDRRoutesSummary               = (SafeJoin $udrRoutesSummary)
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
    FirewallCountInThisSubscription = @($firewalls).Count
  }) | Out-Null
}

# Handle case: no VNets
if ($summaryRows.Count -eq 0) {
  $summaryRows.Add([pscustomobject]@{
    SubscriptionName=''; SubscriptionId=''; Environment=$adh_subscription_type; Custodian=$adh_group; CustodianSubGroup=$adh_sub_group;
    ResourceGroup=''; VNetName=''; Location=''; AddressSpaces=''; DnsServers=''; SubnetCount=0; PeeringCount=0; FirewallCountInThisSubscription=@($firewalls).Count
  }) | Out-Null
}

# ---------------- Write CSVs ----------------
$summaryCsv = Join-Path $OutputDir ("vnet_monthly_summary_{0}_{1}_{2}.csv" -f $custodianForFile, $adh_subscription_type, $stamp)
$subnetCsv  = Join-Path $OutputDir ("vnet_monthly_subnets_{0}_{1}_{2}.csv"  -f $custodianForFile, $adh_subscription_type, $stamp)
$peeringCsv = Join-Path $OutputDir ("vnet_monthly_peerings_{0}_{1}_{2}.csv" -f $custodianForFile, $adh_subscription_type, $stamp)

Write-CsvSafe -Rows @($summaryRows) -Path $summaryCsv
Write-CsvSafe -Rows @($subnetRows)  -Path $subnetCsv
Write-CsvSafe -Rows @($peeringRows) -Path $peeringCsv

# Optional: firewall inventory CSV (only useful if firewall exists in SAME subscription context)
$fwCsv = Join-Path $OutputDir ("vnet_monthly_firewalls_{0}_{1}_{2}.csv" -f $custodianForFile, $adh_subscription_type, $stamp)
Write-CsvSafe -Rows @($firewallRows) -Path $fwCsv

Write-Host "VNet Monthly scan completed."
Write-Host "Summary CSV : $summaryCsv"
Write-Host "Subnets CSV : $subnetCsv"
Write-Host "Peerings CSV: $peeringCsv"
Write-Host "Firewalls CSV: $fwCsv (will be empty if no firewalls in this subscription)"
exit 0
