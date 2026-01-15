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

# ---------------- Login ----------------
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
  throw "Azure login failed."
}

# Resolve subscriptions for this custodian/env (can be single or multiple)
$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
if ($null -eq $subs) { throw "Resolve-ScSubscriptions returned null." }
$subs = @($subs)
if ($subs.Count -eq 0) { throw "No subscriptions resolved for adh_group=$adh_group env=$adh_subscription_type" }

$custodianForFile = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) { $adh_group } else { "${adh_group}_${adh_sub_group}" }
$stamp = Get-Date -Format 'yyyyMMdd'

# Output rows
$summaryRows  = New-Object System.Collections.Generic.List[object]
$subnetRows   = New-Object System.Collections.Generic.List[object]
$peeringRows  = New-Object System.Collections.Generic.List[object]
$firewallRows = New-Object System.Collections.Generic.List[object]

foreach ($sub in $subs) {

  Write-Host ""
  Write-Host ("=" * 60) -ForegroundColor DarkCyan
  Write-Host ("VNet Monthly: {0} ({1})" -f $sub.Name, $sub.Id) -ForegroundColor Cyan
  Write-Host ("Custodian={0} Env={1} Branch={2}" -f $adh_group, $adh_subscription_type, $BranchName)
  Write-Host ("=" * 60) -ForegroundColor DarkCyan

  Set-ScContext -Subscription $sub

  # ---------------- Collect VNets ----------------
  $vnets = @(Get-AzVirtualNetwork -ErrorAction SilentlyContinue)

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

      # Derive names from IDs
      $nsgName = ''
      if ($nsgId -match '/networkSecurityGroups/([^/]+)$') { $nsgName = $Matches[1] }
      $rtName  = ''
      if ($rtId  -match '/routeTables/([^/]+)$') { $rtName = $Matches[1] }

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

  # ---------------- Azure Firewall + Public IP scan ----------------
  try {
    $firewalls = @(Get-AzFirewall -ErrorAction SilentlyContinue)
  } catch { $firewalls = @() }

  foreach ($fw in $firewalls) {
    $pipIds = @()

    # Try multiple shapes; depends on Az module versions
    try {
      if ($fw.IpConfigurations) {
        foreach ($ipc in @($fw.IpConfigurations)) {
          try { if ($ipc.PublicIpAddress -and $ipc.PublicIpAddress.Id) { $pipIds += $ipc.PublicIpAddress.Id } } catch {}
          try { if ($ipc.PublicIPAddress -and $ipc.PublicIPAddress.Id) { $pipIds += $ipc.PublicIPAddress.Id } } catch {}
        }
      }
    } catch {}

    $pipIds = @($pipIds | Where-Object { $_ -and "$_".Trim() -ne '' } | Select-Object -Unique)

    if ($pipIds.Count -eq 0) {
      # still output a row for the firewall
      $firewallRows.Add([pscustomobject]@{
        SubscriptionName = $sub.Name
        SubscriptionId   = $sub.Id
        Environment      = $adh_subscription_type
        Custodian        = $adh_group
        CustodianSubGroup= $adh_sub_group
        ResourceGroup    = $fw.ResourceGroupName
        FirewallName     = $fw.Name
        PublicIpName     = ''
        PublicIpAddress  = ''
        PublicIpSku      = ''
        PublicIpType     = ''
      }) | Out-Null
      continue
    }

    foreach ($pipId in $pipIds) {
      $pipName = ''
      $pipAddress = ''
      $pipSku = ''
      $pipType = ''

      try { if ($pipId -match '/publicIPAddresses/([^/]+)$') { $pipName = $Matches[1] } } catch {}

      try {
        $pip = Get-AzPublicIpAddress -ResourceId $pipId -ErrorAction SilentlyContinue
        if ($pip) {
          $pipAddress = "$($pip.IpAddress)"
          $pipSku     = "$($pip.Sku.Name)"
          $pipType    = "$($pip.PublicIpAllocationMethod)"
          if (-not $pipName) { $pipName = $pip.Name }
        }
      } catch {}

      $firewallRows.Add([pscustomobject]@{
        SubscriptionName = $sub.Name
        SubscriptionId   = $sub.Id
        Environment      = $adh_subscription_type
        Custodian        = $adh_group
        CustodianSubGroup= $adh_sub_group
        ResourceGroup    = $fw.ResourceGroupName
        FirewallName     = $fw.Name
        PublicIpName     = $pipName
        PublicIpAddress  = $pipAddress
        PublicIpSku      = $pipSku
        PublicIpType     = $pipType
      }) | Out-Null
    }
  }
}

# If NO VNets at all -> still emit a header row for summary
if ($summaryRows.Count -eq 0) {
  $summaryRows.Add([pscustomobject]@{
    SubscriptionName=''; SubscriptionId=''; Environment=$adh_subscription_type; Custodian=$adh_group; CustodianSubGroup=$adh_sub_group;
    ResourceGroup=''; VNetName=''; Location=''; AddressSpaces=''; DnsServers=''; SubnetCount=0; PeeringCount=0
  }) | Out-Null
}

# ---------------- Write CSVs ----------------
$summaryCsv  = Join-Path $OutputDir ("vnet_monthly_summary_{0}_{1}_{2}.csv"   -f $custodianForFile, $adh_subscription_type, $stamp)
$subnetCsv   = Join-Path $OutputDir ("vnet_monthly_subnets_{0}_{1}_{2}.csv"   -f $custodianForFile, $adh_subscription_type, $stamp)
$peeringCsv  = Join-Path $OutputDir ("vnet_monthly_peerings_{0}_{1}_{2}.csv"  -f $custodianForFile, $adh_subscription_type, $stamp)
$fwCsv       = Join-Path $OutputDir ("vnet_monthly_firewalls_{0}_{1}_{2}.csv" -f $custodianForFile, $adh_subscription_type, $stamp)

Write-CsvSafe -Rows @($summaryRows)  -Path $summaryCsv
Write-CsvSafe -Rows @($subnetRows)   -Path $subnetCsv
Write-CsvSafe -Rows @($peeringRows)  -Path $peeringCsv
Write-CsvSafe -Rows @($firewallRows) -Path $fwCsv

Write-Host "VNet Monthly scan completed."
Write-Host "Summary CSV  : $summaryCsv"
Write-Host "Subnets CSV  : $subnetCsv"
Write-Host "Peerings CSV : $peeringCsv"
Write-Host "Firewall CSV : $fwCsv"
exit 0
