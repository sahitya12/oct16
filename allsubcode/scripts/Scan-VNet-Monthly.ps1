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

Import-Module Az.Accounts, Az.Resources, Az.Network -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

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

Write-Host "DEBUG: TenantId      = $TenantId"
Write-Host "DEBUG: ClientId      = $ClientId"
Write-Host "DEBUG: adh_group     = $adh_group"
Write-Host "DEBUG: adh_sub_group = $adh_sub_group"
Write-Host "DEBUG: env           = $adh_subscription_type"
Write-Host "DEBUG: OutputDir     = $OutputDir"
Write-Host "DEBUG: BranchName    = $BranchName"

Ensure-Dir -Path $OutputDir | Out-Null

# ----------------------------------------------------------------------
# Connect & resolve subscriptions
# ----------------------------------------------------------------------
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
  throw "Azure connection failed."
}

$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
if ($subs -isnot [System.Collections.IEnumerable]) { $subs = ,$subs }

# Optional best-effort filter by sub-group (only if it helps)
if (-not [string]::IsNullOrWhiteSpace($adh_sub_group)) {
  $needle = [regex]::Escape($adh_sub_group.Trim())
  $filtered = @($subs | Where-Object { $_.Name -match $needle -or $_.Id -match $needle })
  if ($filtered.Count -gt 0) {
    Write-Host "DEBUG: Filtered subs by adh_sub_group='$adh_sub_group' => $($filtered.Count) matches"
    $subs = $filtered
  } else {
    Write-Host "WARN: No subscription matched adh_sub_group='$adh_sub_group'. Using all resolved subscriptions for adh_group." -ForegroundColor Yellow
  }
}

if (-not $subs -or @($subs).Count -eq 0) {
  throw "No subscriptions resolved for adh_group=$adh_group env=$adh_subscription_type"
}

# Shared stamp
$stamp = Get-Date -Format 'yyyyMMdd'

$custodianForFile = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) { $adh_group } else { "${adh_group}_${adh_sub_group}" }

# ======================================================================
# Collectors
# ======================================================================
$vnetPeeringRows = New-Object System.Collections.Generic.List[object]
$fwRows          = New-Object System.Collections.Generic.List[object]
$subnetRows      = New-Object System.Collections.Generic.List[object]

foreach ($sub in $subs) {
  Set-ScContext -Subscription $sub

  Write-Host ""
  Write-Host "=== VNet Monthly scan for subscription: $($sub.Name) ($($sub.Id)) ===" -ForegroundColor Cyan

  # ---------------- VNets ----------------
  $vnets = @(Get-AzVirtualNetwork -ErrorAction SilentlyContinue)
  Write-Host "DEBUG: Found $(@($vnets).Count) VNets"

  foreach ($vnet in $vnets) {

    # ---- Peerings (same style as Topology script) ----
    if (-not $vnet.VirtualNetworkPeerings -or $vnet.VirtualNetworkPeerings.Count -eq 0) {
      $vnetPeeringRows.Add([pscustomobject]@{
        SubscriptionName                        = $sub.Name
        SubscriptionId                          = $sub.Id
        ResourceGroup                           = $vnet.ResourceGroupName
        VirtualNetwork                          = $vnet.Name
        PeeringName                             = ''
        'Peering connection status'             = 'NoPeerings'
        'Peering state'                         = ''
        'Remote virtual network name'           = ''
        'Virtual network gateway or route server'= ''
      }) | Out-Null
    } else {

      $localHasGateway =
        ($vnet.Gateways -and $vnet.Gateways.Count -gt 0) -or
        ($vnet.VirtualNetworkPeerings | Where-Object { $_.RouteServerId })

      foreach ($peer in $vnet.VirtualNetworkPeerings) {

        $connStatus = $peer.PeeringSyncLevel
        $state      = $peer.PeeringState

        $remoteVnetName = ''
        $remoteVnetRg   = ''
        try {
          if ($peer.RemoteVirtualNetwork -and $peer.RemoteVirtualNetwork.Id) {
            $parts = $peer.RemoteVirtualNetwork.Id -split '/'
            $remoteVnetName = $parts[-1]
            $rgIndex = [Array]::IndexOf($parts, 'resourceGroups')
            if ($rgIndex -ge 0 -and $rgIndex + 1 -lt $parts.Count) {
              $remoteVnetRg = $parts[$rgIndex + 1]
            }
          }
        } catch {}

        $remoteHasGateway = $false
        try {
          $remoteHasGateway = ($peer.UseRemoteGateways -eq $true)
        } catch {}

        $gwOrRs = if ($localHasGateway -or $remoteHasGateway) { 'Gateway/RouteServer present' } else { '' }

        $vnetPeeringRows.Add([pscustomobject]@{
          SubscriptionName                        = $sub.Name
          SubscriptionId                          = $sub.Id
          ResourceGroup                           = $vnet.ResourceGroupName
          VirtualNetwork                          = $vnet.Name
          PeeringName                             = $peer.Name
          'Peering connection status'             = $connStatus
          'Peering state'                         = $state
          'Remote virtual network name'           = if ($remoteVnetRg) { "$remoteVnetRg/$remoteVnetName" } else { $remoteVnetName }
          'Virtual network gateway or route server'= $gwOrRs
        }) | Out-Null
      }
    }

    # ---- Subnets (detailed) ----
    $subnets = @()
    try { $subnets = @($vnet.Subnets) } catch { $subnets = @() }

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
        ResourceGroup                  = $vnet.ResourceGroupName
        VNetName                       = $vnet.Name
        Location                       = $vnet.Location
        SubnetName                     = $s.Name
        SubnetPrefix                   = SafeJoin $s.AddressPrefix
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
  }

  # ---------------- Azure Firewall public IPs (this is what you said is missing) ----------------
  $firewalls = @(Get-AzFirewall -ErrorAction SilentlyContinue)
  Write-Host "DEBUG: Found $(@($firewalls).Count) Azure Firewalls"

  foreach ($fw in $firewalls) {

    $fwRg   = $fw.ResourceGroupName
    $fwName = $fw.Name

    $ipConfigs = @()
    try { $ipConfigs = @($fw.IpConfigurations) } catch { $ipConfigs = @() }

    foreach ($ipconf in $ipConfigs) {

      $pipId = $null
      try { $pipId = $ipconf.PublicIpAddress.Id } catch {}

      $pipName = ''
      $pipIp   = ''
      $pipRg   = ''

      if ($pipId) {
        try {
          $pip = Get-AzPublicIpAddress -ResourceId $pipId -ErrorAction SilentlyContinue
          if ($pip) {
            $pipName = $pip.Name
            $pipIp   = $pip.IpAddress
            $pipRg   = $pip.ResourceGroupName
          }
        } catch {}
      }

      $fwRows.Add([pscustomobject]@{
        SubscriptionName    = $sub.Name
        SubscriptionId      = $sub.Id
        Environment         = $adh_subscription_type
        Custodian           = $adh_group
        CustodianSubGroup   = $adh_sub_group
        FirewallRG          = $fwRg
        FirewallName        = $fwName
        IpConfigName        = $ipconf.Name
        PublicIpResourceId  = $pipId
        PublicIpRG          = $pipRg
        PublicIpName        = $pipName
        PublicIpAddress     = $pipIp
      }) | Out-Null
    }

    # If firewall exists but has no ipconfigs, still log a row
    if ($ipConfigs.Count -eq 0) {
      $fwRows.Add([pscustomobject]@{
        SubscriptionName    = $sub.Name
        SubscriptionId      = $sub.Id
        Environment         = $adh_subscription_type
        Custodian           = $adh_group
        CustodianSubGroup   = $adh_sub_group
        FirewallRG          = $fwRg
        FirewallName        = $fwName
        IpConfigName        = ''
        PublicIpResourceId  = ''
        PublicIpRG          = ''
        PublicIpName        = ''
        PublicIpAddress     = ''
      }) | Out-Null
    }
  }
}

# If nothing found, still create files with headers
if ($vnetPeeringRows.Count -eq 0) { $vnetPeeringRows.Add([pscustomobject]@{ SubscriptionName=''; SubscriptionId=''; ResourceGroup=''; VirtualNetwork=''; PeeringName=''; 'Peering connection status'=''; 'Peering state'=''; 'Remote virtual network name'=''; 'Virtual network gateway or route server'='' }) | Out-Null }
if ($subnetRows.Count     -eq 0) { $subnetRows.Add([pscustomobject]@{ SubscriptionName=''; SubscriptionId=''; Environment=$adh_subscription_type; Custodian=$adh_group; CustodianSubGroup=$adh_sub_group; ResourceGroup=''; VNetName=''; Location=''; SubnetName=''; SubnetPrefix=''; NSGName=''; NSGId=''; RouteTableName=''; RouteTableId=''; Delegations=''; ServiceEndpoints=''; PrivateEndpointNetworkPolicies=''; PrivateLinkServicePolicies='' }) | Out-Null }
if ($fwRows.Count         -eq 0) { $fwRows.Add([pscustomobject]@{ SubscriptionName=''; SubscriptionId=''; Environment=$adh_subscription_type; Custodian=$adh_group; CustodianSubGroup=$adh_sub_group; FirewallRG=''; FirewallName=''; IpConfigName=''; PublicIpResourceId=''; PublicIpRG=''; PublicIpName=''; PublicIpAddress='' }) | Out-Null }

# ----------------------------------------------------------------------
# Write CSVs
# ----------------------------------------------------------------------
$peeringsCsv = Join-Path $OutputDir ("vnet_peerings_{0}_{1}_{2}.csv" -f $custodianForFile, $adh_subscription_type, $stamp)
$fwCsv       = Join-Path $OutputDir ("vnet_firewall_publicips_{0}_{1}_{2}.csv" -f $custodianForFile, $adh_subscription_type, $stamp)
$subnetsCsv  = Join-Path $OutputDir ("vnet_subnets_{0}_{1}_{2}.csv" -f $custodianForFile, $adh_subscription_type, $stamp)

Write-CsvSafe -Rows @($vnetPeeringRows) -Path $peeringsCsv
Write-CsvSafe -Rows @($fwRows)          -Path $fwCsv
Write-CsvSafe -Rows @($subnetRows)      -Path $subnetsCsv

Write-Host "VNet Monthly scan completed."
Write-Host "Peerings CSV : $peeringsCsv"
Write-Host "Firewall CSV : $fwCsv"
Write-Host "Subnets CSV  : $subnetsCsv"
exit 0
