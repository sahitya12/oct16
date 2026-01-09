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

Import-Module Az.Accounts, Az.Network, Az.Resources -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

Ensure-Dir -Path $OutputDir | Out-Null

function New-Finding {
  param(
    [Parameter(Mandatory)][string]$Status,   # OK / WARN / MISSING / ERROR
    [Parameter(Mandatory)][string]$Finding
  )
  return [pscustomobject]@{ Status = $Status; Finding = $Finding }
}

function Safe-Join([object]$v) {
  if ($null -eq $v) { return '' }
  if ($v -is [System.Collections.IEnumerable] -and -not ($v -is [string])) {
    return (@($v) | ForEach-Object { "$_" } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join ';'
  }
  return "$v"
}

function Try-Get([scriptblock]$sb, $default = $null) {
  try { return & $sb } catch { return $default }
}

# ---------------- Login + subscription context ----------------
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
  throw "Azure login failed."
}

$sub = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
Set-ScContext -Subscription $sub

$custToken = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) { $adh_group } else { "${adh_group}_${adh_sub_group}" }
$stamp = Get-Date -Format 'yyyyMMdd'

Write-Host "VNet Monthly scan started"
Write-Host "Subscription: $($sub.Name) ($($sub.Id))"
Write-Host "Custodian   : $custToken"
Write-Host "Env         : $adh_subscription_type"
Write-Host "OutputDir   : $OutputDir"
Write-Host "Branch      : $BranchName"
Write-Host ""

# ---------------- Collect resources ----------------
$vnets = @()
try { $vnets = @(Get-AzVirtualNetwork -ErrorAction Stop) } catch { $vnets = @() }

$nsgs  = @()
$rts   = @()
$fw    = @()
$pips  = @()

try { $nsgs = @(Get-AzNetworkSecurityGroup -ErrorAction SilentlyContinue) } catch {}
try { $rts  = @(Get-AzRouteTable -ErrorAction SilentlyContinue) } catch {}
try { $fw   = @(Get-AzFirewall -ErrorAction SilentlyContinue) } catch {}
try { $pips = @(Get-AzPublicIpAddress -ErrorAction SilentlyContinue) } catch {}

# Quick lookup maps
$nsgById = @{}
foreach ($n in $nsgs) { if ($n.Id) { $nsgById[$n.Id.ToLower()] = $n } }

$rtById = @{}
foreach ($r in $rts) { if ($r.Id) { $rtById[$r.Id.ToLower()] = $r } }

$pipById = @{}
foreach ($p in $pips) { if ($p.Id) { $pipById[$p.Id.ToLower()] = $p } }

# ---------------- Output rows ----------------
$vnetSummary = New-Object System.Collections.Generic.List[object]
$subnetRows  = New-Object System.Collections.Generic.List[object]
$peerRows    = New-Object System.Collections.Generic.List[object]
$nsgRows     = New-Object System.Collections.Generic.List[object]
$rtRows      = New-Object System.Collections.Generic.List[object]
$fwPipRows   = New-Object System.Collections.Generic.List[object]

# ---------------- VNet summary + subnets + peerings ----------------
foreach ($v in $vnets) {

  $addr = Safe-Join (Try-Get { $v.AddressSpace.AddressPrefixes } @())
  $dns  = Safe-Join (Try-Get { $v.DhcpOptions.DnsServers } @())

  $peers = @()
  try { $peers = @(Get-AzVirtualNetworkPeering -ResourceGroupName $v.ResourceGroupName -VirtualNetworkName $v.Name -ErrorAction SilentlyContinue) } catch {}

  $subnets = @()
  try { $subnets = @($v.Subnets) } catch { $subnets = @() }

  # ---- simple validations (summary-level)
  $findings = @()
  if ([string]::IsNullOrWhiteSpace($addr)) { $findings += (New-Finding -Status "WARN" -Finding "No address space detected") }
  if ($subnets.Count -eq 0) { $findings += (New-Finding -Status "WARN" -Finding "No subnets found") }
  if ($peers.Count -eq 0) { $findings += (New-Finding -Status "WARN" -Finding "No peerings found") }

  $overallStatus = if ($findings.Status -contains "ERROR") { "ERROR" }
                  elseif ($findings.Status -contains "MISSING") { "MISSING" }
                  elseif ($findings.Status -contains "WARN") { "WARN" }
                  else { "OK" }

  $vnetSummary.Add([pscustomobject]@{
    SubscriptionName = $sub.Name
    SubscriptionId   = $sub.Id
    Environment      = $adh_subscription_type
    Custodian        = $custToken
    ResourceGroup    = $v.ResourceGroupName
    VNetName         = $v.Name
    Location         = $v.Location
    AddressSpaces    = $addr
    DnsServers       = $dns
    SubnetCount      = $subnets.Count
    PeeringCount     = $peers.Count
    Status           = $overallStatus
    Finding          = (Safe-Join ($findings | ForEach-Object { "$($_.Status):$($_.Finding)" }))
  })

  # ---- subnet level
  foreach ($s in $subnets) {
    $subPrefix = Safe-Join (Try-Get { $s.AddressPrefix } (Try-Get { $s.AddressPrefixes } @()))
    $nsgId     = Try-Get { $s.NetworkSecurityGroup.Id } ''
    $rtId      = Try-Get { $s.RouteTable.Id } ''
    $deleg     = Safe-Join (Try-Get { $s.Delegations.Name } @())
    $svcEp     = Safe-Join (Try-Get { $s.ServiceEndpoints.Service } @())

    $subFind = @()
    if ([string]::IsNullOrWhiteSpace($nsgId)) { $subFind += (New-Finding -Status "MISSING" -Finding "NSG not associated") }
    if ([string]::IsNullOrWhiteSpace($rtId))  { $subFind += (New-Finding -Status "MISSING" -Finding "RouteTable not associated") }

    $subStatus = if ($subFind.Status -contains "ERROR") { "ERROR" }
                elseif ($subFind.Status -contains "MISSING") { "MISSING" }
                elseif ($subFind.Status -contains "WARN") { "WARN" }
                else { "OK" }

    $subnetRows.Add([pscustomobject]@{
      SubscriptionName = $sub.Name
      SubscriptionId   = $sub.Id
      Environment      = $adh_subscription_type
      Custodian        = $custToken
      ResourceGroup    = $v.ResourceGroupName
      VNetName         = $v.Name
      SubnetName       = $s.Name
      AddressPrefix    = $subPrefix
      NsgId            = $nsgId
      RouteTableId     = $rtId
      Delegations      = $deleg
      ServiceEndpoints = $svcEp
      PrivateEndpointNetworkPolicies = (Try-Get { $s.PrivateEndpointNetworkPolicies } '')
      PrivateLinkServiceNetworkPolicies = (Try-Get { $s.PrivateLinkServiceNetworkPolicies } '')
      Status           = $subStatus
      Finding          = (Safe-Join ($subFind | ForEach-Object { "$($_.Status):$($_.Finding)" }))
    })
  }

  # ---- peering level
  foreach ($p in $peers) {
    $state = Try-Get { $p.PeeringState } ''
    $pFind = @()
    if ($state -and $state -ne "Connected") { $pFind += (New-Finding -Status "WARN" -Finding "PeeringState=$state") }

    $pStatus = if ($pFind.Status -contains "ERROR") { "ERROR" }
              elseif ($pFind.Status -contains "MISSING") { "MISSING" }
              elseif ($pFind.Status -contains "WARN") { "WARN" }
              else { "OK" }

    $peerRows.Add([pscustomobject]@{
      SubscriptionName = $sub.Name
      SubscriptionId   = $sub.Id
      Environment      = $adh_subscription_type
      Custodian        = $custToken
      ResourceGroup    = $v.ResourceGroupName
      VNetName         = $v.Name
      PeeringName      = $p.Name
      RemoteVNetId     = (Try-Get { $p.RemoteVirtualNetwork.Id } '')
      PeeringState     = $state
      AllowForwardedTraffic = (Try-Get { $p.AllowForwardedTraffic } '')
      AllowGatewayTransit   = (Try-Get { $p.AllowGatewayTransit } '')
      UseRemoteGateways     = (Try-Get { $p.UseRemoteGateways } '')
      Status           = $pStatus
      Finding          = (Safe-Join ($pFind | ForEach-Object { "$($_.Status):$($_.Finding)" }))
    })
  }
}

# ---------------- NSG summary ----------------
foreach ($n in $nsgs) {
  $rulesIn  = (Try-Get { @($n.SecurityRules | Where-Object { $_.Direction -eq "Inbound" }).Count } 0)
  $rulesOut = (Try-Get { @($n.SecurityRules | Where-Object { $_.Direction -eq "Outbound" }).Count } 0)

  $nsgRows.Add([pscustomobject]@{
    SubscriptionName = $sub.Name
    SubscriptionId   = $sub.Id
    Environment      = $adh_subscription_type
    Custodian        = $custToken
    ResourceGroup    = $n.ResourceGroupName
    NsgName          = $n.Name
    Location         = $n.Location
    InboundRuleCount = $rulesIn
    OutboundRuleCount= $rulesOut
    Status           = "OK"
    Finding          = ""
  })
}

# ---------------- Route table summary ----------------
foreach ($rt in $rts) {
  $routeCount = (Try-Get { @($rt.Routes).Count } 0)
  $rtRows.Add([pscustomobject]@{
    SubscriptionName = $sub.Name
    SubscriptionId   = $sub.Id
    Environment      = $adh_subscription_type
    Custodian        = $custToken
    ResourceGroup    = $rt.ResourceGroupName
    RouteTableName   = $rt.Name
    Location         = $rt.Location
    RouteCount       = $routeCount
    Routes           = (Safe-Join (Try-Get { $rt.Routes | ForEach-Object { "$($_.Name):$($_.AddressPrefix)->$($_.NextHopType)" } } @()))
    Status           = "OK"
    Finding          = ""
  })
}

# ---------------- Firewall -> Public IP resolution (from your Topology script idea) ----------------
foreach ($f in $fw) {
  $fwName = $f.Name
  $rgName = $f.ResourceGroupName

  foreach ($cfg in @($f.IpConfigurations)) {
    $pipId = Try-Get { $cfg.PublicIpAddress.Id } ''
    $pipAddr = ''
    $pipName = ''
    $pipRg   = ''

    if (-not [string]::IsNullOrWhiteSpace($pipId)) {
      $pipObj = $null
      $key = $pipId.ToLower()

      if ($pipById.ContainsKey($key)) {
        $pipObj = $pipById[$key]
      } else {
        $pipObj = Try-Get { Get-AzPublicIpAddress -ResourceId $pipId -ErrorAction SilentlyContinue } $null
      }

      if ($pipObj) {
        $pipAddr = Try-Get { $pipObj.IpAddress } ''
        $pipName = Try-Get { $pipObj.Name } ''
        $pipRg   = Try-Get { $pipObj.ResourceGroupName } ''
      }
    }

    $st = "OK"
    $fd = ""
    if ([string]::IsNullOrWhiteSpace($pipId)) { $st = "MISSING"; $fd = "Firewall IPConfiguration has no PublicIpAddress.Id" }
    elseif ([string]::IsNullOrWhiteSpace($pipAddr)) { $st = "WARN"; $fd = "Public IP resource resolved but IpAddress is empty (maybe not allocated yet)" }

    $fwPipRows.Add([pscustomobject]@{
      SubscriptionName  = $sub.Name
      SubscriptionId    = $sub.Id
      Environment       = $adh_subscription_type
      Custodian         = $custToken
      FirewallName      = $fwName
      FirewallRG        = $rgName
      IpConfigName      = (Try-Get { $cfg.Name } '')
      PublicIpResourceId= $pipId
      PublicIpName      = $pipName
      PublicIpRG        = $pipRg
      PublicIpAddress   = $pipAddr
      Status            = $st
      Finding           = $fd
    })
  }
}

# ---------------- Write CSVs ----------------
function Out-CsvSafe([string]$name, [object[]]$rows) {
  if (-not $rows -or $rows.Count -eq 0) {
    $rows = @([pscustomobject]@{ Info = "No data" })
  }
  $path = Join-Path $OutputDir $name
  Write-CsvSafe -Rows $rows -Path $path
  Write-Host "CSV : $path"
}

Out-CsvSafe -name ("vnet_summary_{0}_{1}_{2}.csv" -f $custToken, $adh_subscription_type, $stamp) -rows @($vnetSummary)
Out-CsvSafe -name ("vnet_subnets_{0}_{1}_{2}.csv" -f $custToken, $adh_subscription_type, $stamp) -rows @($subnetRows)
Out-CsvSafe -name ("vnet_peerings_{0}_{1}_{2}.csv" -f $custToken, $adh_subscription_type, $stamp) -rows @($peerRows)
Out-CsvSafe -name ("vnet_nsgs_{0}_{1}_{2}.csv" -f $custToken, $adh_subscription_type, $stamp) -rows @($nsgRows)
Out-CsvSafe -name ("vnet_route_tables_{0}_{1}_{2}.csv" -f $custToken, $adh_subscription_type, $stamp) -rows @($rtRows)
Out-CsvSafe -name ("vnet_firewall_publicips_{0}_{1}_{2}.csv" -f $custToken, $adh_subscription_type, $stamp) -rows @($fwPipRows)

Write-Host ""
Write-Host "VNet Monthly scan completed." -ForegroundColor Green
exit 0
