param(
  [Parameter(Mandatory)][string]$TenantId,
  [Parameter(Mandatory)][string]$ClientId,
  [Parameter(Mandatory)][string]$ClientSecret,
  [Parameter(Mandatory)][string]$adh_group,
  [ValidateSet('nonprd','prd')][string]$adh_subscription_type = 'nonprd',
  [Parameter(Mandatory)][string]$OutputDir,
  [string]$BranchName = ''
)

Import-Module Az.Accounts, Az.Network, Az.Resources -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop
Ensure-Dir $OutputDir | Out-Null

Write-Host "==== Network Scan starting ====" -ForegroundColor Cyan
Write-Host "TenantId: $TenantId"
Write-Host "ClientId: $ClientId"
Write-Host "adh_group: $adh_group"
Write-Host "adh_subscription_type: $adh_subscription_type"
Write-Host "OutputDir: $OutputDir"
Write-Host "BranchName: $BranchName"

# -----------------------------------------------------------------------
# Connect
# -----------------------------------------------------------------------
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
  throw "Azure connection failed."
}

# -----------------------------------------------------------------------
# Resolve subscriptions
# -----------------------------------------------------------------------
switch ($adh_group.ToUpper()) {
  'KTK' {
    $subs = Get-AzSubscription | Where-Object { $_.Name -eq 'dev_azure_20401_ADHPlatform' }
  }
  'MDM' {
    $subs = if ($adh_subscription_type -eq 'prd') {
      Get-AzSubscription | Where-Object { $_.Name -eq 'prd_azure_20910_ADHMDM' }
    } else {
      Get-AzSubscription | Where-Object { $_.Name -eq 'dev_azure_20911_ADHMDM' }
    }
  }
  'NHH' {
    $subs = if ($adh_subscription_type -eq 'prd') {
      Get-AzSubscription | Where-Object { $_.Name -eq 'prd_azure_21000_ADHNHH' }
    } else {
      Get-AzSubscription | Where-Object { $_.Name -eq 'dev_azure_21001_ADHNHH' }
    }
  }
  Default {
    $envPrefix = if ($adh_subscription_type -eq 'prd') { 'prd_azure_' } else { 'dev_azure_' }
    $suffix    = "_ADH$($adh_group.ToUpper())"
    $subs      = Get-AzSubscription | Where-Object { $_.Name -like "${envPrefix}*${suffix}" }
  }
}

if (-not $subs -or $subs.Count -eq 0) {
  Write-Warning "No subscriptions found for adh_group '$adh_group' / type '$adh_subscription_type'."
}

Write-Host "Found $($subs.Count) subscription(s): $($subs.Name -join ', ')" -ForegroundColor Yellow

# -----------------------------------------------------------------------
# Prepare result containers
# -----------------------------------------------------------------------
$rows       = @()
$peerRows   = @()
$subnetRows = @()
$fwRows     = @()

# SPN objectId (for RBAC)
$sp          = Get-AzADServicePrincipal -ApplicationId $ClientId -ErrorAction Stop
$spObjectId  = $sp.Id
Write-Host "Pipeline SPN ObjectId: $spObjectId" -ForegroundColor Yellow

# -----------------------------------------------------------------------
# Main loop
# -----------------------------------------------------------------------
foreach ($sub in $subs) {

  Write-Host "----- Processing subscription: $($sub.Name) [$($sub.Id)] -----" -ForegroundColor Cyan
  Set-ScContext -Subscription $sub

  # Fetch all VNets first
  $vnetsAll = Get-AzVirtualNetwork -ErrorAction SilentlyContinue

  if (-not $vnetsAll -or $vnetsAll.Count -eq 0) {
    Write-Warning "No VNets found in subscription $($sub.Name)."
  } else {
    Write-Host "Total VNets in sub $($sub.Name): $($vnetsAll.Count)" -ForegroundColor Yellow
  }

  $rgNames = $vnetsAll | Select-Object -ExpandProperty ResourceGroupName -Unique

  # -------------------------------------------------------------------
  # Assign Network Contributor role to SPN on all RGs with VNets
  # -------------------------------------------------------------------
  foreach ($rg in $rgNames) {
    try {
      New-AzRoleAssignment -ObjectId $spObjectId `
                           -RoleDefinitionName "Network Contributor" `
                           -ResourceGroupName $rg `
                           -ErrorAction Stop
      Write-Host "Assigned Network Contributor on RG '$rg' to SPN." -ForegroundColor Green
    } catch {
      Write-Warning "Failed to assign Network Contributor on RG '$rg': $_"
    }
  }

  if ($rgNames.Count -gt 0) {
    Write-Host "Waiting 30s for RBAC propagation..." -ForegroundColor Yellow
    Start-Sleep -Seconds 30
  }

  # -------------------------------------------------------------------
  # Filter VNets by adh_group in name (removed hard 'core' requirement)
  # -------------------------------------------------------------------
  $adhPattern = [regex]::Escape($adh_group)

  if ([string]::IsNullOrWhiteSpace($adh_group)) {
    # If no adh_group specified, take all VNets
    $vnets = $vnetsAll
  } else {
    $vnets = $vnetsAll | Where-Object { $_.Name -match $adhPattern }
  }

  Write-Host "Filtered VNets for adh_group '$adh_group' in sub '$($sub.Name)': $($vnets.Count)" -ForegroundColor Yellow

  # Preload NSGs / RouteTables / NAT / Firewalls
  $nsgs  = Get-AzNetworkSecurityGroup -ErrorAction SilentlyContinue
  $rtabs = Get-AzRouteTable           -ErrorAction SilentlyContinue
  $ngws  = Get-AzNatGateway           -ErrorAction SilentlyContinue
  $azfws = Get-AzFirewall             -ErrorAction SilentlyContinue

  foreach ($v in $vnets) {
    # Topology row
    $rows += [PSCustomObject]@{
      SubscriptionName = $sub.Name
      VNetName         = $v.Name
      ResourceGroup    = $v.ResourceGroupName
      AddressSpace     = ($v.AddressSpace.AddressPrefixes -join ',')
      DnsServers       = ($v.DhcpOptions.DnsServers -join ',')
      Subnets          = (($v.Subnets | ForEach-Object { $_.Name + '(' + $_.AddressPrefix + ')' }) -join ';')
    }

    # Peering info
    $peerings = Get-AzVirtualNetworkPeering -ResourceGroupName $v.ResourceGroupName `
                                            -VirtualNetworkName $v.Name `
                                            -ErrorAction SilentlyContinue
    foreach ($p in $peerings) {
      $peerRows += [PSCustomObject]@{
        SubscriptionName = $sub.Name
        VNetName         = $v.Name
        PeeringName      = $p.Name
        RemoteVNetId     = $p.RemoteVirtualNetwork.Id
        AllowForwarded   = $p.AllowForwardedTraffic
        AllowGateway     = $p.AllowGatewayTransit
        AllowVnetAccess  = $p.AllowVirtualNetworkAccess
      }
    }

    # Subnets + NSG/RT/NAT
    foreach ($s in $v.Subnets) {
      $nsg = if ($s.NetworkSecurityGroup) { $nsgs  | Where-Object { $_.Id -eq $s.NetworkSecurityGroup.Id } }
      $rt  = if ($s.RouteTable)           { $rtabs | Where-Object { $_.Id -eq $s.RouteTable.Id } }
      $ngw = if ($s.NatGateway)           { $ngws  | Where-Object { $_.Id -eq $s.NatGateway.Id } }

      $subnetRows += [PSCustomObject]@{
        SubscriptionName = $sub.Name
        VNetName         = $v.Name
        ResourceGroup    = $v.ResourceGroupName
        Subnet           = $s.Name
        AddressPrefix    = $s.AddressPrefix
        NSG              = $nsg?.Name
        NatGateway       = $ngw?.Name
        RouteTable       = $rt?.Name
      }
    }
  }

  # Firewalls (per sub)
  foreach ($fw in $azfws) {
    $fwRows += [PSCustomObject]@{
      SubscriptionName = $sub.Name
      FirewallName     = $fw.Name
      ResourceGroup    = $fw.ResourceGroupName
      Location         = $fw.Location
      IpConfigurations = ($fw.IpConfigurations | ForEach-Object { $_.Name + '(' + $_.PrivateIpAddress + ')' }) -join ','
      VNetAssociation  = $fw.VirtualNetwork.Id
    }
  }

  # -------------------------------------------------------------------
  # Revoke temporary Network Contributor role
  # -------------------------------------------------------------------
  foreach ($rg in $rgNames) {
    try {
      Remove-AzRoleAssignment -ObjectId $spObjectId `
                              -RoleDefinitionName "Network Contributor" `
                              -ResourceGroupName $rg `
                              -ErrorAction Stop
      Write-Host "Revoked Network Contributor for RG '$rg'." -ForegroundColor DarkGreen
    } catch {
      Write-Warning "Role removal failed for RG '$rg': $_"
    }
  }
}

# -----------------------------------------------------------------------
# Export helpers
# -----------------------------------------------------------------------
function SafeWrite ($data, $path) {
  if (-not $data -or $data.Count -eq 0) {
    Write-Host "WARN: No data for $path – writing placeholder text." -ForegroundColor DarkYellow
    "No data found." | Out-File -FilePath $path -Encoding UTF8
  } else {
    Write-Host "INFO: Writing $($data.Count) rows to $path" -ForegroundColor Green
    Write-CsvSafe -Rows $data -Path $path
  }
}

# -----------------------------------------------------------------------
# Export CSV + HTML
# -----------------------------------------------------------------------
$out1 = New-StampedPath -BaseDir $OutputDir -Prefix ("vnet_topology_{0}_{1}" -f $adh_group, $adh_subscription_type)
SafeWrite $rows $out1
Convert-CsvToHtml -CsvPath $out1 -HtmlPath ($out1 -replace '\.csv$', '.html') -Title "VNet Topology ($adh_group / $adh_subscription_type) $BranchName"

$out2 = New-StampedPath -BaseDir $OutputDir -Prefix ("vnet_peerings_{0}_{1}" -f $adh_group, $adh_subscription_type)
SafeWrite $peerRows $out2

$out3 = New-StampedPath -BaseDir $OutputDir -Prefix ("subnet_details_{0}_{1}" -f $adh_group, $adh_subscription_type)
SafeWrite $subnetRows $out3

$out4 = New-StampedPath -BaseDir $OutputDir -Prefix ("firewalls_{0}_{1}" -f $adh_group, $adh_subscription_type)
SafeWrite $fwRows $out4

Write-Host "==== Network Scan finished ====" -ForegroundColor Cyan
