param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$ClientId,
    [Parameter(Mandatory)][string]$ClientSecret,
    [Parameter(Mandatory)][string]$adh_group,
    [ValidateSet('nonprd','prd')][string]$adh_subscription_type = 'nonprd',
    [Parameter(Mandatory)][string]$OutputDir,
    [string]$BranchName = ''
)

Import-Module Az.Accounts, Az.Resources, Az.Network -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

Write-Host "DEBUG: TenantId      = $TenantId"
Write-Host "DEBUG: ClientId      = $ClientId"
Write-Host "DEBUG: adh_group     = $adh_group"
Write-Host "DEBUG: subscription  = $adh_subscription_type"
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

# ======================================================================
# 1) VNet peering scan (unchanged)
# ======================================================================
$vnetRows = @()

foreach ($sub in $subs) {
    Set-ScContext -Subscription $sub

    Write-Host ""
    Write-Host "=== VNet scan for subscription: $($sub.Name) ===" -ForegroundColor Cyan

    $vnets = Get-AzVirtualNetwork -ErrorAction SilentlyContinue
    Write-Host "DEBUG: Found $(@($vnets).Count) VNets in $($sub.Name)"

    if (-not $vnets) { continue }

    foreach ($vnet in $vnets) {

        if (-not $vnet.VirtualNetworkPeerings -or $vnet.VirtualNetworkPeerings.Count -eq 0) {
            $vnetRows += [pscustomobject]@{
                SubscriptionName                          = $sub.Name
                SubscriptionId                            = $sub.Id
                ResourceGroup                             = $vnet.ResourceGroupName
                VirtualNetwork                            = $vnet.Name
                PeeringName                               = ''
                'Peering connection status'               = 'NoPeerings'
                'Peering state'                           = ''
                'Remote virtual network name'             = ''
                'Virtual network gateway or route server' = ''
                AllowVirtualNetworkAccess                 = $null
                AllowForwardedTraffic                     = $null
                AllowGatewayTransit                       = $null
                UseRemoteGateways                         = $null
            }
            continue
        }

        foreach ($peer in $vnet.VirtualNetworkPeerings) {

            $connStatus = $peer.PeeringSyncLevel
            $state      = $peer.PeeringState

            $remoteVnetName = ''
            if ($peer.RemoteVirtualNetwork -and $peer.RemoteVirtualNetwork.Id) {
                $remoteVnetName = ($peer.RemoteVirtualNetwork.Id -split '/')[ -1 ]
            }

            $vnetGwOrRs =
                if ($peer.AllowGatewayTransit -or $peer.UseRemoteGateways) { 'Enabled' }
                else { 'Disabled' }

            $vnetRows += [pscustomobject]@{
                SubscriptionName                          = $sub.Name
                SubscriptionId                            = $sub.Id
                ResourceGroup                             = $vnet.ResourceGroupName
                VirtualNetwork                            = $vnet.Name
                PeeringName                               = $peer.Name
                'Peering connection status'               = $connStatus
                'Peering state'                           = $state
                'Remote virtual network name'             = $remoteVnetName
                'Virtual network gateway or route server' = $vnetGwOrRs
                AllowVirtualNetworkAccess                 = $peer.AllowVirtualNetworkAccess
                AllowForwardedTraffic                     = $peer.AllowForwardedTraffic
                AllowGatewayTransit                       = $peer.AllowGatewayTransit
                UseRemoteGateways                         = $peer.UseRemoteGateways
            }
        }
    }
}

if (-not $vnetRows -or $vnetRows.Count -eq 0) {
    $vnetRows = @(
        [pscustomobject]@{
            SubscriptionName                          = ''
            SubscriptionId                            = ''
            ResourceGroup                             = ''
            VirtualNetwork                            = ''
            PeeringName                               = ''
            'Peering connection status'               = ''
            'Peering state'                           = ''
            'Remote virtual network name'             = ''
            'Virtual network gateway or route server' = ''
            AllowVirtualNetworkAccess                 = $null
            AllowForwardedTraffic                     = $null
            AllowGatewayTransit                       = $null
            UseRemoteGateways                         = $null
        }
    )
}

$vnetCsv  = New-StampedPath -BaseDir $OutputDir -Prefix ("vnet_peerings_{0}_{1}" -f $adh_group, $adh_subscription_type)
Write-CsvSafe -Rows $vnetRows -Path $vnetCsv
Convert-CsvToHtml -CsvPath $vnetCsv -HtmlPath ($vnetCsv -replace '\.csv$','.html') -Title "VNet Peerings ($adh_group / $adh_subscription_type) $BranchName"

Write-Host "VNet peering scan completed."
Write-Host "  CSV : $vnetCsv"

# ======================================================================
# 2) Azure Firewall + Public IP scan  (reworked)
# ======================================================================
$fwRows = @()

foreach ($sub in $subs) {
    Set-ScContext -Subscription $sub

    Write-Host ""
    Write-Host "=== Firewall scan for subscription: $($sub.Name) ===" -ForegroundColor Cyan

    # First: discover firewall *resources* (this almost always works)
    $fwResources = Get-AzResource -ResourceType "Microsoft.Network/azureFirewalls" -ErrorAction SilentlyContinue
    Write-Host "DEBUG: Get-AzResource found $(@($fwResources).Count) firewall resources in $($sub.Name)"

    if (-not $fwResources) {
        Write-Host "DEBUG: No firewall resources in $($sub.Name)"
        continue
    }

    foreach ($fwRes in $fwResources) {

        Write-Host "DEBUG: Processing firewall resource: $($fwRes.Name) / RG: $($fwRes.ResourceGroupName)"

        $pipName    = ''
        $pipRg      = ''
        $pipAddress = ''
        $pipSku     = ''
        $pipType    = ''

        # Try to get full Firewall object (for IP configs)
        $fwObj = $null
        try {
            $fwObj = Get-AzFirewall -Name $fwRes.Name -ResourceGroupName $fwRes.ResourceGroupName -ErrorAction Stop
        } catch {
            Write-Host "WARN: Get-AzFirewall failed for $($fwRes.Name) in $($fwRes.ResourceGroupName): $($_.Exception.Message)" -ForegroundColor Yellow
        }

        if ($fwObj -and $fwObj.IpConfigurations) {
            foreach ($ipConf in $fwObj.IpConfigurations) {
                $pipName    = ''
                $pipRg      = ''
                $pipAddress = ''
                $pipSku     = ''
                $pipType    = ''

                if ($ipConf.PublicIpAddress -and $ipConf.PublicIpAddress.Id) {
                    $idParts = $ipConf.PublicIpAddress.Id -split '/'
                    $pipName = $idParts[-1]
                    $rgIndex = [Array]::IndexOf($idParts, 'resourceGroups')
                    if ($rgIndex -ge 0 -and $rgIndex + 1 -lt $idParts.Count) {
                        $pipRg = $idParts[$rgIndex + 1]
                    }

                    try {
                        $pip = Get-AzPublicIpAddress -Name $pipName -ResourceGroupName $pipRg -ErrorAction Stop
                        $pipAddress = $pip.IpAddress
                        $pipSku     = $pip.Sku.Name
                        $pipType    = $pip.PublicIpAllocationMethod
                    } catch {
                        Write-Host "WARN: Failed to resolve Public IP $pipName in RG $pipRg : $($_.Exception.Message)" -ForegroundColor Yellow
                    }
                }

                $fwRows += [pscustomobject]@{
                    SubscriptionName = $sub.Name
                    SubscriptionId   = $sub.Id
                    ResourceGroup    = $fwRes.ResourceGroupName
                    FirewallName     = $fwRes.Name
                    PublicIpName     = $pipName
                    PublicIpAddress  = $pipAddress
                    PublicIpSku      = $pipSku
                    PublicIpType     = $pipType
                }
            }
        }
        else {
            # We still output a row even if we couldn't get IP config details
            $fwRows += [pscustomobject]@{
                SubscriptionName = $sub.Name
                SubscriptionId   = $sub.Id
                ResourceGroup    = $fwRes.ResourceGroupName
                FirewallName     = $fwRes.Name
                PublicIpName     = ''
                PublicIpAddress  = ''
                PublicIpSku      = ''
                PublicIpType     = ''
            }
        }
    }
}

if (-not $fwRows -or $fwRows.Count -eq 0) {
    $fwRows = @(
        [pscustomobject]@{
            SubscriptionName = ''
            SubscriptionId   = ''
            ResourceGroup    = ''
            FirewallName     = ''
            PublicIpName     = ''
            PublicIpAddress  = ''
            PublicIpSku      = ''
            PublicIpType     = ''
        }
    )
}

$fwCsv = New-StampedPath -BaseDir $OutputDir -Prefix ("firewall_publicips_{0}_{1}" -f $adh_group, $adh_subscription_type)
Write-CsvSafe -Rows $fwRows -Path $fwCsv
Convert-CsvToHtml -CsvPath $fwCsv -HtmlPath ($fwCsv -replace '\.csv$','.html') -Title "Firewall Public IPs ($adh_group / $adh_subscription_type) $BranchName"

Write-Host "Firewall public IP scan completed."
Write-Host "  CSV : $fwCsv"

# ======================================================================
# 3) Subnets + NSG + Route Table scan (unchanged)
# ======================================================================
$subnetRows = @()

foreach ($sub in $subs) {
    Set-ScContext -Subscription $sub

    Write-Host ""
    Write-Host "=== Subnet scan for subscription: $($sub.Name) ===" -ForegroundColor Cyan

    $vnets = Get-AzVirtualNetwork -ErrorAction SilentlyContinue
    Write-Host "DEBUG: Found $(@($vnets).Count) VNets (for subnet scan) in $($sub.Name)"

    if (-not $vnets) { continue }

    foreach ($vnet in $vnets) {

        foreach ($subnet in $vnet.Subnets) {

            $nsgName = ""
            if ($subnet.NetworkSecurityGroup -and $subnet.NetworkSecurityGroup.Id) {
                $nsgName = ($subnet.NetworkSecurityGroup.Id -split '/')[ -1 ]
            }

            $rtName = ""
            if ($subnet.RouteTable -and $subnet.RouteTable.Id) {
                $rtName = ($subnet.RouteTable.Id -split '/')[ -1 ]
            }

            $subnetRows += [pscustomobject]@{
                SubscriptionName                  = $sub.Name
                SubscriptionId                    = $sub.Id
                ResourceGroup                     = $vnet.ResourceGroupName
                VirtualNetwork                    = $vnet.Name
                SubnetName                        = $subnet.Name
                AddressPrefix                     = ($subnet.AddressPrefix -join ', ')
                NetworkSecurityGroup              = $nsgName
                RouteTable                        = $rtName
                PrivateEndpointNetworkPolicies    = $subnet.PrivateEndpointNetworkPolicies
                PrivateLinkServiceNetworkPolicies = $subnet.PrivateLinkServiceNetworkPolicies
            }
        }
    }
}

if (-not $subnetRows -or $subnetRows.Count -eq 0) {
    $subnetRows = @(
        [pscustomobject]@{
            SubscriptionName                  = ''
            SubscriptionId                    = ''
            ResourceGroup                     = ''
            VirtualNetwork                    = ''
            SubnetName                        = ''
            AddressPrefix                     = ''
            NetworkSecurityGroup              = ''
            RouteTable                        = ''
            PrivateEndpointNetworkPolicies    = ''
            PrivateLinkServiceNetworkPolicies = ''
        }
    )
}

$subnetCsv = New-StampedPath -BaseDir $OutputDir -Prefix ("vnet_subnets_{0}_{1}" -f $adh_group, $adh_subscription_type)
Write-CsvSafe -Rows $subnetRows -Path $subnetCsv
Convert-CsvToHtml -CsvPath $subnetCsv -HtmlPath ($subnetCsv -replace '\.csv$','.html') -Title "VNet Subnets ($adh_group / $adh_subscription_type) $BranchName"

Write-Host "Subnet scan completed."
Write-Host "  CSV : $subnetCsv"
