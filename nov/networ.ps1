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

# ----------------------------------------------------------------------
# 1) VNet peering scan (ALL VNets in those subscriptions)
# ----------------------------------------------------------------------
$vnetRows = @()

foreach ($sub in $subs) {
    Set-ScContext -Subscription $sub

    Write-Host ""
    Write-Host "=== VNet scan for subscription: $($sub.Name) ===" -ForegroundColor Cyan

    $vnets = Get-AzVirtualNetwork -ErrorAction SilentlyContinue
    if (-not $vnets) { continue }

    foreach ($vnet in $vnets) {

        # If there are no peerings, still add one row showing "NoPeerings"
        if (-not $vnet.VirtualNetworkPeerings -or $vnet.VirtualNetworkPeerings.Count -eq 0) {
            $vnetRows += [pscustomobject]@{
                SubscriptionName                 = $sub.Name
                SubscriptionId                   = $sub.Id
                ResourceGroup                    = $vnet.ResourceGroupName
                VirtualNetwork                   = $vnet.Name
                PeeringName                      = ''
                'Peering connection status'      = 'NoPeerings'
                'Peering state'                  = ''
                'Remote virtual network name'    = ''
                'Virtual network gateway or route server' = ''
                AllowVirtualNetworkAccess        = $null
                AllowForwardedTraffic            = $null
                AllowGatewayTransit              = $null
                UseRemoteGateways                = $null
            }
            continue
        }

        foreach ($peer in $vnet.VirtualNetworkPeerings) {

            # Peering connection status ~ PeeringSyncLevel (Fully In Sync, etc.)
            $connStatus = $peer.PeeringSyncLevel
            # Peering state ~ PeeringState (Connected, Disconnected, etc.)
            $state      = $peer.PeeringState

            # Remote VNet name from ID
            $remoteVnetName = ''
            if ($peer.RemoteVirtualNetwork -and $peer.RemoteVirtualNetwork.Id) {
                $remoteVnetName = ($peer.RemoteVirtualNetwork.Id -split '/')[ -1 ]
            }

            # Virtual network gateway / route server column
            $vnetGwOrRs =
                if ($peer.AllowGatewayTransit -or $peer.UseRemoteGateways) { 'Enabled' }
                else { 'Disabled' }

            $vnetRows += [pscustomobject]@{
                SubscriptionName                 = $sub.Name
                SubscriptionId                   = $sub.Id
                ResourceGroup                    = $vnet.ResourceGroupName
                VirtualNetwork                   = $vnet.Name
                PeeringName                      = $peer.Name
                'Peering connection status'      = $connStatus
                'Peering state'                  = $state
                'Remote virtual network name'    = $remoteVnetName
                'Virtual network gateway or route server' = $vnetGwOrRs
                AllowVirtualNetworkAccess        = $peer.AllowVirtualNetworkAccess
                AllowForwardedTraffic            = $peer.AllowForwardedTraffic
                AllowGatewayTransit              = $peer.AllowGatewayTransit
                UseRemoteGateways                = $peer.UseRemoteGateways
            }
        }
    }
}

if (-not $vnetRows -or $vnetRows.Count -eq 0) {
    $vnetRows = @(
        [pscustomobject]@{
            SubscriptionName                 = ''
            SubscriptionId                   = ''
            ResourceGroup                    = ''
            VirtualNetwork                   = ''
            PeeringName                      = ''
            'Peering connection status'      = ''
            'Peering state'                  = ''
            'Remote virtual network name'    = ''
            'Virtual network gateway or route server' = ''
            AllowVirtualNetworkAccess        = $null
            AllowForwardedTraffic            = $null
            AllowGatewayTransit              = $null
            UseRemoteGateways                = $null
        }
    )
}

$vnetCsv  = New-StampedPath -BaseDir $OutputDir -Prefix ("vnet_peerings_{0}_{1}" -f $adh_group, $adh_subscription_type)
Write-CsvSafe -Rows $vnetRows -Path $vnetCsv
Convert-CsvToHtml -CsvPath $vnetCsv -HtmlPath ($vnetCsv -replace '\.csv$','.html') -Title "VNet Peerings ($adh_group / $adh_subscription_type) $BranchName"

Write-Host "VNet peering scan completed."
Write-Host "  CSV : $vnetCsv"

# ----------------------------------------------------------------------
# 2) Azure Firewall + Public IP scan
# ----------------------------------------------------------------------
$fwRows = @()

foreach ($sub in $subs) {
    Set-ScContext -Subscription $sub

    Write-Host ""
    Write-Host "=== Firewall scan for subscription: $($sub.Name) ===" -ForegroundColor Cyan

    $firewalls = Get-AzFirewall -ErrorAction SilentlyContinue
    if (-not $firewalls) { continue }

    foreach ($fw in $firewalls) {

        if (-not $fw.IpConfigurations) {
            $fwRows += [pscustomobject]@{
                SubscriptionName = $sub.Name
                SubscriptionId   = $sub.Id
                ResourceGroup    = $fw.ResourceGroupName
                FirewallName     = $fw.Name
                PublicIpName     = ''
                PublicIpAddress  = ''
                PublicIpSku      = ''
                PublicIpType     = ''
            }
            continue
        }

        foreach ($ipConf in $fw.IpConfigurations) {
            $pipName      = ''
            $pipRg        = ''
            $pipAddress   = ''
            $pipSku       = ''
            $pipType      = ''

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
                ResourceGroup    = $fw.ResourceGroupName
                FirewallName     = $fw.Name
                PublicIpName     = $pipName
                PublicIpAddress  = $pipAddress
                PublicIpSku      = $pipSku
                PublicIpType     = $pipType
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
