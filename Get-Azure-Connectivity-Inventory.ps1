<#
Purpose:
Inventory across all SPN-accessible subscriptions:
1. Azure Firewall public IPs
2. NAT Gateway public IPs and attached subnets
3. ADF Self-hosted Integration Runtime details
4. Logic App Consumption outbound IPs, including recurrence-trigger workflows
5. Logic App Standard outbound IPs

Required modules:
Install-Module Az.Accounts -Scope CurrentUser -Force
Install-Module Az.Network -Scope CurrentUser -Force
Install-Module Az.DataFactory -Scope CurrentUser -Force
Install-Module Az.Resources -Scope CurrentUser -Force
Install-Module Az.Websites -Scope CurrentUser -Force
#>

param(
    [Parameter(Mandatory = $true)]
    [string] $TenantId,

    [Parameter(Mandatory = $true)]
    [string] $ClientId,

    [Parameter(Mandatory = $true)]
    [string] $ClientSecret,

    [string] $OutputFolder = ".\Azure-Connectivity-Inventory"
)

# -----------------------------
# Helper functions
# -----------------------------

function Get-ResourceGroupNameFromId {
    param([string] $ResourceId)

    if ([string]::IsNullOrWhiteSpace($ResourceId)) {
        return ""
    }

    $parts = $ResourceId -split "/"
    $rgIndex = [Array]::IndexOf($parts, "resourceGroups")

    if ($rgIndex -ge 0 -and ($rgIndex + 1) -lt $parts.Count) {
        return $parts[$rgIndex + 1]
    }

    return ""
}

function Get-ResourceNameFromId {
    param([string] $ResourceId)

    if ([string]::IsNullOrWhiteSpace($ResourceId)) {
        return ""
    }

    return ($ResourceId -split "/")[-1]
}

function Safe-Join {
    param(
        [object[]] $Values,
        [string] $Separator = "; "
    )

    if ($null -eq $Values) {
        return ""
    }

    return ($Values | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join $Separator
}

function Add-InventoryRow {
    param(
        [string] $SubscriptionName,
        [string] $SubscriptionId,
        [string] $ResourceGroupName,
        [string] $ResourceType,
        [string] $ResourceName,
        [string] $Location,
        [string] $DetailType,
        [string] $IpAddress,
        [string] $IpPrefix,
        [string] $AttachedSubnetName,
        [string] $AttachedSubnetId,
        [string] $ParentResourceName,
        [string] $ParentResourceType,
        [string] $ExtraDetails
    )

    $script:Inventory += [PSCustomObject]@{
        SubscriptionName   = $SubscriptionName
        SubscriptionId     = $SubscriptionId
        ResourceGroupName  = $ResourceGroupName
        ResourceType       = $ResourceType
        ResourceName       = $ResourceName
        Location           = $Location
        DetailType         = $DetailType
        IpAddress          = $IpAddress
        IpPrefix           = $IpPrefix
        AttachedSubnetName = $AttachedSubnetName
        AttachedSubnetId   = $AttachedSubnetId
        ParentResourceName = $ParentResourceName
        ParentResourceType = $ParentResourceType
        ExtraDetails       = $ExtraDetails
    }
}

function Get-PublicIpAddressFromId {
    param([string] $PublicIpId)

    if ([string]::IsNullOrWhiteSpace($PublicIpId)) {
        return ""
    }

    try {
        $rgName = Get-ResourceGroupNameFromId -ResourceId $PublicIpId
        $pipName = Get-ResourceNameFromId -ResourceId $PublicIpId

        $pip = Get-AzPublicIpAddress -ResourceGroupName $rgName -Name $pipName -ErrorAction Stop

        return $pip.IpAddress
    }
    catch {
        return "UnableToResolvePublicIP"
    }
}

function Get-PublicIpPrefixFromId {
    param([string] $PrefixId)

    if ([string]::IsNullOrWhiteSpace($PrefixId)) {
        return ""
    }

    try {
        $rgName = Get-ResourceGroupNameFromId -ResourceId $PrefixId
        $prefixName = Get-ResourceNameFromId -ResourceId $PrefixId

        $prefix = Get-AzPublicIpPrefix -ResourceGroupName $rgName -Name $prefixName -ErrorAction Stop

        return $prefix.IpPrefix
    }
    catch {
        return "UnableToResolvePublicIPPrefix"
    }
}

# -----------------------------
# Prepare output
# -----------------------------

if (!(Test-Path $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder | Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

$script:Inventory = @()

# -----------------------------
# Login using SPN
# -----------------------------

Write-Host "Logging in using Service Principal..." -ForegroundColor Cyan

$secureSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($ClientId, $secureSecret)

Connect-AzAccount `
    -ServicePrincipal `
    -Tenant $TenantId `
    -Credential $credential `
    -ErrorAction Stop | Out-Null

$subscriptions = Get-AzSubscription | Sort-Object Name

Write-Host "Found $($subscriptions.Count) subscription(s)." -ForegroundColor Green

# -----------------------------
# Scan subscriptions
# -----------------------------

foreach ($sub in $subscriptions) {

    Write-Host "`nProcessing subscription: $($sub.Name) [$($sub.Id)]" -ForegroundColor Yellow

    try {
        Set-AzContext -SubscriptionId $sub.Id -TenantId $TenantId -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Warning "Unable to set context for subscription $($sub.Name). Skipping."
        continue
    }

    # -----------------------------
    # 1. Azure Firewall public IPs
    # -----------------------------
    try {
        $firewalls = Get-AzFirewall -ErrorAction SilentlyContinue

        foreach ($fw in $firewalls) {

            $fwRg = Get-ResourceGroupNameFromId -ResourceId $fw.Id

            foreach ($ipConfig in $fw.IpConfigurations) {

                $pipId = $ipConfig.PublicIpAddress.Id
                $pipName = Get-ResourceNameFromId -ResourceId $pipId
                $pipAddress = Get-PublicIpAddressFromId -PublicIpId $pipId

                Add-InventoryRow `
                    -SubscriptionName $sub.Name `
                    -SubscriptionId $sub.Id `
                    -ResourceGroupName $fwRg `
                    -ResourceType "Microsoft.Network/azureFirewalls" `
                    -ResourceName $fw.Name `
                    -Location $fw.Location `
                    -DetailType "AzureFirewallPublicIP" `
                    -IpAddress $pipAddress `
                    -IpPrefix "" `
                    -AttachedSubnetName "" `
                    -AttachedSubnetId "" `
                    -ParentResourceName $pipName `
                    -ParentResourceType "Microsoft.Network/publicIPAddresses" `
                    -ExtraDetails "Firewall IP Configuration: $($ipConfig.Name)"
            }

            if ($null -ne $fw.ManagementIpConfiguration -and $null -ne $fw.ManagementIpConfiguration.PublicIpAddress) {

                $mgmtPipId = $fw.ManagementIpConfiguration.PublicIpAddress.Id
                $mgmtPipName = Get-ResourceNameFromId -ResourceId $mgmtPipId
                $mgmtPipAddress = Get-PublicIpAddressFromId -PublicIpId $mgmtPipId

                Add-InventoryRow `
                    -SubscriptionName $sub.Name `
                    -SubscriptionId $sub.Id `
                    -ResourceGroupName $fwRg `
                    -ResourceType "Microsoft.Network/azureFirewalls" `
                    -ResourceName $fw.Name `
                    -Location $fw.Location `
                    -DetailType "AzureFirewallManagementPublicIP" `
                    -IpAddress $mgmtPipAddress `
                    -IpPrefix "" `
                    -AttachedSubnetName "" `
                    -AttachedSubnetId "" `
                    -ParentResourceName $mgmtPipName `
                    -ParentResourceType "Microsoft.Network/publicIPAddresses" `
                    -ExtraDetails "Firewall Management IP Configuration"
            }
        }
    }
    catch {
        Write-Warning "Failed to scan Azure Firewalls in subscription $($sub.Name): $($_.Exception.Message)"
    }

    # -----------------------------
    # 2. NAT Gateway public IPs and attached subnets
    # -----------------------------
    try {
        $natGateways = Get-AzNatGateway -ErrorAction SilentlyContinue

        foreach ($nat in $natGateways) {

            $natRg = Get-ResourceGroupNameFromId -ResourceId $nat.Id

            $attachedSubnetIds = @()

            if ($null -ne $nat.Subnets) {
                $attachedSubnetIds = $nat.Subnets.Id
            }

            $attachedSubnetNames = $attachedSubnetIds | ForEach-Object { Get-ResourceNameFromId -ResourceId $_ }

            # NAT public IPs
            if ($null -ne $nat.PublicIpAddresses) {
                foreach ($pipRef in $nat.PublicIpAddresses) {

                    $pipId = $pipRef.Id
                    $pipName = Get-ResourceNameFromId -ResourceId $pipId
                    $pipAddress = Get-PublicIpAddressFromId -PublicIpId $pipId

                    if ($attachedSubnetIds.Count -gt 0) {
                        foreach ($subnetId in $attachedSubnetIds) {
                            Add-InventoryRow `
                                -SubscriptionName $sub.Name `
                                -SubscriptionId $sub.Id `
                                -ResourceGroupName $natRg `
                                -ResourceType "Microsoft.Network/natGateways" `
                                -ResourceName $nat.Name `
                                -Location $nat.Location `
                                -DetailType "NatGatewayPublicIP" `
                                -IpAddress $pipAddress `
                                -IpPrefix "" `
                                -AttachedSubnetName (Get-ResourceNameFromId -ResourceId $subnetId) `
                                -AttachedSubnetId $subnetId `
                                -ParentResourceName $pipName `
                                -ParentResourceType "Microsoft.Network/publicIPAddresses" `
                                -ExtraDetails "NAT Gateway public IP attached to subnet"
                        }
                    }
                    else {
                        Add-InventoryRow `
                            -SubscriptionName $sub.Name `
                            -SubscriptionId $sub.Id `
                            -ResourceGroupName $natRg `
                            -ResourceType "Microsoft.Network/natGateways" `
                            -ResourceName $nat.Name `
                            -Location $nat.Location `
                            -DetailType "NatGatewayPublicIP" `
                            -IpAddress $pipAddress `
                            -IpPrefix "" `
                            -AttachedSubnetName "" `
                            -AttachedSubnetId "" `
                            -ParentResourceName $pipName `
                            -ParentResourceType "Microsoft.Network/publicIPAddresses" `
                            -ExtraDetails "NAT Gateway public IP. No attached subnet found."
                    }
                }
            }

            # NAT public IP prefixes
            if ($null -ne $nat.PublicIpPrefixes) {
                foreach ($prefixRef in $nat.PublicIpPrefixes) {

                    $prefixId = $prefixRef.Id
                    $prefixName = Get-ResourceNameFromId -ResourceId $prefixId
                    $resolvedPrefix = Get-PublicIpPrefixFromId -PrefixId $prefixId

                    if ($attachedSubnetIds.Count -gt 0) {
                        foreach ($subnetId in $attachedSubnetIds) {
                            Add-InventoryRow `
                                -SubscriptionName $sub.Name `
                                -SubscriptionId $sub.Id `
                                -ResourceGroupName $natRg `
                                -ResourceType "Microsoft.Network/natGateways" `
                                -ResourceName $nat.Name `
                                -Location $nat.Location `
                                -DetailType "NatGatewayPublicIPPrefix" `
                                -IpAddress "" `
                                -IpPrefix $resolvedPrefix `
                                -AttachedSubnetName (Get-ResourceNameFromId -ResourceId $subnetId) `
                                -AttachedSubnetId $subnetId `
                                -ParentResourceName $prefixName `
                                -ParentResourceType "Microsoft.Network/publicIPPrefixes" `
                                -ExtraDetails "NAT Gateway public IP prefix attached to subnet"
                        }
                    }
                    else {
                        Add-InventoryRow `
                            -SubscriptionName $sub.Name `
                            -SubscriptionId $sub.Id `
                            -ResourceGroupName $natRg `
                            -ResourceType "Microsoft.Network/natGateways" `
                            -ResourceName $nat.Name `
                            -Location $nat.Location `
                            -DetailType "NatGatewayPublicIPPrefix" `
                            -IpAddress "" `
                            -IpPrefix $resolvedPrefix `
                            -AttachedSubnetName "" `
                            -AttachedSubnetId "" `
                            -ParentResourceName $prefixName `
                            -ParentResourceType "Microsoft.Network/publicIPPrefixes" `
                            -ExtraDetails "NAT Gateway public IP prefix. No attached subnet found."
                    }
                }
            }

            if (($null -eq $nat.PublicIpAddresses -or $nat.PublicIpAddresses.Count -eq 0) -and
                ($null -eq $nat.PublicIpPrefixes -or $nat.PublicIpPrefixes.Count -eq 0)) {

                Add-InventoryRow `
                    -SubscriptionName $sub.Name `
                    -SubscriptionId $sub.Id `
                    -ResourceGroupName $natRg `
                    -ResourceType "Microsoft.Network/natGateways" `
                    -ResourceName $nat.Name `
                    -Location $nat.Location `
                    -DetailType "NatGatewayNoPublicIPFound" `
                    -IpAddress "" `
                    -IpPrefix "" `
                    -AttachedSubnetName (Safe-Join -Values $attachedSubnetNames) `
                    -AttachedSubnetId (Safe-Join -Values $attachedSubnetIds) `
                    -ParentResourceName "" `
                    -ParentResourceType "" `
                    -ExtraDetails "NAT Gateway found, but no Public IP or Public IP Prefix associated."
            }
        }
    }
    catch {
        Write-Warning "Failed to scan NAT Gateways in subscription $($sub.Name): $($_.Exception.Message)"
    }

    # -----------------------------
    # 3. ADF Self-hosted Integration Runtime details
    # -----------------------------
    try {
        $factories = Get-AzDataFactoryV2 -ErrorAction SilentlyContinue

        foreach ($factory in $factories) {

            $integrationRuntimes = Get-AzDataFactoryV2IntegrationRuntime `
                -ResourceGroupName $factory.ResourceGroupName `
                -DataFactoryName $factory.DataFactoryName `
                -ErrorAction SilentlyContinue

            foreach ($ir in $integrationRuntimes) {

                if ($ir.Type -eq "SelfHosted") {

                    $irStatusText = ""
                    $nodeInfo = ""

                    try {
                        $irStatus = Get-AzDataFactoryV2IntegrationRuntime `
                            -ResourceGroupName $factory.ResourceGroupName `
                            -DataFactoryName $factory.DataFactoryName `
                            -Name $ir.Name `
                            -Status `
                            -ErrorAction SilentlyContinue

                        if ($null -ne $irStatus) {
                            $irStatusText = $irStatus.State

                            if ($null -ne $irStatus.Node) {
                                $nodeInfo = ($irStatus.Node | ForEach-Object {
                                    "NodeName=$($_.NodeName),Status=$($_.Status),Version=$($_.Version),LastConnectTime=$($_.LastConnectTime)"
                                }) -join " | "
                            }
                        }
                    }
                    catch {
                        $irStatusText = "UnableToReadStatus"
                    }

                    Add-InventoryRow `
                        -SubscriptionName $sub.Name `
                        -SubscriptionId $sub.Id `
                        -ResourceGroupName $factory.ResourceGroupName `
                        -ResourceType "Microsoft.DataFactory/factories/integrationRuntimes" `
                        -ResourceName $ir.Name `
                        -Location $factory.Location `
                        -DetailType "ADF-SelfHostedIntegrationRuntime" `
                        -IpAddress "" `
                        -IpPrefix "" `
                        -AttachedSubnetName "" `
                        -AttachedSubnetId "" `
                        -ParentResourceName $factory.DataFactoryName `
                        -ParentResourceType "Microsoft.DataFactory/factories" `
                        -ExtraDetails "ADF=$($factory.DataFactoryName); IRType=$($ir.Type); IRStatus=$irStatusText; Nodes=$nodeInfo"
                }
            }
        }
    }
    catch {
        Write-Warning "Failed to scan ADF Self-hosted IRs in subscription $($sub.Name): $($_.Exception.Message)"
    }

    # -----------------------------
    # 4. Logic App Consumption outbound IPs and recurrence-trigger details
    # -----------------------------
    try {
        $logicApps = Get-AzResource `
            -ResourceType "Microsoft.Logic/workflows" `
            -ExpandProperties `
            -ErrorAction SilentlyContinue

        foreach ($logicApp in $logicApps) {

            $logicAppRg = $logicApp.ResourceGroupName
            $logicAppName = $logicApp.Name
            $logicAppLocation = $logicApp.Location

            $props = $logicApp.Properties

            $workflowOutgoingIps = @()
            $connectorOutgoingIps = @()
            $accessEndpoint = ""
            $triggerNames = @()
            $triggerTypes = @()
            $hasRecurrenceTrigger = $false

            if ($null -ne $props.accessEndpoint) {
                $accessEndpoint = [string]$props.accessEndpoint
            }

            if ($null -ne $props.endpointsConfiguration) {

                if ($null -ne $props.endpointsConfiguration.workflow -and
                    $null -ne $props.endpointsConfiguration.workflow.outgoingIpAddresses) {

                    $workflowOutgoingIps = $props.endpointsConfiguration.workflow.outgoingIpAddresses | ForEach-Object {
                        if ($_.address) { $_.address } else { [string]$_ }
                    }
                }

                if ($null -ne $props.endpointsConfiguration.connector -and
                    $null -ne $props.endpointsConfiguration.connector.outgoingIpAddresses) {

                    $connectorOutgoingIps = $props.endpointsConfiguration.connector.outgoingIpAddresses | ForEach-Object {
                        if ($_.address) { $_.address } else { [string]$_ }
                    }
                }
            }

            if ($null -ne $props.definition -and $null -ne $props.definition.triggers) {

                $triggerObject = $props.definition.triggers

                $triggerObject.PSObject.Properties | ForEach-Object {
                    $triggerName = $_.Name
                    $triggerValue = $_.Value
                    $triggerType = [string]$triggerValue.type

                    $triggerNames += $triggerName
                    $triggerTypes += $triggerType

                    if ($triggerType -eq "Recurrence") {
                        $hasRecurrenceTrigger = $true
                    }
                }
            }

            $triggerSummary = "Triggers=$((Safe-Join -Values $triggerNames)); TriggerTypes=$((Safe-Join -Values $triggerTypes)); HasRecurrenceTrigger=$hasRecurrenceTrigger; AccessEndpoint=$accessEndpoint"

            foreach ($ip in $workflowOutgoingIps) {
                Add-InventoryRow `
                    -SubscriptionName $sub.Name `
                    -SubscriptionId $sub.Id `
                    -ResourceGroupName $logicAppRg `
                    -ResourceType "Microsoft.Logic/workflows" `
                    -ResourceName $logicAppName `
                    -Location $logicAppLocation `
                    -DetailType "LogicAppConsumptionWorkflowOutboundIP" `
                    -IpAddress $ip `
                    -IpPrefix "" `
                    -AttachedSubnetName "" `
                    -AttachedSubnetId "" `
                    -ParentResourceName "" `
                    -ParentResourceType "" `
                    -ExtraDetails $triggerSummary
            }

            foreach ($ip in $connectorOutgoingIps) {
                Add-InventoryRow `
                    -SubscriptionName $sub.Name `
                    -SubscriptionId $sub.Id `
                    -ResourceGroupName $logicAppRg `
                    -ResourceType "Microsoft.Logic/workflows" `
                    -ResourceName $logicAppName `
                    -Location $logicAppLocation `
                    -DetailType "LogicAppConsumptionConnectorOutboundIP" `
                    -IpAddress $ip `
                    -IpPrefix "" `
                    -AttachedSubnetName "" `
                    -AttachedSubnetId "" `
                    -ParentResourceName "" `
                    -ParentResourceType "" `
                    -ExtraDetails $triggerSummary
            }

            if (($workflowOutgoingIps.Count -eq 0) -and ($connectorOutgoingIps.Count -eq 0)) {
                Add-InventoryRow `
                    -SubscriptionName $sub.Name `
                    -SubscriptionId $sub.Id `
                    -ResourceGroupName $logicAppRg `
                    -ResourceType "Microsoft.Logic/workflows" `
                    -ResourceName $logicAppName `
                    -Location $logicAppLocation `
                    -DetailType "LogicAppConsumptionNoOutboundIPFound" `
                    -IpAddress "" `
                    -IpPrefix "" `
                    -AttachedSubnetName "" `
                    -AttachedSubnetId "" `
                    -ParentResourceName "" `
                    -ParentResourceType "" `
                    -ExtraDetails $triggerSummary
            }
        }
    }
    catch {
        Write-Warning "Failed to scan Logic App Consumption workflows in subscription $($sub.Name): $($_.Exception.Message)"
    }

    # -----------------------------
    # 5. Logic App Standard outbound IPs
    # Logic App Standard is App Service based: Microsoft.Web/sites with kind containing workflowapp
    # -----------------------------
    try {
        $workflowApps = Get-AzResource `
            -ResourceType "Microsoft.Web/sites" `
            -ExpandProperties `
            -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Kind -like "*workflowapp*"
            }

        foreach ($app in $workflowApps) {

            $appRg = $app.ResourceGroupName
            $appName = $app.Name
            $appLocation = $app.Location
            $props = $app.Properties

            $outboundIps = @()
            $possibleOutboundIps = @()

            if ($null -ne $props.outboundIpAddresses) {
                $outboundIps = ([string]$props.outboundIpAddresses).Split(",", [System.StringSplitOptions]::RemoveEmptyEntries) | ForEach-Object { $_.Trim() }
            }

            if ($null -ne $props.possibleOutboundIpAddresses) {
                $possibleOutboundIps = ([string]$props.possibleOutboundIpAddresses).Split(",", [System.StringSplitOptions]::RemoveEmptyEntries) | ForEach-Object { $_.Trim() }
            }

            foreach ($ip in $outboundIps) {
                Add-InventoryRow `
                    -SubscriptionName $sub.Name `
                    -SubscriptionId $sub.Id `
                    -ResourceGroupName $appRg `
                    -ResourceType "Microsoft.Web/sites" `
                    -ResourceName $appName `
                    -Location $appLocation `
                    -DetailType "LogicAppStandardOutboundIP" `
                    -IpAddress $ip `
                    -IpPrefix "" `
                    -AttachedSubnetName "" `
                    -AttachedSubnetId "" `
                    -ParentResourceName "" `
                    -ParentResourceType "" `
                    -ExtraDetails "Kind=$($app.Kind); PossibleOutboundIPs=$((Safe-Join -Values $possibleOutboundIps))"
            }

            if ($outboundIps.Count -eq 0) {
                Add-InventoryRow `
                    -SubscriptionName $sub.Name `
                    -SubscriptionId $sub.Id `
                    -ResourceGroupName $appRg `
                    -ResourceType "Microsoft.Web/sites" `
                    -ResourceName $appName `
                    -Location $appLocation `
                    -DetailType "LogicAppStandardNoOutboundIPFound" `
                    -IpAddress "" `
                    -IpPrefix "" `
                    -AttachedSubnetName "" `
                    -AttachedSubnetId "" `
                    -ParentResourceName "" `
                    -ParentResourceType "" `
                    -ExtraDetails "Kind=$($app.Kind); PossibleOutboundIPs=$((Safe-Join -Values $possibleOutboundIps))"
            }
        }
    }
    catch {
        Write-Warning "Failed to scan Logic App Standard workflow apps in subscription $($sub.Name): $($_.Exception.Message)"
    }
}

# -----------------------------
# Export CSVs
# -----------------------------

$allCsv = Join-Path $OutputFolder "All-Connectivity-Inventory-$timestamp.csv"
$fwCsv = Join-Path $OutputFolder "AzureFirewall-PublicIPs-$timestamp.csv"
$natCsv = Join-Path $OutputFolder "NatGateway-PublicIPs-Subnets-$timestamp.csv"
$shirCsv = Join-Path $OutputFolder "ADF-SHIR-Details-$timestamp.csv"
$logicAppCsv = Join-Path $OutputFolder "LogicApp-OutboundIPs-$timestamp.csv"

$Inventory |
    Sort-Object SubscriptionName, ResourceType, ResourceName, DetailType |
    Export-Csv -Path $allCsv -NoTypeInformation -Encoding UTF8

$Inventory |
    Where-Object { $_.DetailType -like "AzureFirewall*" } |
    Sort-Object SubscriptionName, ResourceName |
    Export-Csv -Path $fwCsv -NoTypeInformation -Encoding UTF8

$Inventory |
    Where-Object { $_.DetailType -like "NatGateway*" } |
    Sort-Object SubscriptionName, ResourceName |
    Export-Csv -Path $natCsv -NoTypeInformation -Encoding UTF8

$Inventory |
    Where-Object { $_.DetailType -like "ADF-SelfHostedIntegrationRuntime" } |
    Sort-Object SubscriptionName, ParentResourceName, ResourceName |
    Export-Csv -Path $shirCsv -NoTypeInformation -Encoding UTF8

$Inventory |
    Where-Object { $_.DetailType -like "LogicApp*" } |
    Sort-Object SubscriptionName, ResourceGroupName, ResourceName, DetailType |
    Export-Csv -Path $logicAppCsv -NoTypeInformation -Encoding UTF8

Write-Host "`nExport completed." -ForegroundColor Green
Write-Host "All inventory:              $allCsv"
Write-Host "Azure Firewall IPs:         $fwCsv"
Write-Host "NAT Gateway IPs/Subnets:    $natCsv"
Write-Host "ADF SHIR details:           $shirCsv"
Write-Host "Logic App outbound IPs:     $logicAppCsv"
