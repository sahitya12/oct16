# sanitychecks/scripts/Scan-DataFactory.ps1

param(
    [Parameter(Mandatory = $true)][string]$TenantId,
    [Parameter(Mandatory = $true)][string]$ClientId,
    [Parameter(Mandatory = $true)][string]$ClientSecret,
    [Parameter(Mandatory = $true)][string]$adh_group,
    [ValidateSet('nonprd','prd')][string]$adh_subscription_type = 'nonprd',
    [Parameter(Mandatory = $true)][string]$OutputDir,
    [string]$BranchName = ''
)

Import-Module Az.Accounts, Az.Resources, Az.DataFactory -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

Write-Host "DEBUG: TenantId              = $TenantId"
Write-Host "DEBUG: ClientId              = $ClientId"
Write-Host "DEBUG: adh_group             = $adh_group"
Write-Host "DEBUG: adh_subscription_type = $adh_subscription_type"
Write-Host "DEBUG: OutputDir             = $OutputDir"
Write-Host "DEBUG: BranchName            = $BranchName"

Ensure-Dir -Path $OutputDir | Out-Null

if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure login failed."
}

function Invoke-ArmGetJson {
    param([Parameter(Mandatory)][string]$Path)
    $resp = Invoke-AzRestMethod -Method GET -Path $Path -ErrorAction Stop
    return ($resp.Content | ConvertFrom-Json)
}

function Get-IrStatusAndMessage {
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroupName,
        [Parameter(Mandatory)][string]$FactoryName,
        [Parameter(Mandatory)][string]$IrName
    )

    $apiVersion = "2018-06-01"
    $path = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.DataFactory/factories/$FactoryName/integrationRuntimes/$IrName/status?api-version=$apiVersion"

    try {
        $json = Invoke-ArmGetJson -Path $path

        # Typical: properties.state (Online / NeedRegistration / Starting / Stopped / etc)
        $state = $null
        if ($json.properties -and ($json.properties.PSObject.Properties.Name -contains 'state')) {
            $state = $json.properties.state
        }
        elseif ($json.properties -and ($json.properties.PSObject.Properties.Name -contains 'integrationRuntimeState')) {
            $state = $json.properties.integrationRuntimeState
        }

        if ([string]::IsNullOrWhiteSpace($state)) {
            return @{ Status = 'Unknown'; ErrorMessage = 'Status endpoint returned no state field.' }
        }

        return @{ Status = [string]$state; ErrorMessage = '' }
    }
    catch {
        $msg = $_.Exception.Message

        # Make portal-like meaning explicit
        if ($msg -match '\b404\b' -or $msg -match 'NotFound') {
            return @{ Status = 'NotFound'; ErrorMessage = $msg }
        }
        if ($msg -match '\b403\b' -or $msg -match 'Forbidden') {
            return @{ Status = 'Forbidden'; ErrorMessage = $msg }
        }
        if ($msg -match '\b401\b' -or $msg -match 'Unauthorized') {
            return @{ Status = 'Unauthorized'; ErrorMessage = $msg }
        }

        return @{ Status = 'Unknown'; ErrorMessage = $msg }
    }
}

# Resolve subscriptions
$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
if ($subs -isnot [System.Collections.IEnumerable]) { $subs = ,$subs }

$overview = @()
$lsRows   = @()
$irRows   = @()

foreach ($sub in $subs) {

    Write-Host "DEBUG: Processing subscription $($sub.Name) ($($sub.Id))"

    Set-ScContext -Subscription $sub
    try { Set-AzContext -Tenant $TenantId -SubscriptionId $sub.Id -ErrorAction Stop | Out-Null } catch {}

    # LIVE ADFs
    $dfs = @(Get-AzDataFactoryV2 -ErrorAction SilentlyContinue)
    if ($dfs.Count -eq 0) {
        Write-Host "DEBUG: No DataFactories found in $($sub.Name)"
        continue
    }

    foreach ($df in $dfs) {

        $dfName = $null
        if ($df.PSObject.Properties.Match('DataFactoryName').Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($df.DataFactoryName)) { $dfName = $df.DataFactoryName }
        elseif ($df.PSObject.Properties.Match('FactoryName').Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($df.FactoryName)) { $dfName = $df.FactoryName }
        elseif ($df.PSObject.Properties.Match('Name').Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($df.Name)) { $dfName = $df.Name }

        if ([string]::IsNullOrWhiteSpace($dfName)) { continue }

        $rg = [string]$df.ResourceGroupName

        $overview += [pscustomobject]@{
            SubscriptionName = $sub.Name
            SubscriptionId   = $sub.Id
            ResourceGroup    = $rg
            DataFactory      = $dfName
            Exists           = 'Yes'
            Location         = $df.Location
        }

        # ----------------- Linked Services (live) -----------------
        try {
            $ls = @(Get-AzDataFactoryV2LinkedService -ResourceGroupName $rg -DataFactoryName $dfName -ErrorAction Stop)

            if ($ls.Count -eq 0) {
                $lsRows += [pscustomobject]@{
                    SubscriptionName = $sub.Name
                    ResourceGroup    = $rg
                    DataFactory      = $dfName
                    LinkedService    = ''
                    Type             = ''
                    Status           = 'OK'
                    ErrorMessage     = 'No linked services returned (likely not published / not in live).'
                }
            } else {
                $ls = $ls | Group-Object Name | ForEach-Object { $_.Group | Select-Object -First 1 }
                foreach ($l in $ls) {
                    $lsType = $null
                    if ($l.Properties -and $l.Properties.Type) { $lsType = $l.Properties.Type }
                    elseif ($l.Type) { $lsType = $l.Type }
                    elseif ($l.Properties) { $lsType = $l.Properties.GetType().Name }
                    if (-not $lsType) { $lsType = 'Unknown' }

                    $lsRows += [pscustomobject]@{
                        SubscriptionName = $sub.Name
                        ResourceGroup    = $rg
                        DataFactory      = $dfName
                        LinkedService    = $l.Name
                        Type             = $lsType
                        Status           = 'OK'
                        ErrorMessage     = ''
                    }
                }
            }
        }
        catch {
            $lsRows += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $rg
                DataFactory      = $dfName
                LinkedService    = ''
                Type             = ''
                Status           = 'ERROR'
                ErrorMessage     = $_.Exception.Message
            }
        }

        # ----------------- Integration Runtimes (portal-like list via ARM REST) -----------------
        try {
            $apiVersion = "2018-06-01"
            $listPath = "/subscriptions/$($sub.Id)/resourceGroups/$rg/providers/Microsoft.DataFactory/factories/$dfName/integrationRuntimes?api-version=$apiVersion"
            $listJson = Invoke-ArmGetJson -Path $listPath

            $irItems = @()
            if ($listJson -and ($listJson.PSObject.Properties.Name -contains 'value')) {
                $irItems = @($listJson.value)
            }

            if ($irItems.Count -eq 0) {
                $irRows += [pscustomobject]@{
                    SubscriptionName = $sub.Name
                    ResourceGroup    = $rg
                    DataFactory      = $dfName
                    IRName           = ''
                    IRType           = ''
                    Status           = 'OK'
                    ErrorMessage     = 'No integration runtimes returned (likely not published / not in live).'
                }
            } else {
                foreach ($item in $irItems) {
                    $irName = [string]$item.name
                    $irType = 'Unknown'
                    if ($item.properties -and ($item.properties.PSObject.Properties.Name -contains 'type')) {
                        $irType = [string]$item.properties.type  # Managed / SelfHosted
                    }

                    $st = Get-IrStatusAndMessage -SubscriptionId $sub.Id -ResourceGroupName $rg -FactoryName $dfName -IrName $irName

                    $irRows += [pscustomobject]@{
                        SubscriptionName = $sub.Name
                        ResourceGroup    = $rg
                        DataFactory      = $dfName
                        IRName           = $irName
                        IRType           = $irType
                        Status           = $st.Status
                        ErrorMessage     = $st.ErrorMessage
                    }
                }
            }
        }
        catch {
            $irRows += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $rg
                DataFactory      = $dfName
                IRName           = ''
                IRType           = ''
                Status           = 'ERROR'
                ErrorMessage     = $_.Exception.Message
            }
        }
    }
}

# If no ADFs were found at all, still emit one "Exists = No" per sub
if (-not $overview) {
    foreach ($sub in $subs) {
        $overview += [pscustomobject]@{
            SubscriptionName = $sub.Name
            SubscriptionId   = $sub.Id
            ResourceGroup    = ''
            DataFactory      = ''
            Exists           = 'No'
            Location         = ''
        }
    }
}

# Ensure CSVs always have at least one row
if (-not $lsRows) {
    foreach ($sub in $subs) {
        $lsRows += [pscustomobject]@{
            SubscriptionName = $sub.Name
            ResourceGroup    = ''
            DataFactory      = ''
            LinkedService    = ''
            Type             = ''
            Status           = 'OK'
            ErrorMessage     = 'No data'
        }
    }
}

if (-not $irRows) {
    foreach ($sub in $subs) {
        $irRows += [pscustomobject]@{
            SubscriptionName = $sub.Name
            ResourceGroup    = ''
            DataFactory      = ''
            IRName           = ''
            IRType           = ''
            Status           = 'OK'
            ErrorMessage     = 'No data'
        }
    }
}

# Output CSV + HTML
$csv1 = New-StampedPath -BaseDir $OutputDir -Prefix ("adf_overview_{0}_{1}" -f $adh_group, $adh_subscription_type)
Write-CsvSafe -Rows $overview -Path $csv1
Convert-CsvToHtml -CsvPath $csv1 -HtmlPath ($csv1 -replace '\.csv$','.html') -Title "ADF Overview ($adh_group / $adh_subscription_type) $BranchName"

$csv2 = New-StampedPath -BaseDir $OutputDir -Prefix ("adf_linkedservices_{0}_{1}" -f $adh_group, $adh_subscription_type)
Write-CsvSafe -Rows $lsRows -Path $csv2

$csv3 = New-StampedPath -BaseDir $OutputDir -Prefix ("adf_integrationruntimes_{0}_{1}" -f $adh_group, $adh_subscription_type)
Write-CsvSafe -Rows $irRows -Path $csv3

Write-Host "ADF scan completed." -ForegroundColor Green
Write-Host "Overview CSV : $csv1"
Write-Host "Linked Svc   : $csv2"
Write-Host "IRs          : $csv3"
