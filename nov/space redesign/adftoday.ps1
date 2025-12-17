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

# ---------------- Helpers ----------------
function Normalize-PortalStatus([string]$rawState) {
    if ([string]::IsNullOrWhiteSpace($rawState)) { return 'Unknown' }

    switch -Regex ($rawState) {
        '^Online$' { return 'Running' }   # portal uses Running
        default    { return $rawState }
    }
}

function Get-IrPortalStateViaRest {
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroupName,
        [Parameter(Mandatory)][string]$FactoryName,
        [Parameter(Mandatory)][string]$IrName
    )

    # ADF IR status endpoint (ARM)
    # Returns state-like values similar to portal column (or very close).
    $apiVersion = "2018-06-01"
    $path = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.DataFactory/factories/$FactoryName/integrationRuntimes/$IrName/status?api-version=$apiVersion"

    try {
        $resp = Invoke-AzRestMethod -Method GET -Path $path -ErrorAction Stop
        $json = $resp.Content | ConvertFrom-Json

        # Common shapes:
        # - $json.properties.state
        # - $json.properties.integrationRuntimeState
        $state = $null
        if ($json.properties.PSObject.Properties.Match('state').Count -gt 0) {
            $state = $json.properties.state
        }
        elseif ($json.properties.PSObject.Properties.Match('integrationRuntimeState').Count -gt 0) {
            $state = $json.properties.integrationRuntimeState
        }

        return (Normalize-PortalStatus -rawState $state)
    }
    catch {
        return "Unknown"
    }
}

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

# Resolve subscriptions
$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
if ($subs -isnot [System.Collections.IEnumerable]) { $subs = ,$subs }

$subNames = ($subs | Select-Object -ExpandProperty Name) -join ', '
Write-Host "DEBUG: Resolved adh_group='$adh_group' env='$adh_subscription_type' -> subscriptions: $subNames"

$overview = @()
$lsRows   = @()
$irRows   = @()

foreach ($sub in $subs) {

    Write-Host "DEBUG: Processing subscription $($sub.Name) ($($sub.Id))"

    Set-ScContext -Subscription $sub
    try { Set-AzContext -Tenant $TenantId -SubscriptionId $sub.Id -ErrorAction Stop | Out-Null } catch {}

    # Read ADFs (live mode)
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

        # Overview row
        $overview += [pscustomobject]@{
            SubscriptionName = $sub.Name
            SubscriptionId   = $sub.Id
            ResourceGroup    = $rg
            DataFactory      = $dfName
            Exists           = 'Yes'
            Location         = $df.Location
        }

        # ---------- Linked Services ----------
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
                    ErrorMessage     = 'No linked services returned (likely not published / validation failing).'
                }
            } else {
                # de-dupe
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

        # ---------- Integration Runtimes ----------
        try {
            $irs = @(Get-AzDataFactoryV2IntegrationRuntime -ResourceGroupName $rg -DataFactoryName $dfName -ErrorAction Stop)

            if ($irs.Count -eq 0) {
                $irRows += [pscustomobject]@{
                    SubscriptionName = $sub.Name
                    ResourceGroup    = $rg
                    DataFactory      = $dfName
                    IRName           = ''
                    IRType           = ''
                    Status           = 'OK'
                    ErrorMessage     = 'No integration runtimes returned (likely not published / validation failing).'
                }
            } else {
                foreach ($ir in $irs) {

                    $irType = $null
                    if ($ir.Properties -and $ir.Properties.Type) { $irType = $ir.Properties.Type } # Managed / SelfHosted
                    elseif ($ir.Type) { $irType = $ir.Type }
                    if (-not $irType) { $irType = 'Unknown' }

                    # Portal-like status via ARM status endpoint
                    $portalStatus = Get-IrPortalStateViaRest `
                        -SubscriptionId $sub.Id `
                        -ResourceGroupName $rg `
                        -FactoryName $dfName `
                        -IrName $ir.Name

                    $irRows += [pscustomobject]@{
                        SubscriptionName = $sub.Name
                        ResourceGroup    = $rg
                        DataFactory      = $dfName
                        IRName           = $ir.Name
                        IRType           = $irType
                        Status           = $portalStatus
                        ErrorMessage     = ''
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

# If nothing found at all, still emit overview rows
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
