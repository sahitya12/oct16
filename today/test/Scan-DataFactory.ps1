# sanitychecks/scripts/Scan-DataFactory.ps1

param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$ClientId,
    [Parameter(Mandatory)][string]$ClientSecret,
    [Parameter(Mandatory)][string]$adh_group,
    [ValidateSet('nonprd','prd')][string]$adh_subscription_type = 'nonprd',
    [Parameter(Mandatory)][string]$OutputDir,
    [string]$BranchName = ''
)

# Import required modules
Import-Module Az.Accounts, Az.Resources, Az.DataFactory -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

# Ensure output directory exists and normalize path
$OutputDir = Ensure-Dir $OutputDir

# Connect using service principal
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure connection failed."
}

# -------------------------------------------------
# NEW: Use shared helper to resolve subscriptions
# (replaces the old switch($adh_group.ToUpper()) {...})
# -------------------------------------------------
$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type

$overview = @()
$lsRows   = @()
$irRows   = @()

$allowedEnvs = if ($adh_subscription_type -eq 'prd') { @('prd') } else { @('dev', 'tst', 'stg') }
$adfNames = $allowedEnvs | ForEach-Object { "ADH-$adh_group-ADF-$_" }

foreach ($sub in $subs) {
    Set-ScContext -Subscription $sub

    $dfs = Get-AzDataFactoryV2 -ErrorAction SilentlyContinue |
           Where-Object { $adfNames -contains $_.Name }

    Write-Host ("DEBUG: Scanning subscription {0}; Found DataFactories: {1}" -f `
        $sub.Name, ($dfs | ForEach-Object { $_.Name } -join ', '))

    foreach ($df in $dfs) {
        # Overview row
        $overview += [pscustomobject]@{
            SubscriptionName = $sub.Name
            SubscriptionId   = $sub.Id
            ResourceGroup    = $df.ResourceGroupName
            DataFactory      = $df.Name
            Exists           = 'Yes'
            Location         = $df.Location
        }

        # Linked services
        $ls = Get-AzDataFactoryV2LinkedService -ResourceGroupName $df.ResourceGroupName `
                                               -DataFactoryName $df.Name `
                                               -ErrorAction SilentlyContinue
        foreach ($l in $ls) {
            $lsRows += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $df.ResourceGroupName
                DataFactory      = $df.Name
                LinkedService    = $l.Name
                Type             = $l.Properties.Type
            }
        }

        # Integration runtimes
        $irs = Get-AzDataFactoryV2IntegrationRuntime -ResourceGroupName $df.ResourceGroupName `
                                                     -DataFactoryName $df.Name `
                                                     -ErrorAction SilentlyContinue
        foreach ($ir in $irs) {
            $irRows += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $df.ResourceGroupName
                DataFactory      = $df.Name
                IRName           = $ir.Name
                IRType           = $ir.Properties.Type
                ComputeDesc      = ($ir.Properties.AdditionalProperties.ClusterSize ?? $ir.Properties.Description)
                State            = $ir.Properties.State
            }
        }
    }
}

# If no overview rows at all, emit "Exists = No" rows per subscription
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

# If no linked services, still output placeholder rows
if (-not $lsRows) {
    foreach ($sub in $subs) {
        $lsRows += [pscustomobject]@{
            SubscriptionName = $sub.Name
            ResourceGroup    = ''
            DataFactory      = ''
            LinkedService    = ''
            Type             = ''
        }
    }
}

# If no IRs, still output placeholder rows
if (-not $irRows) {
    foreach ($sub in $subs) {
        $irRows += [pscustomobject]@{
            SubscriptionName = $sub.Name
            ResourceGroup    = ''
            DataFactory      = ''
            IRName           = ''
            IRType           = ''
            ComputeDesc      = ''
            State            = ''
        }
    }
}

# ------------ Outputs --------------

# Overview CSV + HTML
$csv1 = New-StampedPath -BaseDir $OutputDir -Prefix ("adf_overview_{0}_{1}" -f $adh_group, $adh_subscription_type)
Write-CsvSafe -Rows $overview -Path $csv1
Convert-CsvToHtml -CsvPath $csv1 `
                  -HtmlPath ($csv1 -replace '\.csv$','.html') `
                  -Title "ADF Overview ($adh_group / $adh_subscription_type) $BranchName"

# Linked Services CSV
$csv2 = New-StampedPath -BaseDir $OutputDir -Prefix ("adf_linkedservices_{0}_{1}" -f $adh_group, $adh_subscription_type)
Write-CsvSafe -Rows $lsRows -Path $csv2

# Integration Runtimes CSV
$csv3 = New-StampedPath -BaseDir $OutputDir -Prefix ("adf_integrationruntimes_{0}_{1}" -f $adh_group, $adh_subscription_type)
Write-CsvSafe -Rows $irRows -Path $csv3
