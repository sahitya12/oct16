param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$ClientId,
    [Parameter(Mandatory)][string]$ClientSecret,
    [Parameter(Mandatory)][string]$adh_group,
    [ValidateSet('nonprd','prd')][string]$adh_subscription_type = 'nonprd',
    [Parameter(Mandatory)][string]$OutputDir,
    [string]$BranchName = ''
)

Import-Module Az.Accounts, Az.Resources, Az.DataFactory -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

Write-Host "DEBUG: TenantId=$TenantId"
Write-Host "DEBUG: ClientId=$ClientId"
Write-Host "DEBUG: adh_group=$adh_group"
Write-Host "DEBUG: adh_subscription_type=$adh_subscription_type"
Write-Host "DEBUG: OutputDir=$OutputDir"
Write-Host "DEBUG: BranchName=$BranchName"

Ensure-Dir -Path $OutputDir | Out-Null

if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure connection failed."
}

# Use the shared subscription resolver from Common.psm1
$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
if ($subs -isnot [System.Collections.IEnumerable]) { $subs = ,$subs }

$overview = @()
$lsRows   = @()
$irRows   = @()

# Non-prd: dev/tst/stg workspaces; prd: only prd
$allowedEnvs = if ($adh_subscription_type -eq 'prd') { @('prd') } else { @('dev','tst','stg') }
$adfNames    = $allowedEnvs | ForEach-Object { "ADH-$adh_group-ADF-$_" }

foreach ($sub in $subs) {

    Set-ScContext -Subscription $sub

    $dfs = Get-AzDataFactoryV2 -ErrorAction SilentlyContinue |
           Where-Object { $adfNames -contains $_.Name }

    Write-Host ("DEBUG: Scanning subscription {0}; ADFs: {1}" -f
        $sub.Name, ($dfs | ForEach-Object Name -join ', '))

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
        $ls = Get-AzDataFactoryV2LinkedService `
                -ResourceGroupName $df.ResourceGroupName `
                -DataFactoryName   $df.Name `
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
        $irs = Get-AzDataFactoryV2IntegrationRuntime `
                 -ResourceGroupName $df.ResourceGroupName `
                 -DataFactoryName   $df.Name `
                 -ErrorAction SilentlyContinue

        foreach ($ir in $irs) {

            $computeDesc = $null
            if ($ir.Properties.AdditionalProperties -and
                $ir.Properties.AdditionalProperties.ClusterSize) {
                $computeDesc = $ir.Properties.AdditionalProperties.ClusterSize
            } elseif ($ir.Properties.Description) {
                $computeDesc = $ir.Properties.Description
            }

            $irRows += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $df.ResourceGroupName
                DataFactory      = $df.Name
                IRName           = $ir.Name
                IRType           = $ir.Properties.Type
                ComputeDesc      = $computeDesc
                State            = $ir.Properties.State
            }
        }
    }
}

# If no ADF at all, still emit one "Exists = No" row per sub
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

# Ensure we always have at least one LS / IR row (for empty subscriptions)
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

# -------- Output files --------
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
