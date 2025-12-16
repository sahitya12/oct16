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

function Throw-PermissionError([string]$SubName) {
@"
❌ PERMISSION CHECK FAILED

The Service Principal does NOT have permission to read Azure Data Factory.

Grant temporarily (preferred):
• Role: Data Factory Reader
• Scope: Resource Group OR Data Factory resource

Subscription: $SubName

Then re-run the pipeline. Use PIM/JIT and remove after scan.
"@ | ForEach-Object { throw $_ }
}

Ensure-Dir -Path $OutputDir | Out-Null

# ---------------- AUTH ----------------
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure login failed."
}

# Azure CLI login (needed for IR status)
try {
    az login --service-principal -u $ClientId -p $ClientSecret --tenant $TenantId --only-show-errors | Out-Null
} catch {
    Write-Warning "Azure CLI login failed; IR status may be missing. Error: $($_.Exception.Message)"
}

# ---------------- RESOLVE SUBS ----------------
$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
if ($subs -isnot [System.Collections.IEnumerable]) { $subs = ,$subs }

$overview = @()
$lsRows   = @()
$irRows   = @()

foreach ($sub in $subs) {

    Write-Host "DEBUG: Processing subscription $($sub.Name) ($($sub.Id))"

    Set-ScContext -Subscription $sub
    try { Set-AzContext -SubscriptionId $sub.Id -Tenant $TenantId -ErrorAction Stop | Out-Null } catch {}
    try { az account set --subscription $sub.Id --only-show-errors | Out-Null } catch {}

    # ---------------- PERMISSION PRECHECK ----------------
    try {
        $testDf = Get-AzDataFactoryV2 -ErrorAction Stop | Select-Object -First 1
    } catch {
        Throw-PermissionError -SubName $sub.Name
    }

    # If subscription truly has no ADF, still continue but add overview "Exists=No"
    if (-not $testDf) {
        Write-Host "DEBUG: No Data Factories found in $($sub.Name)"
        $overview += [pscustomobject]@{
            SubscriptionName = $sub.Name
            SubscriptionId   = $sub.Id
            ResourceGroup    = ''
            DataFactory      = ''
            Exists           = 'No'
            Location         = ''
        }
        continue
    }

    $dfs = @(Get-AzDataFactoryV2 -ErrorAction Stop)
    Write-Host "DEBUG: ADF count in $($sub.Name) = $($dfs.Count)"

    foreach ($df in $dfs) {

        $dfName = $df.DataFactoryName
        if ([string]::IsNullOrWhiteSpace($dfName)) { $dfName = $df.FactoryName }
        if ([string]::IsNullOrWhiteSpace($dfName)) { $dfName = $df.Name }

        if ([string]::IsNullOrWhiteSpace($dfName)) {
            Write-Warning "ADF has no detectable name; skipping"
            continue
        }

        # ---------------- OVERVIEW ----------------
        $overview += [pscustomobject]@{
            SubscriptionName = $sub.Name
            SubscriptionId   = $sub.Id
            ResourceGroup    = $df.ResourceGroupName
            DataFactory      = $dfName
            Exists           = 'Yes'
            Location         = $df.Location
        }

        # ---------------- LINKED SERVICES ----------------
        $ls = @()
        try {
            $ls = @(Get-AzDataFactoryV2LinkedService `
                    -ResourceGroupName $df.ResourceGroupName `
                    -DataFactoryName   $dfName `
                    -ErrorAction Stop)
        } catch {
            Write-Warning "Failed to query Linked Services for ADF '$dfName' RG '$($df.ResourceGroupName)': $($_.Exception.Message)"
            $ls = @()
        }

        $ls = $ls | Group-Object Name | ForEach-Object { $_.Group | Select-Object -First 1 }

        foreach ($l in $ls) {
            $lsType = $null
            if ($l.Properties -and $l.Properties.Type) { $lsType = $l.Properties.Type }
            elseif ($l.Type) { $lsType = $l.Type }
            elseif ($l.Properties) { $lsType = $l.Properties.GetType().Name }
            if (-not $lsType) { $lsType = "Unknown" }

            $lsRows += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $df.ResourceGroupName
                DataFactory      = $dfName
                LinkedService    = $l.Name
                Type             = $lsType
            }
        }

        # ---------------- INTEGRATION RUNTIMES ----------------
        $irs = @()
        try {
            $irs = @(Get-AzDataFactoryV2IntegrationRuntime `
                        -ResourceGroupName $df.ResourceGroupName `
                        -DataFactoryName   $dfName `
                        -ErrorAction Stop)
        } catch {
            Write-Warning "Failed to query Integration Runtimes for ADF '$dfName' RG '$($df.ResourceGroupName)': $($_.Exception.Message)"
            $irs = @()
        }

        # IR Status from CLI (portal-like “Running / Not Found / Offline”)
        $irStatusMap = @{}
        try {
            $statusJson = az datafactory integration-runtime list `
                --resource-group "$($df.ResourceGroupName)" `
                --factory-name "$dfName" `
                -o json --only-show-errors | ConvertFrom-Json

            foreach ($s in $statusJson) {
                $irStatusMap[$s.name] = $s.properties.state
            }
        } catch {
            Write-Warning "CLI IR status list failed for ADF '$dfName': $($_.Exception.Message)"
        }

        foreach ($ir in $irs) {

            $irType = $null
            if ($ir.Properties -and $ir.Properties.Type) { $irType = $ir.Properties.Type }
            elseif ($ir.Type) { $irType = $ir.Type }
            if (-not $irType) { $irType = "Unknown" }

            $computeDesc = ""
            if ($ir.Properties -and $ir.Properties.Description) { $computeDesc = [string]$ir.Properties.Description }

            $status = $irStatusMap[$ir.Name]
            if ([string]::IsNullOrWhiteSpace($status)) { $status = "Unknown" }

            $irRows += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $df.ResourceGroupName
                DataFactory      = $dfName
                IRName           = $ir.Name
                IRType           = $irType
                ComputeDesc      = $computeDesc
                Status           = $status
            }
        }
    }
}

# Ensure outputs always have at least one row
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
            Status           = ''
        }
    }
}

# ---------------- OUTPUT ----------------
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
