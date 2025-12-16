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

function Write-RequiredPermissions {
    param(
        [string]$ScopeHint = "Subscription or Resource Group containing the Data Factory"
    )

    Write-Host ""
    Write-Host "================ PERMISSIONS REQUIRED ================" -ForegroundColor Yellow
    Write-Host "Your identity could not read Data Factory / Integration Runtime data."
    Write-Host "Grant ONE of the following (least privilege preferred) at: $ScopeHint"
    Write-Host ""
    Write-Host "Option A (recommended if available):" -ForegroundColor Yellow
    Write-Host "  - Data Factory Reader (or equivalent custom role allowing Microsoft.DataFactory/*/read)"
    Write-Host ""
    Write-Host "Option B:" -ForegroundColor Yellow
    Write-Host "  - Reader + explicit DataFactory read permissions (custom role)"
    Write-Host ""
    Write-Host "Option C (broad, not recommended):" -ForegroundColor Yellow
    Write-Host "  - Data Factory Contributor"
    Write-Host ""
    Write-Host "After the scan, remove the role assignment (use PIM/JIT if possible)." -ForegroundColor Yellow
    Write-Host "======================================================" -ForegroundColor Yellow
    Write-Host ""
}

function Is-AuthError([string]$msg) {
    if ([string]::IsNullOrWhiteSpace($msg)) { return $false }
    $m = $msg.ToLowerInvariant()
    return ($m -match "authorizationfailed" -or
            $m -match "does not have authorization" -or
            $m -match "insufficient privileges" -or
            $m -match "forbidden" -or
            $m -match "statuscode:\s*403" -or
            $m -match "permission")
}

Write-Host "DEBUG: TenantId              = $TenantId"
Write-Host "DEBUG: ClientId              = $ClientId"
Write-Host "DEBUG: adh_group             = $adh_group"
Write-Host "DEBUG: adh_subscription_type = $adh_subscription_type"
Write-Host "DEBUG: OutputDir             = $OutputDir"
Write-Host "DEBUG: BranchName            = $BranchName"

Ensure-Dir -Path $OutputDir | Out-Null

if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure connection failed."
}

# Make Azure CLI auth explicit (important for CLI fallback)
try {
    Write-Host "DEBUG: Logging into Azure CLI as SPN..."
    az login --service-principal -u $ClientId -p $ClientSecret --tenant $TenantId --only-show-errors | Out-Null
} catch {
    Write-Warning "DEBUG: Azure CLI login failed. CLI fallback may not work. Error: $($_.Exception.Message)"
}

# ----------------------------------------------------------------------
# Resolve subscription from adh_group + environment
# ----------------------------------------------------------------------
$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
if ($subs -isnot [System.Collections.IEnumerable]) { $subs = ,$subs }

$subNames = ($subs | Select-Object -ExpandProperty Name) -join ', '
Write-Host "DEBUG: Resolved adh_group='$adh_group' env='$adh_subscription_type' -> subscriptions: $subNames"

$overview = @()
$lsRows   = @()
$irRows   = @()

foreach ($sub in $subs) {

    Write-Host "DEBUG: Processing subscription $($sub.Name) ($($sub.Id))"

    try { Set-ScContext -Subscription $sub } catch {}
    try { Set-AzContext -SubscriptionId $sub.Id -Tenant $TenantId -ErrorAction Stop | Out-Null } catch {}

    # ----------------- Get ALL data factories (FAIL LOUD) -----------------
    $dfs = @()
    try {
        $dfs = @(Get-AzDataFactoryV2 -ErrorAction Stop)
    }
    catch {
        $msg = $_.Exception.Message
        Write-Host "ERROR: Cannot list Data Factories in subscription '$($sub.Name)'. $msg" -ForegroundColor Red
        if (Is-AuthError $msg) {
            Write-RequiredPermissions -ScopeHint "Subscription '$($sub.Name)' or RG hosting the Data Factory"
        }
        throw
    }

    Write-Host "DEBUG: DataFactories found in $($sub.Name) = $($dfs.Count)"

    if ($dfs.Count -eq 0) {
        Write-Host "DEBUG: No DataFactories found in $($sub.Name)"
        continue
    }

    foreach ($df in $dfs) {

        # Determine ADF Name safely
        $dfName = $null
        if ($df.PSObject.Properties.Match('DataFactoryName').Count -gt 0 -and $df.DataFactoryName) { $dfName = $df.DataFactoryName }
        elseif ($df.PSObject.Properties.Match('FactoryName').Count -gt 0 -and $df.FactoryName) { $dfName = $df.FactoryName }
        elseif ($df.PSObject.Properties.Match('Name').Count -gt 0 -and $df.Name) { $dfName = $df.Name }

        if ([string]::IsNullOrWhiteSpace($dfName)) {
            Write-Warning "DEBUG: ADF object has no detectable name; skipping."
            continue
        }

        # Overview row
        $overview += [pscustomobject]@{
            SubscriptionName = $sub.Name
            SubscriptionId   = $sub.Id
            ResourceGroup    = $df.ResourceGroupName
            DataFactory      = $dfName
            Exists           = 'Yes'
            Location         = $df.Location
        }

        # ----------------- Linked services -----------------
        $ls = @()
        try {
            $ls = @(Get-AzDataFactoryV2LinkedService `
                    -ResourceGroupName $df.ResourceGroupName `
                    -DataFactoryName   $dfName `
                    -ErrorAction Stop)
        }
        catch {
            $msg = $_.Exception.Message
            Write-Host "ERROR: Cannot list Linked Services for ADF '$dfName' RG '$($df.ResourceGroupName)'. $msg" -ForegroundColor Red
            if (Is-AuthError $msg) {
                Write-RequiredPermissions -ScopeHint "RG '$($df.ResourceGroupName)' (Data Factory scope)"
            }
            # Do not stop entire scan; keep going
            $ls = @()
        }

        # Dedup by name
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

        # ----------------- Integration runtimes (PS + CLI fallback) -----------------
        $irs = @()
        $usedCliFallback = $false

        try {
            $irs = @(Get-AzDataFactoryV2IntegrationRuntime `
                        -ResourceGroupName $df.ResourceGroupName `
                        -DataFactoryName   $dfName `
                        -ErrorAction Stop)
        }
        catch {
            $msg = $_.Exception.Message
            Write-Host "WARN: PS IR list failed for ADF '$dfName' RG '$($df.ResourceGroupName)'. $msg" -ForegroundColor Yellow
            $irs = @()
        }

        if ($irs.Count -eq 0) {
            # CLI fallback list
            try {
                $usedCliFallback = $true
                az account set --subscription $sub.Id --only-show-errors | Out-Null

                $cliListJson = az datafactory integration-runtime list `
                    --resource-group "$($df.ResourceGroupName)" `
                    --factory-name "$dfName" `
                    --only-show-errors -o json

                $cliIrs = @()
                if (-not [string]::IsNullOrWhiteSpace($cliListJson)) {
                    $cliIrs = @($cliListJson | ConvertFrom-Json)
                }

                $irs = $cliIrs | ForEach-Object {
                    [pscustomobject]@{
                        Name       = $_.name
                        Type       = $_.properties.type
                        Properties = $_.properties
                    }
                }
            }
            catch {
                $msg = $_.Exception.Message
                Write-Host "ERROR: CLI IR list failed for ADF '$dfName' RG '$($df.ResourceGroupName)'. $msg" -ForegroundColor Red
                if (Is-AuthError $msg) {
                    Write-RequiredPermissions -ScopeHint "RG '$($df.ResourceGroupName)' (Data Factory scope)"
                }
                $irs = @()
            }
        }

        Write-Host "DEBUG: ADF '$dfName' -> IR count: $($irs.Count) (CLI fallback: $usedCliFallback)"

        foreach ($ir in $irs) {

            $irType = if ($ir.Type) { $ir.Type } elseif ($ir.Properties -and $ir.Properties.Type) { $ir.Properties.Type } else { "Unknown" }

            $computeDesc = ""
            if ($ir.Properties) {
                if ($ir.Properties.Description) { $computeDesc = [string]$ir.Properties.Description }
                elseif ($ir.Properties.AdditionalProperties -and $ir.Properties.AdditionalProperties.ClusterSize) {
                    $computeDesc = [string]$ir.Properties.AdditionalProperties.ClusterSize
                }
            }

            # Status: PS first; else CLI show
            $status = ""
            $statusFetched = $false

            try {
                $irStatus = Get-AzDataFactoryV2IntegrationRuntimeStatus `
                                -ResourceGroupName $df.ResourceGroupName `
                                -DataFactoryName   $dfName `
                                -Name              $ir.Name `
                                -ErrorAction Stop

                if ($irStatus.Status) { $status = [string]$irStatus.Status }
                elseif ($irStatus.State) { $status = [string]$irStatus.State }
                else { $status = "Unknown" }

                $statusFetched = $true
            }
            catch {
                # CLI show fallback
                try {
                    az account set --subscription $sub.Id --only-show-errors | Out-Null

                    $cliShowJson = az datafactory integration-runtime show `
                        --resource-group "$($df.ResourceGroupName)" `
                        --factory-name "$dfName" `
                        --name "$($ir.Name)" `
                        --only-show-errors -o json

                    if (-not [string]::IsNullOrWhiteSpace($cliShowJson)) {
                        $cliShow = $cliShowJson | ConvertFrom-Json
                        if ($cliShow.properties.state) { $status = [string]$cliShow.properties.state }
                        elseif ($cliShow.properties.status) { $status = [string]$cliShow.properties.status }
                        else { $status = "Unknown" }
                        $statusFetched = $true
                    }
                }
                catch {
                    $status = "Not Found"
                }
            }

            if (-not $statusFetched -and [string]::IsNullOrWhiteSpace($status)) { $status = "Unknown" }

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

# ----------------------------------------------------------------------
# If no ADFs were found at all, still emit one "Exists = No" per sub
# ----------------------------------------------------------------------
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

# Ensure LS / IR CSVs always have at least one row with correct columns
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

# ----------------------------------------------------------------------
# Output CSV + HTML
# ----------------------------------------------------------------------
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
