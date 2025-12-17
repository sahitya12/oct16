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

function Ensure-RowLS([string]$subName,[string]$rg,[string]$df,[string]$ls,[string]$type,[string]$status,[string]$err) {
    [pscustomobject]@{
        SubscriptionName = $subName
        ResourceGroup    = $rg
        DataFactory      = $df
        LinkedService    = $ls
        Type             = $type
        Status           = $status
        Error            = $err
    }
}

function Ensure-RowIR([string]$subName,[string]$rg,[string]$df,[string]$ir,[string]$type,[string]$compute,[string]$status,[string]$err) {
    [pscustomobject]@{
        SubscriptionName = $subName
        ResourceGroup    = $rg
        DataFactory      = $df
        IRName           = $ir
        IRType           = $type
        ComputeDesc      = $compute
        Status           = $status
        Error            = $err
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
    throw "Azure connection failed."
}

# CLI login for getStatus (portal-like IR status)
try {
    az login --service-principal -u $ClientId -p $ClientSecret --tenant $TenantId --only-show-errors | Out-Null
} catch {
    throw "Azure CLI login failed: $($_.Exception.Message)"
}

# ----------------------------------------------------------------------
# Resolve subscriptions
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
    Set-ScContext -Subscription $sub
    try { Set-AzContext -SubscriptionId $sub.Id -Tenant $TenantId -ErrorAction Stop | Out-Null } catch {}
    try { az account set --subscription $sub.Id --only-show-errors | Out-Null } catch {}

    # Get ALL data factories in this subscription
    $dfs = @(Get-AzDataFactoryV2 -ErrorAction SilentlyContinue)

    if ($dfs.Count -eq 0) {
        Write-Host "DEBUG: No DataFactories found in $($sub.Name)"
        continue
    }

    Write-Host "DEBUG: Found $($dfs.Count) DataFactory instance(s) in $($sub.Name)"

    foreach ($df in $dfs) {

        # Determine ADF name safely
        $dfName = $null
        if ($df.PSObject.Properties.Match('DataFactoryName').Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($df.DataFactoryName)) {
            $dfName = $df.DataFactoryName
        } elseif ($df.PSObject.Properties.Match('FactoryName').Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($df.FactoryName)) {
            $dfName = $df.FactoryName
        } elseif ($df.PSObject.Properties.Match('Name').Count -gt 0) {
            $dfName = $df.Name
        }

        if ([string]::IsNullOrWhiteSpace($dfName)) {
            Write-Warning "DEBUG: ADF object has no detectable name. Skipping. Raw: `n$($df | Out-String)"
            continue
        }

        $rg = $df.ResourceGroupName

        # ----------------- Overview row -----------------
        $overview += [pscustomobject]@{
            SubscriptionName = $sub.Name
            SubscriptionId   = $sub.Id
            ResourceGroup    = $rg
            DataFactory      = $dfName
            Exists           = 'Yes'
            Location         = $df.Location
        }

        # ==========================================================
        # LINKED SERVICES (add ERROR rows so dev won't disappear)
        # ==========================================================
        try {
            $ls = @(Get-AzDataFactoryV2LinkedService -ResourceGroupName $rg -DataFactoryName $dfName -ErrorAction Stop)

            if ($ls.Count -eq 0) {
                $lsRows += Ensure-RowLS $sub.Name $rg $dfName '' '' 'OK' 'No linked services returned'
            } else {
                foreach ($l in $ls) {
                    $lsType = $null
                    if ($l.Properties -and $l.Properties.Type) { $lsType = $l.Properties.Type }
                    elseif ($l.Type) { $lsType = $l.Type }
                    elseif ($l.Properties) { $lsType = $l.Properties.GetType().Name }
                    if (-not $lsType) { $lsType = 'Unknown' }

                    $lsRows += Ensure-RowLS $sub.Name $rg $dfName $l.Name $lsType 'OK' ''
                }
            }
        }
        catch {
            $lsRows += Ensure-RowLS $sub.Name $rg $dfName '' '' 'ERROR' $_.Exception.Message
        }

        # ==========================================================
        # INTEGRATION RUNTIMES + STATUS (portal-like via getStatus)
        # ==========================================================
        try {
            $irs = @(Get-AzDataFactoryV2IntegrationRuntime -ResourceGroupName $rg -DataFactoryName $dfName -ErrorAction Stop)

            if ($irs.Count -eq 0) {
                $irRows += Ensure-RowIR $sub.Name $rg $dfName '' '' '' 'OK' 'No integration runtimes returned'
            } else {

                foreach ($ir in $irs) {

                    $irName = $ir.Name

                    $irType = $null
                    if ($ir.Properties -and $ir.Properties.Type) { $irType = $ir.Properties.Type }
                    elseif ($ir.Type) { $irType = $ir.Type }
                    if (-not $irType) { $irType = 'Unknown' }

                    $computeDesc = ''
                    if ($ir.Properties -and $ir.Properties.Description) { $computeDesc = [string]$ir.Properties.Description }

                    # getStatus via ARM REST (most accurate for SHIR “Not Found / Online / Offline”)
                    $status = 'Unknown'
                    $statusErr = ''

                    $uri = "https://management.azure.com/subscriptions/$($sub.Id)/resourceGroups/$rg/providers/Microsoft.DataFactory/factories/$dfName/integrationruntimes/$irName/getStatus?api-version=2018-06-01"

                    try {
                        $statusJson = az rest --method post --uri $uri -o json --only-show-errors | ConvertFrom-Json
                        if ($statusJson -and $statusJson.properties -and $statusJson.properties.state) {
                            $status = [string]$statusJson.properties.state
                        } else {
                            $status = 'Unknown'
                        }
                    }
                    catch {
                        # If SHIR is deleted / not registered, ARM often throws -> map to Not Found
                        $status = 'Not Found'
                        $statusErr = $_.Exception.Message
                    }

                    $irRows += Ensure-RowIR $sub.Name $rg $dfName $irName $irType $computeDesc $status $statusErr
                }
            }
        }
        catch {
            $irRows += Ensure-RowIR $sub.Name $rg $dfName '' '' '' 'ERROR' $_.Exception.Message
        }
    }
}

# Fallback rows so CSV headers always appear
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
if (-not $lsRows) { $lsRows += Ensure-RowLS '' '' '' '' '' '' '' }
if (-not $irRows) { $irRows += Ensure-RowIR '' '' '' '' '' '' '' '' }

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
