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
    throw "Azure connection failed."
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

    Write-Host "DEBUG: Processing subscription $($sub.Name)"

    Set-ScContext -Subscription $sub

    # Get ALL data factories in this subscription
    $dfs = Get-AzDataFactoryV2 -ErrorAction SilentlyContinue

    $adfCount = @($dfs).Count
    if ($adfCount -eq 0) {
        Write-Host "DEBUG: No DataFactories found in $($sub.Name)"
        continue
    } else {
        Write-Host "DEBUG: Found $adfCount DataFactory instance(s) in $($sub.Name)"
    }

    foreach ($df in $dfs) {

        # ----------------- Determine a safe DataFactory name -------------
        $dfName = $null

        if ($df.PSObject.Properties.Match('DataFactoryName').Count -gt 0 -and
            -not [string]::IsNullOrWhiteSpace($df.DataFactoryName)) {
            $dfName = $df.DataFactoryName
        }
        elseif ($df.PSObject.Properties.Match('FactoryName').Count -gt 0 -and
                -not [string]::IsNullOrWhiteSpace($df.FactoryName)) {
            $dfName = $df.FactoryName
        }
        else {
            # fall back to Name if it exists
            if ($df.PSObject.Properties.Match('Name').Count -gt 0) {
                $dfName = $df.Name
            }
        }

        if ([string]::IsNullOrWhiteSpace($dfName)) {
            Write-Warning "DEBUG: DataFactory object in subscription '$($sub.Name)' has no detectable name. Skipping. Raw object: `n$($df | Out-String)"
            continue
        }

        # ----------------- Overview row -----------------
        $overview += [pscustomobject]@{
            SubscriptionName = $sub.Name
            SubscriptionId   = $sub.Id
            ResourceGroup    = $df.ResourceGroupName
            DataFactory      = $dfName
            Exists           = 'Yes'
            Location         = $df.Location
        }

        # ----------------- Linked services --------------
        try {
            $ls = Get-AzDataFactoryV2LinkedService `
                    -ResourceGroupName $df.ResourceGroupName `
                    -DataFactoryName   $dfName `
                    -ErrorAction Stop
        }
        catch {
            Write-Warning "DEBUG: Failed to query Linked Services for ADF '$dfName' in RG '$($df.ResourceGroupName)': $($_.Exception.Message)"
            $ls = @()
        }

        foreach ($l in $ls) {

            # --- Robust Linked Service Type detection ---
            $lsType = $null

            # 1) Try the standard Properties.Type if it exists
            if ($l.Properties -and ($l.Properties.PSObject.Properties.Match('Type').Count -gt 0)) {
                $lsType = $l.Properties.Type
            }

            # 2) If still empty, derive from CLR type name (e.g. "AzureSqlDatabaseLinkedService")
            if ([string]::IsNullOrWhiteSpace($lsType) -and $l.Properties) {
                $rawTypeName = $l.Properties.GetType().Name   # e.g. Microsoft.Azure.Management.DataFactory.Models.AzureSqlDatabaseLinkedService
                # Strip namespace + common suffix to get something readable
                $short = ($rawTypeName -split '\.')[-1]       # AzureSqlDatabaseLinkedService
                $short = $short -replace 'LinkedService$',''  # AzureSqlDatabase
                $lsType = $short
            }

            # 3) Fallback to whole type name if everything else fails
            if ([string]::IsNullOrWhiteSpace($lsType) -and $l.Properties) {
                $lsType = $l.Properties.GetType().FullName
            }

            # --- Integration Runtime name (ConnectVia) if present ---
            $irName = $null
            if ($l.Properties -and $l.Properties.PSObject.Properties.Match('ConnectVia').Count -gt 0) {
                if ($l.Properties.ConnectVia -and $l.Properties.ConnectVia.PSObject.Properties.Match('ReferenceName').Count -gt 0) {
                    $irName = $l.Properties.ConnectVia.ReferenceName
                }
            }

            $lsRows += [pscustomobject]@{
                SubscriptionName   = $sub.Name
                ResourceGroup      = $df.ResourceGroupName
                DataFactory        = $dfName
                LinkedService      = $l.Name
                Type               = $lsType
                IntegrationRuntime = $irName
            }
        }

        # ----------------- Integration runtimes ---------
        try {
            $irs = Get-AzDataFactoryV2IntegrationRuntime `
                     -ResourceGroupName $df.ResourceGroupName `
                     -DataFactoryName   $dfName `
                     -ErrorAction Stop
        }
        catch {
            Write-Warning "DEBUG: Failed to query Integration Runtimes for ADF '$dfName' in RG '$($df.ResourceGroupName)': $($_.Exception.Message)"
            $irs = @()
        }

        foreach ($ir in $irs) {

            $computeDesc = $null
            if ($ir.Properties.AdditionalProperties -and
                $ir.Properties.AdditionalProperties.ClusterSize) {
                $computeDesc = $ir.Properties.AdditionalProperties.ClusterSize
            }
            elseif ($ir.Properties.Description) {
                $computeDesc = $ir.Properties.Description
            }

            $irRows += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $df.ResourceGroupName
                DataFactory      = $dfName
                IRName           = $ir.Name
                IRType           = $ir.Properties.Type
                ComputeDesc      = $computeDesc
                State            = $ir.Properties.State
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

# Ensure LS / IR CSVs always have at least one row
if (-not $lsRows) {
    foreach ($sub in $subs) {
        $lsRows += [pscustomobject]@{
            SubscriptionName   = $sub.Name
            ResourceGroup      = ''
            DataFactory        = ''
            LinkedService      = ''
            Type               = ''
            IntegrationRuntime = ''
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
