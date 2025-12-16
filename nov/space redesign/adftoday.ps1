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
    $dfs = @(Get-AzDataFactoryV2 -ErrorAction SilentlyContinue)

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
        $ls = @()
        try {
            $ls = @(Get-AzDataFactoryV2LinkedService `
                    -ResourceGroupName $df.ResourceGroupName `
                    -DataFactoryName   $dfName `
                    -ErrorAction Stop)
        }
        catch {
            Write-Warning "DEBUG: Failed to query Linked Services for ADF '$dfName' in RG '$($df.ResourceGroupName)': $($_.Exception.Message)"
            $ls = @()
        }

        # Deduplicate by linked service name
        $ls = $ls | Group-Object Name | ForEach-Object { $_.Group | Select-Object -First 1 }

        Write-Host "DEBUG: ADF '$dfName' RG '$($df.ResourceGroupName)' -> LinkedServices: $(@($ls).Count)"

        foreach ($l in $ls) {

            # Try to resolve a useful Type for the linked service
            $lsType = $null

            # 1) Most common shape: .Properties.Type
            if ($l.PSObject.Properties.Match('Properties').Count -gt 0 -and $l.Properties) {
                if ($l.Properties.PSObject.Properties.Match('Type').Count -gt 0 -and
                    -not [string]::IsNullOrWhiteSpace($l.Properties.Type)) {
                    $lsType = $l.Properties.Type
                }
            }

            # 2) Some Az.DataFactory versions expose .Type directly
            if (-not $lsType -and
                $l.PSObject.Properties.Match('Type').Count -gt 0 -and
                -not [string]::IsNullOrWhiteSpace($l.Type)) {
                $lsType = $l.Type
            }

            # 3) Fallback: use the underlying .Properties .NET type name
            if (-not $lsType -and $l.Properties) {
                $lsType = $l.Properties.GetType().Name   # e.g. "AzureSqlDatabaseLinkedService"
            }

            # 4) Absolute fallback
            if (-not $lsType) { $lsType = 'Unknown' }

            $lsRows += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $df.ResourceGroupName
                DataFactory      = $dfName
                LinkedService    = $l.Name
                Type             = $lsType
            }
        }

        # ----------------- Integration runtimes ---------
        $irs = @()
        try {
            # IMPORTANT: Wrap in @() so single object becomes an array
            $irs = @(Get-AzDataFactoryV2IntegrationRuntime `
                     -ResourceGroupName $df.ResourceGroupName `
                     -DataFactoryName   $dfName `
                     -ErrorAction Stop)
        }
        catch {
            Write-Warning "DEBUG: Failed to query Integration Runtimes for ADF '$dfName' in RG '$($df.ResourceGroupName)': $($_.Exception.Message)"
            $irs = @()
        }

        Write-Host "DEBUG: ADF '$dfName' RG '$($df.ResourceGroupName)' -> IntegrationRuntimes: $(@($irs).Count)"

        foreach ($ir in $irs) {

            # IR Type
            $irType = $null
            if ($ir.PSObject.Properties.Match('Type').Count -gt 0 -and $ir.Type) {
                $irType = $ir.Type
            }
            elseif ($ir.Properties -and $ir.Properties.PSObject.Properties.Match('Type').Count -gt 0 -and $ir.Properties.Type) {
                $irType = $ir.Properties.Type
            }
            if ([string]::IsNullOrWhiteSpace($irType)) { $irType = "Unknown" }

            # Compute description (best-effort)
            $computeDesc = ""
            if ($ir.Properties) {
                if ($ir.Properties.Description) {
                    $computeDesc = [string]$ir.Properties.Description
                }
                elseif ($ir.Properties.AdditionalProperties -and $ir.Properties.AdditionalProperties.ClusterSize) {
                    $computeDesc = [string]$ir.Properties.AdditionalProperties.ClusterSize
                }
            }

            # Status (use Status cmdlet)
            $status = ""
            try {
                $irStatus = Get-AzDataFactoryV2IntegrationRuntimeStatus `
                                -ResourceGroupName $df.ResourceGroupName `
                                -DataFactoryName   $dfName `
                                -Name              $ir.Name `
                                -ErrorAction Stop

                if ($irStatus.PSObject.Properties.Match('Status').Count -gt 0 -and $irStatus.Status) {
                    $status = [string]$irStatus.Status
                }
                elseif ($irStatus.PSObject.Properties.Match('State').Count -gt 0 -and $irStatus.State) {
                    $status = [string]$irStatus.State
                }
                else {
                    $status = ($irStatus | Out-String).Trim()
                }
            }
            catch {
                $status = "Not Found"
            }

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
