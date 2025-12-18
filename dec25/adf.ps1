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

# ------------------------------------------------------------
# Helper: Count linked services using a given IR (connectVia)
# ------------------------------------------------------------
function Get-IRRelatedCount {
    param(
        [Parameter(Mandatory)][array]$LinkedServices,
        [Parameter(Mandatory)][string]$IrName
    )
    $count = 0
    foreach ($ls in $LinkedServices) {
        try {
            $cv = $ls.Properties.connectVia
            if ($cv -and $cv.referenceName -and $cv.referenceName -eq $IrName) {
                $count++
            }
        } catch {}
    }
    return $count
}

# ------------------------------------------------------------
# Connect
# ------------------------------------------------------------
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure connection failed."
}

# ------------------------------------------------------------
# Resolve subscription from adh_group + environment
# ------------------------------------------------------------
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

        # ----------------- Determine DataFactory name safely -------------
        $dfName = $null

        if ($df.PSObject.Properties.Match('DataFactoryName').Count -gt 0 -and
            -not [string]::IsNullOrWhiteSpace($df.DataFactoryName)) {
            $dfName = $df.DataFactoryName
        }
        elseif ($df.PSObject.Properties.Match('FactoryName').Count -gt 0 -and
                -not [string]::IsNullOrWhiteSpace($df.FactoryName)) {
            $dfName = $df.FactoryName
        }
        elseif ($df.PSObject.Properties.Match('Name').Count -gt 0 -and
                -not [string]::IsNullOrWhiteSpace($df.Name)) {
            $dfName = $df.Name
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

            $lsType = $null

            if ($l.PSObject.Properties.Match('Properties').Count -gt 0 -and $l.Properties) {
                if ($l.Properties.PSObject.Properties.Match('Type').Count -gt 0 -and
                    -not [string]::IsNullOrWhiteSpace($l.Properties.Type)) {
                    $lsType = $l.Properties.Type
                }
            }

            if (-not $lsType -and
                $l.PSObject.Properties.Match('Type').Count -gt 0 -and
                -not [string]::IsNullOrWhiteSpace($l.Type)) {
                $lsType = $l.Type
            }

            if (-not $lsType -and $l.Properties) {
                $lsType = $l.Properties.GetType().Name
            }

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

            # Basic IR type from ADF API
            $rawType = $null
            try {
                if ($ir.Properties -and $ir.Properties.PSObject.Properties.Match('Type').Count -gt 0) {
                    $rawType = $ir.Properties.Type
                }
            } catch {}

            # Map into portal-like Type/SubType
            $portalType    = 'Unknown'
            $portalSubType = 'Unknown'

            switch ($rawType) {
                'Managed' {
                    $portalType = 'Azure'
                    $portalSubType = 'Public'
                }
                'SelfHosted' {
                    $portalType = 'SelfHosted'
                    $portalSubType = 'Self-Hosted'
                }
                'AzureSSIS' {
                    $portalType = 'Azure'
                    $portalSubType = 'SSIS'
                }
                default {
                    if ($ir.Name -eq 'AutoResolveIntegrationRuntime') {
                        $portalType = 'Azure'
                        $portalSubType = 'Public'
                    }
                }
            }

            # Detect Managed VNet IR (portal shows "Managed Virtual Network")
            try {
                $tp = $ir.Properties.TypeProperties
                if ($tp) {
                    if ($tp.PSObject.Properties.Match('VNetProperties').Count -gt 0 -and $tp.VNetProperties) {
                        $portalSubType = 'Managed Virtual Network'
                    }
                    elseif ($tp.PSObject.Properties.Match('VnetProperties').Count -gt 0 -and $tp.VnetProperties) {
                        $portalSubType = 'Managed Virtual Network'
                    }
                    elseif ($tp.PSObject.Properties.Match('ManagedVirtualNetwork').Count -gt 0 -and $tp.ManagedVirtualNetwork) {
                        $portalSubType = 'Managed Virtual Network'
                    }
                }

                if ($ir.Properties -and $ir.Properties.AdditionalProperties) {
                    if ($ir.Properties.AdditionalProperties.ManagedVirtualNetwork -or
                        $ir.Properties.AdditionalProperties.VNetProperties -or
                        $ir.Properties.AdditionalProperties.VnetProperties) {
                        $portalSubType = 'Managed Virtual Network'
                    }
                }
            } catch {}

            # Region (portal column)
            $region = ''
            try {
                if ($ir.Name -eq 'AutoResolveIntegrationRuntime') {
                    $region = 'Auto Resolve'
                }
                elseif ($ir.Location) {
                    $region = $ir.Location
                }
                elseif ($ir.Properties -and $ir.Properties.TypeProperties -and $ir.Properties.TypeProperties.Location) {
                    $region = $ir.Properties.TypeProperties.Location
                }
            } catch {}

            # Status + Version from IR Status API
            $statusText = 'Unknown'
            $version    = ''

            try {
                $st = Get-AzDataFactoryV2IntegrationRuntimeStatus `
                        -ResourceGroupName $df.ResourceGroupName `
                        -DataFactoryName   $dfName `
                        -Name              $ir.Name `
                        -ErrorAction Stop

                if ($st -and $st.Properties -and $st.Properties.State) {
                    $statusText = $st.Properties.State
                }

                if ($st -and $st.Properties -and $st.Properties.Version) {
                    $version = $st.Properties.Version
                }
                elseif ($st -and $st.Properties -and $st.Properties.Nodes) {
                    $versions = @()
                    foreach ($n in $st.Properties.Nodes) {
                        if ($n.Version) { $versions += $n.Version }
                    }
                    if ($versions.Count -gt 0) { $version = ($versions | Select-Object -Unique) -join ';' }
                }
            }
            catch {
                Write-Warning "DEBUG: IR status fetch failed for IR '$($ir.Name)' in ADF '$dfName': $($_.Exception.Message)"
            }

            # Related count (linked services using this IR)
            $relatedCount = 0
            try {
                $relatedCount = Get-IRRelatedCount -LinkedServices $ls -IrName $ir.Name
            } catch {}

            $irRows += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $df.ResourceGroupName
                DataFactory      = $dfName
                IRName           = $ir.Name
                IRType           = $portalType
                IRSubType        = $portalSubType
                Status           = $statusText
                Region           = $region
                Version          = $version
                RelatedCount     = $relatedCount
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
            IRSubType        = ''
            Status           = ''
            Region           = ''
            Version          = ''
            RelatedCount     = ''
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
