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

# -------------------------------------------------------
# Helpers
# -------------------------------------------------------
function New-ErrorRow([string]$subName, [string]$rg, [string]$df, [string]$area, [string]$msg) {
    return [pscustomobject]@{
        SubscriptionName = $subName
        ResourceGroup    = $rg
        DataFactory      = $df
        Area             = $area
        Status           = 'ERROR'
        Error            = $msg
    }
}

Write-Host "DEBUG: TenantId              = $TenantId"
Write-Host "DEBUG: ClientId              = $ClientId"
Write-Host "DEBUG: adh_group             = $adh_group"
Write-Host "DEBUG: adh_subscription_type = $adh_subscription_type"
Write-Host "DEBUG: OutputDir             = $OutputDir"
Write-Host "DEBUG: BranchName            = $BranchName"

Ensure-Dir -Path $OutputDir | Out-Null

# ---------------- AUTH (Az) ----------------
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure connection failed."
}

# ---------------- AUTH (CLI) ----------------
$cliAvailable = $false
try {
    az --version | Out-Null
    $cliAvailable = $true
} catch {
    $cliAvailable = $false
    Write-Warning "Azure CLI not available on agent. IR Status may be limited."
}

if ($cliAvailable) {
    try {
        az login --service-principal -u $ClientId -p $ClientSecret --tenant $TenantId --only-show-errors | Out-Null
    } catch {
        Write-Warning "Azure CLI login failed; IR status may be missing. Error: $($_.Exception.Message)"
    }
}

# ---------------- RESOLVE SUBS ----------------
$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
if ($subs -isnot [System.Collections.IEnumerable]) { $subs = ,$subs }

$subNames = ($subs | Select-Object -ExpandProperty Name) -join ', '
Write-Host "DEBUG: Resolved adh_group='$adh_group' env='$adh_subscription_type' -> subscriptions: $subNames"

# ---------------- OUTPUT BUFFERS ----------------
$overview = @()
$lsRows   = @()
$irRows   = @()

foreach ($sub in $subs) {

    Write-Host "DEBUG: Processing subscription $($sub.Name) ($($sub.Id))"

    # Context for your helper module + Az + CLI
    Set-ScContext -Subscription $sub
    try { Set-AzContext -SubscriptionId $sub.Id -Tenant $TenantId -ErrorAction Stop | Out-Null } catch {}

    if ($cliAvailable) {
        try { az account set --subscription $sub.Id --only-show-errors | Out-Null } catch {}
    }

    # ---------------- List Data Factories ----------------
    $dfs = @()
    try {
        $dfs = @(Get-AzDataFactoryV2 -ErrorAction Stop)
    } catch {
        # Permission issue at subscription scope
        $overview += [pscustomobject]@{
            SubscriptionName = $sub.Name
            SubscriptionId   = $sub.Id
            ResourceGroup    = ''
            DataFactory      = ''
            Exists           = 'ERROR'
            Location         = ''
            Error            = "Cannot list Data Factories. Grant 'Data Factory Reader' at RG/ADF scope. Details: $($_.Exception.Message)"
        }
        continue
    }

    if (@($dfs).Count -eq 0) {
        # No ADFs found - still add overview row
        $overview += [pscustomobject]@{
            SubscriptionName = $sub.Name
            SubscriptionId   = $sub.Id
            ResourceGroup    = ''
            DataFactory      = ''
            Exists           = 'No'
            Location         = ''
            Error            = ''
        }
        continue
    }

    foreach ($df in $dfs) {

        # Resolve DF name robustly
        $dfName = $null
        if ($df.PSObject.Properties.Match('DataFactoryName').Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($df.DataFactoryName)) {
            $dfName = $df.DataFactoryName
        } elseif ($df.PSObject.Properties.Match('FactoryName').Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($df.FactoryName)) {
            $dfName = $df.FactoryName
        } elseif ($df.PSObject.Properties.Match('Name').Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($df.Name)) {
            $dfName = $df.Name
        }

        if ([string]::IsNullOrWhiteSpace($dfName)) {
            Write-Warning "Skipping ADF with no detectable name. Raw: $($df | Out-String)"
            continue
        }

        $rg = [string]$df.ResourceGroupName

        # ---------------- Overview row ----------------
        $overview += [pscustomobject]@{
            SubscriptionName = $sub.Name
            SubscriptionId   = $sub.Id
            ResourceGroup    = $rg
            DataFactory      = $dfName
            Exists           = 'Yes'
            Location         = $df.Location
            Error            = ''
        }

        # ============================================================
        # LINKED SERVICES
        # ============================================================
        $ls = @()
        try {
            $ls = @(Get-AzDataFactoryV2LinkedService `
                    -ResourceGroupName $rg `
                    -DataFactoryName   $dfName `
                    -ErrorAction Stop)
        } catch {
            # If ADF exists but LS query fails, record a row so you see the failure in CSV
            $lsRows += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $rg
                DataFactory      = $dfName
                LinkedService    = ''
                Type             = ''
                Status           = 'ERROR'
                Error            = "Failed to query linked services: $($_.Exception.Message)"
            }
            $ls = @()
        }

        # Deduplicate by name (some environments return duplicates)
        $ls = $ls | Group-Object Name | ForEach-Object { $_.Group | Select-Object -First 1 }

        if (@($ls).Count -eq 0) {
            $lsRows += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $rg
                DataFactory      = $dfName
                LinkedService    = ''
                Type             = ''
                Status           = 'OK'
                Error            = 'No linked services returned'
            }
        } else {
            foreach ($l in $ls) {
                $lsType = $null
                if ($l.Properties -and $l.Properties.Type) { $lsType = [string]$l.Properties.Type }
                elseif ($l.Type) { $lsType = [string]$l.Type }
                elseif ($l.Properties) { $lsType = $l.Properties.GetType().Name }
                if (-not $lsType) { $lsType = 'Unknown' }

                $lsRows += [pscustomobject]@{
                    SubscriptionName = $sub.Name
                    ResourceGroup    = $rg
                    DataFactory      = $dfName
                    LinkedService    = $l.Name
                    Type             = $lsType
                    Status           = 'OK'
                    Error            = ''
                }
            }
        }

        # ============================================================
        # INTEGRATION RUNTIMES (include AutoResolve + Status Running/Not Found)
        # ============================================================
        $irsAz = @()
        try {
            $irsAz = @(Get-AzDataFactoryV2IntegrationRuntime `
                        -ResourceGroupName $rg `
                        -DataFactoryName   $dfName `
                        -ErrorAction Stop)
        } catch {
            $irsAz = @()
            $irRows += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $rg
                DataFactory      = $dfName
                IRName           = ''
                IRType           = ''
                Status           = 'ERROR'
                Error            = "Failed to query IRs via Az: $($_.Exception.Message)"
            }
        }

        # Map: IRName -> IRType (from Az)
        $irTypeMap = @{}
        foreach ($ir in $irsAz) {
            $t = $null
            if ($ir.Properties -and $ir.Properties.Type) { $t = [string]$ir.Properties.Type }
            elseif ($ir.Type) { $t = [string]$ir.Type }
            if (-not $t) { $t = "Unknown" }
            $irTypeMap[$ir.Name] = $t
        }

        # Map: IRName -> Status/state (from CLI, live/ARM)
        $irStateMap = @{}
        $cliError = $null

        if ($cliAvailable) {
            try {
                $cliIrList = az datafactory integration-runtime list `
                    --resource-group "$rg" `
                    --factory-name   "$dfName" `
                    -o json --only-show-errors | ConvertFrom-Json

                foreach ($x in $cliIrList) {
                    $name = [string]$x.name
                    $state = $null
                    try { $state = [string]$x.properties.state } catch {}
                    if ([string]::IsNullOrWhiteSpace($state)) { $state = "Unknown" }
                    $irStateMap[$name] = $state

                    # Also capture IR type from CLI if present
                    $ctype = $null
                    try { $ctype = [string]$x.properties.type } catch {}
                    if (-not [string]::IsNullOrWhiteSpace($ctype)) {
                        $irTypeMap[$name] = $ctype
                    }
                }
            } catch {
                $cliError = $_.Exception.Message
            }
        }

        # Union IR names (Az + CLI)
        $allIrNames = @()
        $allIrNames += @($irTypeMap.Keys)
        $allIrNames += @($irStateMap.Keys)
        $allIrNames = $allIrNames | Sort-Object -Unique

        if (-not $allIrNames -or $allIrNames.Count -eq 0) {
            $irRows += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $rg
                DataFactory      = $dfName
                IRName           = ''
                IRType           = ''
                Status           = 'ERROR'
                Error            = $(if ($cliError) { "CLI IR list failed: $cliError" } else { "No integration runtimes returned" })
            }
        } else {
            foreach ($irName in $allIrNames) {

                $type = $irTypeMap[$irName]
                if ([string]::IsNullOrWhiteSpace($type)) { $type = "Unknown" }

                # Status resolution:
                # - if in CLI list => live factory state
                # - else if only in Az list => Git/draft-only => Not Found
                # - else Unknown
                $status = $null
                $error  = ''

                if ($irStateMap.ContainsKey($irName)) {
                    $status = $irStateMap[$irName]
                }
                elseif ($irTypeMap.ContainsKey($irName)) {
                    $status = "Not Found"
                    $error  = "Exists in Git/draft but not in live (publish/deploy pending)"
                }
                else {
                    $status = "Unknown"
                }

                $irRows += [pscustomobject]@{
                    SubscriptionName = $sub.Name
                    ResourceGroup    = $rg
                    DataFactory      = $dfName
                    IRName           = $irName
                    IRType           = $type
                    Status           = $status
                    Error            = $error
                }
            }
        }
    }
}

# ----------------------------------------------------------------------
# Ensure non-empty outputs
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
            Error            = ''
        }
    }
}

if (-not $lsRows) {
    foreach ($sub in $subs) {
        $lsRows += [pscustomobject]@{
            SubscriptionName = $sub.Name
            ResourceGroup    = ''
            DataFactory      = ''
            LinkedService    = ''
            Type             = ''
            Status           = ''
            Error            = ''
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
            Status           = ''
            Error            = ''
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
