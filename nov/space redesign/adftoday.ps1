# sanitychecks/scripts/Scan-DataFactory.ps1

[CmdletBinding()]
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

# -----------------------------
# Helpers
# -----------------------------
function Write-DebugLine([string]$msg) { Write-Host "DEBUG: $msg" }

function Ensure-AzCli {
    try {
        az --version | Out-Null
    } catch {
        throw "Azure CLI (az) not found on agent. Install Azure CLI on the agent to fetch IR Status."
    }
}

function Ensure-AzCliLogin {
    param([string]$TenantId,[string]$ClientId,[string]$ClientSecret)

    try {
        az login --service-principal -u $ClientId -p $ClientSecret --tenant $TenantId --only-show-errors | Out-Null
        return $true
    } catch {
        Write-Warning "Azure CLI login failed. IR status may be missing. Error: $($_.Exception.Message)"
        return $false
    }
}

function Set-ContextBoth {
    param([object]$Sub,[string]$TenantId)

    try { Set-ScContext -Subscription $Sub } catch {}
    try { Set-AzContext -SubscriptionId $Sub.Id -Tenant $TenantId -ErrorAction Stop | Out-Null } catch {}
    try { az account set --subscription $Sub.Id --only-show-errors | Out-Null } catch {}
}

function Safe-ADFName {
    param($df)
    $dfName = $null

    if ($df.PSObject.Properties.Match('DataFactoryName').Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($df.DataFactoryName)) {
        $dfName = $df.DataFactoryName
    } elseif ($df.PSObject.Properties.Match('FactoryName').Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($df.FactoryName)) {
        $dfName = $df.FactoryName
    } elseif ($df.PSObject.Properties.Match('Name').Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($df.Name)) {
        $dfName = $df.Name
    }

    return $dfName
}

function Get-LinkedServicesAz {
    param([string]$rg,[string]$dfName)
    try {
        $ls = @(Get-AzDataFactoryV2LinkedService -ResourceGroupName $rg -DataFactoryName $dfName -ErrorAction Stop)
        return $ls
    } catch {
        return @()
    }
}

function Get-LinkedServicesCli {
    param([string]$rg,[string]$dfName)
    try {
        $json = az datafactory linked-service list --resource-group $rg --factory-name $dfName -o json --only-show-errors
        if ([string]::IsNullOrWhiteSpace($json)) { return @() }
        return ($json | ConvertFrom-Json)
    } catch {
        return @()
    }
}

function Get-IntegrationRuntimesCli {
    param([string]$rg,[string]$dfName)

    # CLI gives portal-like "state" and includes AutoResolveIntegrationRuntime
    try {
        $json = az datafactory integration-runtime list --resource-group $rg --factory-name $dfName -o json --only-show-errors
        if ([string]::IsNullOrWhiteSpace($json)) { return @() }
        return ($json | ConvertFrom-Json)
    } catch {
        return @()
    }
}

# -----------------------------
# Start
# -----------------------------
Write-DebugLine "TenantId              = $TenantId"
Write-DebugLine "ClientId              = $ClientId"
Write-DebugLine "adh_group             = $adh_group"
Write-DebugLine "adh_subscription_type = $adh_subscription_type"
Write-DebugLine "OutputDir             = $OutputDir"
Write-DebugLine "BranchName            = $BranchName"

Ensure-Dir -Path $OutputDir | Out-Null

if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure login failed."
}

Ensure-AzCli
$cliLoggedIn = Ensure-AzCliLogin -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret

# Resolve subscriptions
$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
if ($subs -isnot [System.Collections.IEnumerable]) { $subs = ,$subs }

$subNames = ($subs | Select-Object -ExpandProperty Name) -join ', '
Write-DebugLine "Resolved adh_group='$adh_group' env='$adh_subscription_type' -> subscriptions: $subNames"

# Output rows
$overview = @()
$lsRows   = @()
$irRows   = @()

foreach ($sub in $subs) {

    Write-DebugLine "Processing subscription $($sub.Name) ($($sub.Id))"
    Set-ContextBoth -Sub $sub -TenantId $TenantId

    # Get ALL ADFs
    $dfs = @()
    try {
        $dfs = @(Get-AzDataFactoryV2 -ErrorAction Stop)
    } catch {
        Write-Warning "Failed to list Data Factories in subscription '$($sub.Name)': $($_.Exception.Message)"
        $dfs = @()
    }

    if (@($dfs).Count -eq 0) {
        Write-DebugLine "No DataFactories found in $($sub.Name)"
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

    Write-DebugLine "Found $(@($dfs).Count) DataFactory instance(s) in $($sub.Name)"

    foreach ($df in $dfs) {

        $dfName = Safe-ADFName -df $df
        $rg     = [string]$df.ResourceGroupName
        $loc    = [string]$df.Location

        if ([string]::IsNullOrWhiteSpace($dfName) -or [string]::IsNullOrWhiteSpace($rg)) {
            Write-Warning "ADF object missing name/RG in subscription '$($sub.Name)'. Raw:`n$($df | Out-String)"
            continue
        }

        # ---- Overview ----
        $overview += [pscustomobject]@{
            SubscriptionName = $sub.Name
            SubscriptionId   = $sub.Id
            ResourceGroup    = $rg
            DataFactory      = $dfName
            Exists           = 'Yes'
            Location         = $loc
        }

        # ---- Linked Services (Az first, then CLI fallback) ----
        $ls = Get-LinkedServicesAz -rg $rg -dfName $dfName

        if (@($ls).Count -eq 0) {
            # fallback to CLI
            $lsCli = Get-LinkedServicesCli -rg $rg -dfName $dfName

            if (@($lsCli).Count -gt 0) {
                foreach ($l in $lsCli) {
                    $typeName = $null
                    if ($l.properties -and $l.properties.type) { $typeName = [string]$l.properties.type }
                    if ([string]::IsNullOrWhiteSpace($typeName) -and $l.properties) {
                        $typeName = [string]$l.properties.GetType().Name
                    }
                    if ([string]::IsNullOrWhiteSpace($typeName)) { $typeName = "Unknown" }

                    $lsRows += [pscustomobject]@{
                        SubscriptionName = $sub.Name
                        ResourceGroup    = $rg
                        DataFactory      = $dfName
                        LinkedService    = [string]$l.name
                        Type             = $typeName
                        Status           = 'OK'
                        ErrorMessage     = ''
                    }
                }
            } else {
                $lsRows += [pscustomobject]@{
                    SubscriptionName = $sub.Name
                    ResourceGroup    = $rg
                    DataFactory      = $dfName
                    LinkedService    = ''
                    Type             = ''
                    Status           = 'OK'
                    ErrorMessage     = 'No linked services returned'
                }
            }
        }
        else {
            # Deduplicate by Name
            $ls = $ls | Group-Object Name | ForEach-Object { $_.Group | Select-Object -First 1 }

            foreach ($l in $ls) {
                $lsType = $null

                if ($l.PSObject.Properties.Match('Properties').Count -gt 0 -and $l.Properties) {
                    if ($l.Properties.PSObject.Properties.Match('Type').Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($l.Properties.Type)) {
                        $lsType = $l.Properties.Type
                    }
                }
                if (-not $lsType -and $l.PSObject.Properties.Match('Type').Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($l.Type)) {
                    $lsType = $l.Type
                }
                if (-not $lsType -and $l.Properties) {
                    $lsType = $l.Properties.GetType().Name
                }
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

        # ---- Integration Runtimes (CLI - includes AutoResolve + status) ----
        if (-not $cliLoggedIn) {
            $irRows += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $rg
                DataFactory      = $dfName
                IRName           = ''
                IRType           = ''
                Status           = ''
                ErrorMessage     = 'Azure CLI login failed; IR status not collected'
            }
            continue
        }

        $irsCli = Get-IntegrationRuntimesCli -rg $rg -dfName $dfName

        if (@($irsCli).Count -eq 0) {
            $irRows += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $rg
                DataFactory      = $dfName
                IRName           = ''
                IRType           = ''
                Status           = ''
                ErrorMessage     = 'No integration runtimes returned'
            }
        } else {
            foreach ($ir in $irsCli) {
                $irName = [string]$ir.name

                $irType = ''
                if ($ir.properties -and $ir.properties.type) { $irType = [string]$ir.properties.type }
                if ([string]::IsNullOrWhiteSpace($irType) -and $ir.properties -and $ir.properties.typeProperties -and $ir.properties.typeProperties.subtype) {
                    $irType = [string]$ir.properties.typeProperties.subtype
                }
                if ([string]::IsNullOrWhiteSpace($irType)) { $irType = 'Unknown' }

                # state is what you want for portal-like column: Running / NotFound / etc.
                $status = ''
                if ($ir.properties -and $ir.properties.state) { $status = [string]$ir.properties.state }
                if ([string]::IsNullOrWhiteSpace($status)) { $status = 'Unknown' }

                $irRows += [pscustomobject]@{
                    SubscriptionName = $sub.Name
                    ResourceGroup    = $rg
                    DataFactory      = $dfName
                    IRName           = $irName
                    IRType           = $irType
                    Status           = $status
                    ErrorMessage     = ''
                }
            }
        }
    }
}

# Ensure at least one row exists in LS/IR outputs
if (-not $lsRows) {
    foreach ($sub in $subs) {
        $lsRows += [pscustomobject]@{
            SubscriptionName = $sub.Name
            ResourceGroup    = ''
            DataFactory      = ''
            LinkedService    = ''
            Type             = ''
            Status           = ''
            ErrorMessage     = ''
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
            ErrorMessage     = ''
        }
    }
}

# Output
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
