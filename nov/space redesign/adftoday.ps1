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

function Write-DebugLine([string]$msg) { Write-Host "DEBUG: $msg" }

function Ensure-AzCli {
    try { az --version | Out-Null } catch { throw "Azure CLI (az) not found on agent." }
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
    if ($df.PSObject.Properties.Match('DataFactoryName').Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($df.DataFactoryName)) { return $df.DataFactoryName }
    if ($df.PSObject.Properties.Match('FactoryName').Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($df.FactoryName)) { return $df.FactoryName }
    if ($df.PSObject.Properties.Match('Name').Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($df.Name)) { return $df.Name }
    return $null
}

function Get-LinkedServicesAz {
    param([string]$rg,[string]$dfName)
    try { return @(Get-AzDataFactoryV2LinkedService -ResourceGroupName $rg -DataFactoryName $dfName -ErrorAction Stop) } catch { return @() }
}

function Get-LinkedServicesCli {
    param([string]$rg,[string]$dfName)
    try {
        $json = az datafactory linked-service list --resource-group $rg --factory-name $dfName -o json --only-show-errors
        if ([string]::IsNullOrWhiteSpace($json)) { return @() }
        return ($json | ConvertFrom-Json)
    } catch { return @() }
}

function Get-IntegrationRuntimesCli {
    param([string]$rg,[string]$dfName)
    try {
        $json = az datafactory integration-runtime list --resource-group $rg --factory-name $dfName -o json --only-show-errors
        if ([string]::IsNullOrWhiteSpace($json)) { return @() }
        return ($json | ConvertFrom-Json)
    } catch { return @() }
}

# ✅ NEW: portal-like status per IR
function Get-IntegrationRuntimeStatusCli {
    param([string]$rg,[string]$dfName,[string]$irName)

    # get-status usually returns an object with "properties" that includes a status/state
    try {
        $json = az datafactory integration-runtime get-status `
            --resource-group $rg `
            --factory-name $dfName `
            --integration-runtime-name $irName `
            -o json --only-show-errors

        if ([string]::IsNullOrWhiteSpace($json)) { return "Unknown" }

        $obj = $json | ConvertFrom-Json

        # Different shapes exist; handle common ones safely:
        if ($obj.properties) {
            if ($obj.properties.state)  { return [string]$obj.properties.state }
            if ($obj.properties.status) { return [string]$obj.properties.status }
        }
        if ($obj.state)  { return [string]$obj.state }
        if ($obj.status) { return [string]$obj.status }

        return "Unknown"
    } catch {
        # When IR exists only in Git (not published), ADF portal shows Not Found
        $m = $_.Exception.Message
        if ($m -match 'NotFound|not found|404') { return "NotFound" }
        return "Unknown"
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

$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
if ($subs -isnot [System.Collections.IEnumerable]) { $subs = ,$subs }

$overview = @()
$lsRows   = @()
$irRows   = @()

foreach ($sub in $subs) {

    Write-DebugLine "Processing subscription $($sub.Name) ($($sub.Id))"
    Set-ContextBoth -Sub $sub -TenantId $TenantId

    $dfs = @()
    try { $dfs = @(Get-AzDataFactoryV2 -ErrorAction Stop) } catch { $dfs = @() }

    if (@($dfs).Count -eq 0) {
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

    foreach ($df in $dfs) {

        $dfName = Safe-ADFName -df $df
        $rg     = [string]$df.ResourceGroupName
        $loc    = [string]$df.Location

        if ([string]::IsNullOrWhiteSpace($dfName) -or [string]::IsNullOrWhiteSpace($rg)) { continue }

        $overview += [pscustomobject]@{
            SubscriptionName = $sub.Name
            SubscriptionId   = $sub.Id
            ResourceGroup    = $rg
            DataFactory      = $dfName
            Exists           = 'Yes'
            Location         = $loc
        }

        # -------- Linked Services (Az then CLI fallback) --------
        $ls = Get-LinkedServicesAz -rg $rg -dfName $dfName
        if (@($ls).Count -eq 0) {
            $lsCli = Get-LinkedServicesCli -rg $rg -dfName $dfName
            if (@($lsCli).Count -gt 0) {
                foreach ($l in $lsCli) {
                    $typeName = ""
                    if ($l.properties -and $l.properties.type) { $typeName = [string]$l.properties.type }
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
        } else {
            $ls = $ls | Group-Object Name | ForEach-Object { $_.Group | Select-Object -First 1 }
            foreach ($l in $ls) {
                $lsType = $null
                if ($l.Properties -and $l.Properties.Type) { $lsType = $l.Properties.Type }
                elseif ($l.Type) { $lsType = $l.Type }
                elseif ($l.Properties) { $lsType = $l.Properties.GetType().Name }
                if (-not $lsType) { $lsType = "Unknown" }

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

        # -------- Integration Runtimes (CLI list + CLI get-status) --------
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

                $irType = ""
                if ($ir.properties -and $ir.properties.type) { $irType = [string]$ir.properties.type }
                if ([string]::IsNullOrWhiteSpace($irType)) { $irType = "Unknown" }

                # ✅ actual portal-like status
                $status = Get-IntegrationRuntimeStatusCli -rg $rg -dfName $dfName -irName $irName

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

# Always emit at least one row
if (-not $lsRows) {
    foreach ($sub in $subs) {
        $lsRows += [pscustomobject]@{
            SubscriptionName = $sub.Name; ResourceGroup=''; DataFactory=''; LinkedService=''; Type=''; Status=''; ErrorMessage=''
        }
    }
}
if (-not $irRows) {
    foreach ($sub in $subs) {
        $irRows += [pscustomobject]@{
            SubscriptionName = $sub.Name; ResourceGroup=''; DataFactory=''; IRName=''; IRType=''; Status=''; ErrorMessage=''
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
