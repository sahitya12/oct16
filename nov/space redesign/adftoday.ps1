param(
    [Parameter(Mandatory = $true)][string]$TenantId,
    [Parameter(Mandatory = $true)][string]$ClientId,
    [Parameter(Mandatory = $true)][string]$ClientSecret,
    [Parameter(Mandatory = $true)][string]$adh_group,
    [ValidateSet('nonprd','prd')][string]$adh_subscription_type = 'nonprd',
    [Parameter(Mandatory = $true)][string]$OutputDir,
    [string]$BranchName = ''
)

Import-Module Az.Accounts, Az.Resources, Az.DataFactory, Az.ResourceGraph -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

# ---------------- Helpers ----------------
function IsAuthError([string]$msg) {
    if ([string]::IsNullOrWhiteSpace($msg)) { return $false }
    $m = $msg.ToLowerInvariant()
    return ($m -match "authorizationfailed" -or
            $m -match "does not have authorization" -or
            $m -match "insufficient privileges" -or
            $m -match "forbidden" -or
            $m -match "statuscode:\s*403" -or
            $m -match "permission")
}

function Throw-PermissionError([string]$Context, [string]$Details) {
    throw @"
❌ PERMISSION / ACCESS ERROR ($Context)

$Details

Required (temporary, least privilege):
• Role: Data Factory Reader (or custom role allowing Microsoft.DataFactory/*/read)
• Scope: Resource Group containing the Data Factory OR the Data Factory resource

Then re-run pipeline. Use PIM/JIT and remove after scan.
"@
}

# ---------------- Setup ----------------
Write-Host "DEBUG: TenantId              = $TenantId"
Write-Host "DEBUG: ClientId              = $ClientId"
Write-Host "DEBUG: adh_group             = $adh_group"
Write-Host "DEBUG: adh_subscription_type = $adh_subscription_type"
Write-Host "DEBUG: OutputDir             = $OutputDir"
Write-Host "DEBUG: BranchName            = $BranchName"

Ensure-Dir -Path $OutputDir | Out-Null

# ---------------- AUTH ----------------
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure login failed."
}

# Azure CLI login (needed for IR Status)
try {
    az login --service-principal -u $ClientId -p $ClientSecret --tenant $TenantId --only-show-errors | Out-Null
} catch {
    Throw-PermissionError -Context "Azure CLI login" -Details $_.Exception.Message
}

# ---------------- Resolve subscriptions ----------------
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

    # ------------------------------------------------------
    # Discover ALL Data Factories via Resource Graph
    # (more consistent than Get-AzDataFactoryV2 in some RBAC setups)
    # ------------------------------------------------------
    $adfs = @()
    try {
        $query = @"
resources
| where type =~ 'microsoft.datafactory/factories'
| project id, name, resourceGroup, subscriptionId, location
"@
        $adfs = @(Search-AzGraph -Query $query -Subscription $sub.Id -First 1000 -ErrorAction Stop)
    }
    catch {
        $msg = $_.Exception.Message
        if (IsAuthError $msg) { Throw-PermissionError -Context "List factories via Resource Graph" -Details $msg }
        throw
    }

    if (-not $adfs -or $adfs.Count -eq 0) {
        Write-Host "DEBUG: No ADFs found in subscription $($sub.Name)"
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

    Write-Host "DEBUG: Found $($adfs.Count) ADF(s) via ARG in $($sub.Name)"

    foreach ($df in $adfs) {

        $rgName = $df.resourceGroup
        $dfName = $df.name

        # ---------------- OVERVIEW ----------------
        $overview += [pscustomobject]@{
            SubscriptionName = $sub.Name
            SubscriptionId   = $sub.Id
            ResourceGroup    = $rgName
            DataFactory      = $dfName
            Exists           = 'Yes'
            Location         = $df.location
        }

        # ======================================================
        # LINKED SERVICES (WITH STATUS + ERROR so Dev won't vanish)
        # ======================================================
        $ls = @()
        $lsError = $null
        try {
            $ls = @(Get-AzDataFactoryV2LinkedService `
                    -ResourceGroupName $rgName `
                    -DataFactoryName   $dfName `
                    -ErrorAction Stop)
        }
        catch {
            $lsError = $_.Exception.Message
            $ls = @()
        }

        if ($lsError) {
            # 1 row to show failure for that ADF
            $lsRows += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $rgName
                DataFactory      = $dfName
                LinkedService    = ''
                Type             = ''
                Status           = 'ERROR'
                Error            = $lsError
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
                    ResourceGroup    = $rgName
                    DataFactory      = $dfName
                    LinkedService    = $l.Name
                    Type             = $lsType
                    Status           = 'OK'
                    Error            = ''
                }
            }
        }

        # ======================================================
        # INTEGRATION RUNTIMES (WITH STATUS)
        # ======================================================
        $irs = @()
        $irListError = $null

        try {
            $irs = @(Get-AzDataFactoryV2IntegrationRuntime `
                    -ResourceGroupName $rgName `
                    -DataFactoryName   $dfName `
                    -ErrorAction Stop)
        }
        catch {
            $irListError = $_.Exception.Message
            $irs = @()
        }

        if ($irListError) {
            # 1 row to show failure for that ADF
            $irRows += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $rgName
                DataFactory      = $dfName
                IRName           = ''
                IRType           = ''
                ComputeDesc      = ''
                Status           = 'ERROR'
                Error            = $irListError
            }
        } else {

            foreach ($ir in $irs) {

                $irType = $null
                if ($ir.Properties -and $ir.Properties.Type) { $irType = $ir.Properties.Type }
                elseif ($ir.Type) { $irType = $ir.Type }
                if (-not $irType) { $irType = "Unknown" }

                $computeDesc = ""
                if ($ir.Properties -and $ir.Properties.Description) { $computeDesc = [string]$ir.Properties.Description }

                # CLI show per IR => best chance to match portal "Running / Not Found"
                $status = "Unknown"
                $statusErr = ""
                try {
                    $showJson = az datafactory integration-runtime show `
                        --resource-group "$rgName" `
                        --factory-name "$dfName" `
                        --name "$($ir.Name)" `
                        -o json --only-show-errors | ConvertFrom-Json

                    if ($showJson -and $showJson.properties -and $showJson.properties.state) {
                        $status = [string]$showJson.properties.state
                    }
                } catch {
                    $status = "Not Found"
                    $statusErr = $_.Exception.Message
                }

                $irRows += [pscustomobject]@{
                    SubscriptionName = $sub.Name
                    ResourceGroup    = $rgName
                    DataFactory      = $dfName
                    IRName           = $ir.Name
                    IRType           = $irType
                    ComputeDesc      = $computeDesc
                    Status           = $status
                    Error            = $statusErr
                }
            }
        }
    }
}

# Ensure headers exist even if lists empty
if (-not $lsRows) {
    $lsRows += [pscustomobject]@{
        SubscriptionName = ''
        ResourceGroup    = ''
        DataFactory      = ''
        LinkedService    = ''
        Type             = ''
        Status           = ''
        Error            = ''
    }
}
if (-not $irRows) {
    $irRows += [pscustomobject]@{
        SubscriptionName = ''
        ResourceGroup    = ''
        DataFactory      = ''
        IRName           = ''
        IRType           = ''
        ComputeDesc      = ''
        Status           = ''
        Error            = ''
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
