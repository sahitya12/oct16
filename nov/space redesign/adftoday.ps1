param(
    [Parameter(Mandatory = $true)][string]$TenantId,
    [Parameter(Mandatory = $true)][string]$ClientId,
    [Parameter(Mandatory = $true)][string]$ClientSecret,
    [Parameter(Mandatory = $true)][string]$adh_group,
    [ValidateSet('nonprd','prd')][string]$adh_subscription_type = 'nonprd',
    [Parameter(Mandatory = $true)][string]$OutputDir,
    [string]$BranchName = ''
)

Import-Module Az.Accounts, Az.Resources, Az.ResourceGraph, Az.DataFactory -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

Ensure-Dir -Path $OutputDir | Out-Null

function Throw-PermissionError([string]$Context, [string]$Details) {
    throw @"
❌ PERMISSION / ACCESS ERROR ($Context)

$Details

Required (temporary, least privilege):
• Role: Data Factory Reader
• Scope: Resource Group containing the Data Factory OR the Data Factory resource

Then re-run pipeline. Use PIM/JIT and remove after scan.
"@
}

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

# ---------------- AUTH ----------------
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure login failed."
}

# Azure CLI login (needed for IR status)
try {
    az login --service-principal -u $ClientId -p $ClientSecret --tenant $TenantId --only-show-errors | Out-Null
} catch {
    Throw-PermissionError -Context "Azure CLI login" -Details $_.Exception.Message
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

    # ------------------------------------------------------------------
    # 1) Discover ALL Data Factories in subscription using Resource Graph
    #    (more reliable than Get-AzDataFactoryV2 for enterprise RBAC)
    # ------------------------------------------------------------------
    $adfRg = @()
    try {
        $q = @"
resources
| where type =~ 'microsoft.datafactory/factories'
| project id, name, resourceGroup, subscriptionId, location
"@
        $adfRg = Search-AzGraph -Query $q -Subscription $sub.Id -First 1000 -ErrorAction Stop
    }
    catch {
        $msg = $_.Exception.Message
        if (IsAuthError $msg) {
            Throw-PermissionError -Context "Resource Graph query (list factories)" -Details $msg
        }
        throw
    }

    if (-not $adfRg -or @($adfRg).Count -eq 0) {
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

    Write-Host "DEBUG: ADFs found via ARG in $($sub.Name) = $(@($adfRg).Count)"

    foreach ($df in $adfRg) {

        $dfName = $df.name
        $rgName = $df.resourceGroup

        # ---------------- OVERVIEW ----------------
        $overview += [pscustomobject]@{
            SubscriptionName = $sub.Name
            SubscriptionId   = $sub.Id
            ResourceGroup    = $rgName
            DataFactory      = $dfName
            Exists           = 'Yes'
            Location         = $df.location
        }

        # ---------------- LINKED SERVICES ----------------
        $ls = @()
        try {
            $ls = @(Get-AzDataFactoryV2LinkedService `
                    -ResourceGroupName $rgName `
                    -DataFactoryName   $dfName `
                    -ErrorAction Stop)
        } catch {
            $msg = $_.Exception.Message
            if (IsAuthError $msg) {
                Throw-PermissionError -Context "Get LinkedServices ($dfName / $rgName)" -Details $msg
            }
            Write-Warning "Failed LinkedServices for ADF '$dfName' RG '$rgName': $msg"
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
                ResourceGroup    = $rgName
                DataFactory      = $dfName
                LinkedService    = $l.Name
                Type             = $lsType
            }
        }

        # ---------------- INTEGRATION RUNTIMES ----------------
        $irs = @()
        try {
            $irs = @(Get-AzDataFactoryV2IntegrationRuntime `
                        -ResourceGroupName $rgName `
                        -DataFactoryName   $dfName `
                        -ErrorAction Stop)
        } catch {
            $msg = $_.Exception.Message
            if (IsAuthError $msg) {
                Throw-PermissionError -Context "Get IntegrationRuntimes ($dfName / $rgName)" -Details $msg
            }
            Write-Warning "Failed IR list for ADF '$dfName' RG '$rgName': $msg"
            $irs = @()
        }

        foreach ($ir in $irs) {

            $irType = $null
            if ($ir.Properties -and $ir.Properties.Type) { $irType = $ir.Properties.Type }
            elseif ($ir.Type) { $irType = $ir.Type }
            if (-not $irType) { $irType = "Unknown" }

            $computeDesc = ""
            if ($ir.Properties -and $ir.Properties.Description) { $computeDesc = [string]$ir.Properties.Description }

            # IR Status: use CLI show per IR (most reliable)
            $status = "Unknown"
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
                # For SHIR agents you may see "Not Found" in portal; keep it informative
                $status = "Not Found"
            }

            $irRows += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $rgName
                DataFactory      = $dfName
                IRName           = $ir.Name
                IRType           = $irType
                ComputeDesc      = $computeDesc
                Status           = $status
            }
        }
    }
}

# Ensure LS / IR outputs always have correct headers even if empty
if (-not $lsRows) {
    $lsRows += [pscustomobject]@{
        SubscriptionName = ''
        ResourceGroup    = ''
        DataFactory      = ''
        LinkedService    = ''
        Type             = ''
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
