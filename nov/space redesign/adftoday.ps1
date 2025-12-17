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

Ensure-Dir -Path $OutputDir | Out-Null

function To-OneString($v) {
    if ($null -eq $v) { return "" }
    if ($v -is [System.Array]) {
        return [string]($v | Select-Object -First 1)
    }
    return [string]$v
}

# ---------------- AUTH ----------------
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure login failed."
}

# Azure CLI login (needed for IR status)
try {
    az login --service-principal -u $ClientId -p $ClientSecret --tenant $TenantId --only-show-errors | Out-Null
} catch {
    Write-Warning "Azure CLI login failed; IR status may be missing. Error: $($_.Exception.Message)"
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

    # ------------------------------------------------------
    # Discover ADFs via Resource Graph (but normalize output)
    # ------------------------------------------------------
    $adfs = @()
    try {
        $query = @"
resources
| where type =~ 'microsoft.datafactory/factories'
| project name, resourceGroup, location
"@
        $adfs = @(Search-AzGraph -Query $query -Subscription $sub.Id -First 1000 -ErrorAction Stop)
    } catch {
        throw "Failed to list ADFs via Resource Graph in subscription $($sub.Name): $($_.Exception.Message)"
    }

    if (-not $adfs -or $adfs.Count -eq 0) {
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

    foreach ($df in $adfs) {

        # Normalize to string (avoid System.Object[])
        $dfName = To-OneString $df.name
        $rgName = To-OneString $df.resourceGroup
        $loc    = To-OneString $df.location

        if ([string]::IsNullOrWhiteSpace($dfName) -or [string]::IsNullOrWhiteSpace($rgName)) {
            Write-Warning "Skipping ADF row due to missing name/RG. Raw: $($df | Out-String)"
            continue
        }

        # ---------------- OVERVIEW ----------------
        $overview += [pscustomobject]@{
            SubscriptionName = $sub.Name
            SubscriptionId   = $sub.Id
            ResourceGroup    = $rgName
            DataFactory      = $dfName
            Exists           = 'Yes'
            Location         = $loc
        }

        # ---------------- LINKED SERVICES (with error row) ----------------
        try {
            $ls = @(Get-AzDataFactoryV2LinkedService -ResourceGroupName $rgName -DataFactoryName $dfName -ErrorAction Stop)

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

            if ($ls.Count -eq 0) {
                $lsRows += [pscustomobject]@{
                    SubscriptionName = $sub.Name
                    ResourceGroup    = $rgName
                    DataFactory      = $dfName
                    LinkedService    = ''
                    Type             = ''
                    Status           = 'OK'
                    Error            = 'No linked services found'
                }
            }

        } catch {
            $lsRows += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $rgName
                DataFactory      = $dfName
                LinkedService    = ''
                Type             = ''
                Status           = 'ERROR'
                Error            = $_.Exception.Message
            }
        }

        # ---------------- IRs (with status) ----------------
        try {
            $irs = @(Get-AzDataFactoryV2IntegrationRuntime -ResourceGroupName $rgName -DataFactoryName $dfName -ErrorAction Stop)

            foreach ($ir in $irs) {

                $irType = $null
                if ($ir.Properties -and $ir.Properties.Type) { $irType = $ir.Properties.Type }
                elseif ($ir.Type) { $irType = $ir.Type }
                if (-not $irType) { $irType = "Unknown" }

                $computeDesc = ""
                if ($ir.Properties -and $ir.Properties.Description) { $computeDesc = [string]$ir.Properties.Description }

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

            if ($irs.Count -eq 0) {
                $irRows += [pscustomobject]@{
                    SubscriptionName = $sub.Name
                    ResourceGroup    = $rgName
                    DataFactory      = $dfName
                    IRName           = ''
                    IRType           = ''
                    ComputeDesc      = ''
                    Status           = 'OK'
                    Error            = 'No integration runtimes found'
                }
            }

        } catch {
            $irRows += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $rgName
                DataFactory      = $dfName
                IRName           = ''
                IRType           = ''
                ComputeDesc      = ''
                Status           = 'ERROR'
                Error            = $_.Exception.Message
            }
        }
    }
}

# Ensure headers
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
