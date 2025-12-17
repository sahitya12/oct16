param(
    [Parameter(Mandatory = $true)][string]$TenantId,
    [Parameter(Mandatory = $true)][string]$ClientId,
    [Parameter(Mandatory = $true)][string]$ClientSecret,
    [Parameter(Mandatory = $true)][string]$adh_group,
    [ValidateSet('nonprd','prd')][string]$adh_subscription_type = 'nonprd',
    [Parameter(Mandatory = $true)][string]$OutputDir,
    [string]$BranchName = ''
)

Import-Module Az.Accounts, Az.Resources, Az.ResourceGraph -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

# ---------------- helpers ----------------
function To-OneString($v) {
    if ($null -eq $v) { return "" }
    if ($v -is [System.Array]) { return [string]($v | Select-Object -First 1) }
    return [string]$v
}

function Add-LSRow {
    param($subName, $rgName, $dfName, $lsName, $lsType, $status, $err)
    return [pscustomobject]@{
        SubscriptionName = $subName
        ResourceGroup    = $rgName
        DataFactory      = $dfName
        LinkedService    = $lsName
        Type             = $lsType
        Status           = $status
        Error            = $err
    }
}

function Add-IRRow {
    param($subName, $rgName, $dfName, $irName, $irType, $computeDesc, $status, $err)
    return [pscustomobject]@{
        SubscriptionName = $subName
        ResourceGroup    = $rgName
        DataFactory      = $dfName
        IRName           = $irName
        IRType           = $irType
        ComputeDesc      = $computeDesc
        Status           = $status
        Error            = $err
    }
}

Ensure-Dir -Path $OutputDir | Out-Null

Write-Host "DEBUG: TenantId              = $TenantId"
Write-Host "DEBUG: ClientId              = $ClientId"
Write-Host "DEBUG: adh_group             = $adh_group"
Write-Host "DEBUG: adh_subscription_type = $adh_subscription_type"
Write-Host "DEBUG: OutputDir             = $OutputDir"
Write-Host "DEBUG: BranchName            = $BranchName"

# ---------------- AUTH ----------------
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure login failed."
}

# Azure CLI login (needed for linked services / IR status)
try {
    az login --service-principal -u $ClientId -p $ClientSecret --tenant $TenantId --only-show-errors | Out-Null
} catch {
    throw "Azure CLI login failed: $($_.Exception.Message)"
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
    # Discover ADFs via Resource Graph
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
        Write-Host "DEBUG: No ADFs found in $($sub.Name)"
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

    Write-Host "DEBUG: Found $($adfs.Count) ADF(s) in $($sub.Name)"

    foreach ($df in $adfs) {

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

        # ======================================================
        # LINKED SERVICES via AZ CLI (reliable)
        # ======================================================
        try {
            $lsJson = az datafactory linked-service list `
                --resource-group "$rgName" `
                --factory-name "$dfName" `
                -o json --only-show-errors | ConvertFrom-Json

            if (-not $lsJson -or $lsJson.Count -eq 0) {
                $lsRows += Add-LSRow $sub.Name $rgName $dfName '' '' 'OK' 'No linked services returned by CLI'
            } else {
                foreach ($l in $lsJson) {
                    $lsType = To-OneString $l.properties.type
                    if ([string]::IsNullOrWhiteSpace($lsType)) { $lsType = 'Unknown' }

                    $lsRows += Add-LSRow $sub.Name $rgName $dfName (To-OneString $l.name) $lsType 'OK' ''
                }
            }
        } catch {
            $lsRows += Add-LSRow $sub.Name $rgName $dfName '' '' 'ERROR' $_.Exception.Message
        }

        # ======================================================
        # INTEGRATION RUNTIMES via AZ CLI (includes state)
        # ======================================================
        try {
            $irJson = az datafactory integration-runtime list `
                --resource-group "$rgName" `
                --factory-name "$dfName" `
                -o json --only-show-errors | ConvertFrom-Json

            if (-not $irJson -or $irJson.Count -eq 0) {
                $irRows += Add-IRRow $sub.Name $rgName $dfName '' '' '' 'OK' 'No integration runtimes returned by CLI'
            } else {
                foreach ($ir in $irJson) {
                    $irType = To-OneString $ir.properties.type
                    if ([string]::IsNullOrWhiteSpace($irType)) { $irType = 'Unknown' }

                    $state = To-OneString $ir.properties.state
                    if ([string]::IsNullOrWhiteSpace($state)) { $state = 'Unknown' }

                    $desc = To-OneString $ir.properties.description

                    $irRows += Add-IRRow $sub.Name $rgName $dfName (To-OneString $ir.name) $irType $desc $state ''
                }
            }
        } catch {
            $irRows += Add-IRRow $sub.Name $rgName $dfName '' '' '' 'ERROR' $_.Exception.Message
        }
    }
}

# Ensure headers even if empty
if (-not $lsRows) {
    $lsRows += Add-LSRow '' '' '' '' '' '' ''
}
if (-not $irRows) {
    $irRows += Add-IRRow '' '' '' '' '' '' '' ''
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
