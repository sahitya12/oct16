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
Ensure-Dir -Path $OutputDir | Out-Null

Write-Host "DEBUG: TenantId              = $TenantId"
Write-Host "DEBUG: ClientId              = $ClientId"
Write-Host "DEBUG: adh_group             = $adh_group"
Write-Host "DEBUG: adh_subscription_type = $adh_subscription_type"
Write-Host "DEBUG: OutputDir             = $OutputDir"
Write-Host "DEBUG: BranchName            = $BranchName"

# ---------------- Helpers ----------------
function Get-PropValue {
    param([object]$Obj, [string[]]$Paths)

    foreach ($p in $Paths) {
        try {
            $cur = $Obj
            foreach ($seg in $p.Split('.')) {
                if ($null -eq $cur) { break }
                if ($cur -is [System.Collections.IDictionary]) {
                    $cur = $cur[$seg]
                } else {
                    $prop = $cur.PSObject.Properties[$seg]
                    $cur = if ($prop) { $prop.Value } else { $null }
                }
            }
            if ($null -ne $cur -and -not [string]::IsNullOrWhiteSpace([string]$cur)) {
                return $cur
            }
        } catch {}
    }
    return $null
}

function Get-ExpectedAdfTargets {
    param(
        [Parameter(Mandatory)][string]$adh_group,
        [Parameter(Mandatory)][ValidateSet('nonprd','prd')][string]$adh_subscription_type
    )

    $gUpper = $adh_group.Trim().ToUpper()
    $gLower = $adh_group.Trim().ToLower()
    $envs = if ($adh_subscription_type -eq 'prd') { @('prd') } else { @('dev','tst','stg') }

    foreach ($env in $envs) {
        $e = $env.ToLower()
        [pscustomobject]@{
            Env           = $e
            DataFactory   = "ADH-$gUpper-ADF-$e"
            ResourceGroup = ("adh_{0}_adf_{1}" -f $gLower, $e)
        }
    }
}

function Map-LSTypeToPortal {
    param([string]$lsType)

    switch -Regex ($lsType) {
        'AzureKeyVault'          { return 'Azure Key Vault' }
        'AzureDatabricks'        { return 'Azure Databricks' }
        'AzureBlobFS'            { return 'Azure Data Lake Storage Gen2' }
        'AzureBlobStorage'       { return 'Azure Blob Storage' }
        '^Http'                  { return 'HTTP' }
        default                  { return $lsType }
    }
}

function Get-LSRelatedCount {
    param(
        [Parameter(Mandatory)][array]$Datasets,
        [Parameter(Mandatory)][array]$Pipelines,
        [Parameter(Mandatory)][string]$LinkedServiceName
    )

    $count = 0

    # (A) Datasets -> Linked Service
    foreach ($ds in $Datasets) {
        $ref = Get-PropValue -Obj $ds -Paths @(
            'Properties.LinkedServiceName.ReferenceName',
            'Properties.linkedServiceName.referenceName',
            'Properties.linkedServiceName.ReferenceName',
            'Properties.LinkedServiceName.referenceName'
        )
        if ($ref -and ($ref.ToString() -eq $LinkedServiceName)) { $count++ }
    }

    # (B) Pipeline activities -> Linked Service (closer to Portal "Related")
    foreach ($pl in $Pipelines) {
        $acts = Get-PropValue -Obj $pl -Paths @('Properties.Activities','properties.activities')
        if (-not $acts) { continue }
        foreach ($a in $acts) {
            $lsRef = Get-PropValue -Obj $a -Paths @(
                'LinkedServiceName.ReferenceName',
                'linkedServiceName.referenceName',
                'linkedServiceName.ReferenceName',
                'typeProperties.linkedServiceName.referenceName',
                'typeProperties.linkedServiceName.ReferenceName'
            )
            if ($lsRef -and ($lsRef.ToString() -eq $LinkedServiceName)) { $count++ }
        }
    }

    return $count
}

function Get-IRRelatedCount {
    param([array]$LinkedServices, [string]$IrName)

    $count = 0
    foreach ($ls in $LinkedServices) {
        $ref = Get-PropValue -Obj $ls -Paths @(
            'Properties.connectVia.referenceName',
            'Properties.connectVia.ReferenceName',
            'Properties.ConnectVia.referenceName',
            'Properties.ConnectVia.ReferenceName',
            'Properties.additionalProperties.connectVia.referenceName',
            'Properties.AdditionalProperties.connectVia.referenceName'
        )
        if ($ref -and ($ref.ToString() -eq $IrName)) { $count++ }
    }
    return $count
}

function Get-IRPortalTypeSubType {
    param([object]$Ir)

    if ($Ir.Name -eq 'AutoResolveIntegrationRuntime') {
        return @('Azure','Public')
    }

    $rawType = Get-PropValue -Obj $Ir -Paths @('Properties.Type','Properties.type','Type','type')

    $portalType = 'Azure'
    $portalSub  = 'Public'

    if ($rawType) {
        switch -Regex ($rawType.ToString()) {
            '^SelfHosted$' { return @('SelfHosted','Self-Hosted') }
            '^Managed$'    { $portalType='Azure'; $portalSub='Public' }
            '^AzureSSIS$'   { return @('Azure','SSIS') }
            default        { $portalType='Azure'; $portalSub='Public' }
        }
    }

    # Managed VNet detection (shape varies)
    $mvnet = Get-PropValue -Obj $Ir -Paths @(
        'Properties.TypeProperties.VNetProperties',
        'Properties.TypeProperties.VnetProperties',
        'Properties.TypeProperties.ManagedVirtualNetwork',
        'Properties.typeProperties.vNetProperties',
        'Properties.typeProperties.managedVirtualNetwork',
        'Properties.AdditionalProperties.ManagedVirtualNetwork',
        'Properties.additionalProperties.managedVirtualNetwork'
    )
    if ($mvnet) { $portalSub = 'Managed Virtual Network' }

    # Name heuristic (your case)
    if ($Ir.Name -match 'managed-vnet|managedvnet') { $portalSub = 'Managed Virtual Network' }

    return @($portalType,$portalSub)
}

function Get-IRStatusAndVersion {
    param(
        [string]$Rg,
        [string]$DfName,
        [string]$IrName
    )

    $status  = 'Unknown'
    $version = '---'

    try {
        $st = Get-AzDataFactoryV2IntegrationRuntimeStatus `
                -ResourceGroupName $Rg `
                -DataFactoryName $DfName `
                -Name $IrName `
                -ErrorAction Stop

        $statusVal = Get-PropValue -Obj $st -Paths @(
            'Properties.State','Properties.state',
            'Properties.Status','Properties.status',
            'Status','status'
        )
        if ($statusVal) { $status = $statusVal.ToString() }

        $verVal = Get-PropValue -Obj $st -Paths @('Properties.Version','Properties.version','Version','version')
        if ($verVal) {
            $version = $verVal.ToString()
        } else {
            $nodes = Get-PropValue -Obj $st -Paths @('Properties.Nodes','Properties.nodes')
            if ($nodes) {
                $vers = @()
                foreach ($n in $nodes) {
                    $v = Get-PropValue -Obj $n -Paths @('Version','version')
                    if ($v) { $vers += $v.ToString() }
                }
                if ($vers.Count -gt 0) { $version = (($vers | Select-Object -Unique) -join ';') }
            }
        }
    } catch {
        # keep Unknown/---
    }

    return @($status,$version)
}

# ---------------- Connect ----------------
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure connection failed."
}

# ---------------- Subscriptions ----------------
$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
if ($subs -isnot [System.Collections.IEnumerable]) { $subs = ,$subs }
Write-Host "DEBUG: Subscriptions: $((($subs | Select-Object -ExpandProperty Name) -join ', '))"

# ---------------- Output rows ----------------
$overview = @()
$lsRows   = @()
$irRows   = @()

foreach ($sub in $subs) {
    Set-ScContext -Subscription $sub
    Write-Host "`n=== ADF scan: $($sub.Name) / $($sub.Id) ===" -ForegroundColor Cyan

    $targets = Get-ExpectedAdfTargets -adh_group $adh_group -adh_subscription_type $adh_subscription_type

    foreach ($t in $targets) {

        $dfName = $t.DataFactory
        $rgName = $t.ResourceGroup

        # ADF exists?
        $df = $null
        try {
            $df = Get-AzDataFactoryV2 -ResourceGroupName $rgName -Name $dfName -ErrorAction Stop
        } catch { $df = $null }

        if (-not $df) {
            Write-Host "DEBUG: Expected ADF NOT found: $dfName in RG $rgName" -ForegroundColor Yellow
            $overview += [pscustomobject]@{
                SubscriptionName = $sub.Name
                SubscriptionId   = $sub.Id
                ResourceGroup    = $rgName
                DataFactory      = $dfName
                Exists           = 'No'
                Location         = ''
            }
            continue
        }

        # Overview
        $overview += [pscustomobject]@{
            SubscriptionName = $sub.Name
            SubscriptionId   = $sub.Id
            ResourceGroup    = $rgName
            DataFactory      = $dfName
            Exists           = 'Yes'
            Location         = $df.Location
        }

        # Linked services
        $ls = @()
        try {
            $ls = Get-AzDataFactoryV2LinkedService -ResourceGroupName $rgName -DataFactoryName $dfName -ErrorAction Stop
        } catch { $ls = @() }

        # Datasets (for LS related)
        $datasets = @()
        try {
            $datasets = Get-AzDataFactoryV2Dataset -ResourceGroupName $rgName -DataFactoryName $dfName -ErrorAction Stop
        } catch { $datasets = @() }

        # Pipelines (for LS related)
        $pipelines = @()
        try {
            $pipelines = Get-AzDataFactoryV2Pipeline -ResourceGroupName $rgName -DataFactoryName $dfName -ErrorAction Stop
        } catch { $pipelines = @() }

        foreach ($l in $ls) {
            $rawType = Get-PropValue -Obj $l -Paths @('Properties.Type','Type')
            if (-not $rawType -and $l.Properties) { $rawType = $l.Properties.GetType().Name }
            if (-not $rawType) { $rawType = 'Unknown' }

            $portalType = Map-LSTypeToPortal -lsType ($rawType.ToString())
            $related = Get-LSRelatedCount -Datasets $datasets -Pipelines $pipelines -LinkedServiceName $l.Name

            # ✅ Portal-like: keep only ones actually used
            if ($related -le 0) { continue }

            $lsRows += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $rgName
                DataFactory      = $dfName
                LinkedService    = $l.Name
                Type             = $portalType
                RelatedCount     = $related
            }
        }

        # Integration runtimes
        $irs = @()
        try {
            $irs = Get-AzDataFactoryV2IntegrationRuntime -ResourceGroupName $rgName -DataFactoryName $dfName -ErrorAction Stop
        } catch { $irs = @() }

        foreach ($ir in $irs) {

            $ts = Get-IRPortalTypeSubType -Ir $ir
            $portalType    = $ts[0]
            $portalSubType = $ts[1]

            $region = ''
            if ($ir.Name -eq 'AutoResolveIntegrationRuntime') {
                $region = 'Auto Resolve'
            } else {
                $region = Get-PropValue -Obj $ir -Paths @(
                    'Location','location',
                    'Properties.TypeProperties.Location',
                    'Properties.typeProperties.location'
                )
                if (-not $region) { $region = '' }
            }

            $sv = Get-IRStatusAndVersion -Rg $rgName -DfName $dfName -IrName $ir.Name
            $status  = $sv[0]
            $version = $sv[1]

            $relatedCount = Get-IRRelatedCount -LinkedServices $ls -IrName $ir.Name

            # ✅ Do NOT filter IRs out (so you always see them)
            $irRows += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $rgName
                DataFactory      = $dfName
                IRName           = $ir.Name
                IRType           = $portalType
                IRSubType        = $portalSubType
                Status           = $status
                RelatedCount     = $relatedCount
                Region           = $region
                Version          = $version
            }
        }
    }
}

# ---------------- Ensure at least one row in each CSV ----------------
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

if (-not $lsRows) {
    foreach ($sub in $subs) {
        $lsRows += [pscustomobject]@{
            SubscriptionName = $sub.Name
            ResourceGroup    = ''
            DataFactory      = ''
            LinkedService    = ''
            Type             = ''
            RelatedCount     = ''
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
            RelatedCount     = ''
            Region           = ''
            Version          = ''
        }
    }
}

# ---------------- Output CSVs ONLY (no HTML) ----------------
$csv1 = New-StampedPath -BaseDir $OutputDir -Prefix ("adf_overview_{0}_{1}" -f $adh_group, $adh_subscription_type)
Write-CsvSafe -Rows $overview -Path $csv1

$csv2 = New-StampedPath -BaseDir $OutputDir -Prefix ("adf_linkedservices_{0}_{1}" -f $adh_group, $adh_subscription_type)
Write-CsvSafe -Rows $lsRows -Path $csv2

$csv3 = New-StampedPath -BaseDir $OutputDir -Prefix ("adf_integrationruntimes_{0}_{1}" -f $adh_group, $adh_subscription_type)
Write-CsvSafe -Rows $irRows -Path $csv3

Write-Host "`nADF scan completed." -ForegroundColor Green
Write-Host "Overview CSV : $csv1"
Write-Host "Linked Svc   : $csv2"
Write-Host "IRs          : $csv3"
