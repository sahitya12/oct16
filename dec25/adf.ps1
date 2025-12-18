# sanitychecks/scripts/Scan-DataFactory.ps1
# CSV ONLY (no HTML) + RBAC auto-grant (Data Factory Contributor)
#
# Naming convention:
#   ADF  : ADH-<adh_group>-ADF-<env>
#   RG   : adh_<adh_group>_adf_<env>
# envs:
#   nonprd => dev,tst,stg
#   prd    => prd
#
# Notes:
# - Az.DataFactory cmdlets read PUBLISHED artifacts (management plane).
#   If your portal is showing a Git branch (e.g., "develop branch"), publish first.
# - IR Status requires Data Factory Contributor (or Contributor) on the ADF RG.

param(
    [Parameter(Mandatory = $true)][string]$TenantId,
    [Parameter(Mandatory = $true)][string]$ClientId,
    [Parameter(Mandatory = $true)][string]$ClientSecret,
    [Parameter(Mandatory = $true)][string]$adh_group,
    [ValidateSet('nonprd','prd')][string]$adh_subscription_type = 'nonprd',
    [Parameter(Mandatory = $true)][string]$OutputDir,
    [string]$BranchName = '',

    # RBAC auto-grant (recommended)
    [switch]$GrantRbac
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
Write-Host "DEBUG: GrantRbac             = $GrantRbac"

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

# Deep reference counter:
# Counts occurrences of any property named "referenceName" with value == $Name
# Recurses through objects/arrays.
function Count-ReferenceNameInObject {
    param([Parameter(Mandatory)]$Obj, [Parameter(Mandatory)][string]$Name)

    $count = 0
    if ($null -eq $Obj) { return 0 }

    if ($Obj -is [System.Collections.IEnumerable] -and $Obj -isnot [string]) {
        foreach ($i in $Obj) { $count += Count-ReferenceNameInObject -Obj $i -Name $Name }
        return $count
    }

    $props = $Obj.PSObject.Properties
    foreach ($p in $props) {
        $v = $p.Value
        if ($null -eq $v) { continue }

        if ($p.Name -match 'referenceName' -and ($v -is [string]) -and ($v -eq $Name)) {
            $count++
        } else {
            $count += Count-ReferenceNameInObject -Obj $v -Name $Name
        }
    }
    return $count
}

function Get-ExpectedAdfTargets {
    param(
        [Parameter(Mandatory)][string]$adh_group,
        [Parameter(Mandatory)][ValidateSet('nonprd','prd')][string]$adh_subscription_type
    )

    $gUpper = $adh_group.Trim().ToUpper()
    $gLower = $adh_group.Trim().ToLower()
    $envs   = if ($adh_subscription_type -eq 'prd') { @('prd') } else { @('dev','tst','stg') }

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

function Get-IRPortalTypeSubType {
    param([object]$Ir)

    if ($Ir.Name -eq 'AutoResolveIntegrationRuntime') { return @('Azure','Public') }

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

function Ensure-DataFactoryContributorOnRg {
    param(
        [Parameter(Mandatory)][string]$SpObjectId,
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroupName
    )

    $scope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName"

    try {
        $rg = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
        if (-not $rg) {
            Write-Host "RBAC: RG not found (skip): $ResourceGroupName" -ForegroundColor Yellow
            return
        }

        $existing = Get-AzRoleAssignment `
            -ObjectId $SpObjectId `
            -RoleDefinitionName "Data Factory Contributor" `
            -Scope $scope `
            -ErrorAction SilentlyContinue

        if ($existing) {
            Write-Host "RBAC: Already assigned on $ResourceGroupName" -ForegroundColor DarkGreen
            return
        }

        New-AzRoleAssignment `
            -ObjectId $SpObjectId `
            -RoleDefinitionName "Data Factory Contributor" `
            -Scope $scope `
            -ErrorAction Stop

        Write-Host "RBAC: Assigned Data Factory Contributor on $ResourceGroupName" -ForegroundColor Green
        Start-Sleep -Seconds 10
    } catch {
        Write-Warning "RBAC: Failed on $ResourceGroupName : $($_.Exception.Message)"
    }
}

# ---------------- Connect ----------------
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure connection failed."
}

# ---------------- Resolve SPN ObjectId (for RBAC) ----------------
$spObjectId = $null
if ($GrantRbac) {
    $sp = Get-AzADServicePrincipal -ApplicationId $ClientId -ErrorAction Stop
    $spObjectId = $sp.Id
    Write-Host "DEBUG: SP ObjectId = $spObjectId" -ForegroundColor DarkCyan
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

    # ---- RBAC auto-grant on all expected ADF RGs in this subscription ----
    if ($GrantRbac) {
        foreach ($t in $targets) {
            Ensure-DataFactoryContributorOnRg -SpObjectId $spObjectId -SubscriptionId $sub.Id -ResourceGroupName $t.ResourceGroup
        }
        # Give RBAC a moment
        Start-Sleep -Seconds 15
    }

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

        # Pull artifacts (PUBLISHED state)
        $ls = @()
        try { $ls = Get-AzDataFactoryV2LinkedService -ResourceGroupName $rgName -DataFactoryName $dfName -ErrorAction Stop } catch { $ls = @() }

        $datasets = @()
        try { $datasets = Get-AzDataFactoryV2Dataset -ResourceGroupName $rgName -DataFactoryName $dfName -ErrorAction Stop } catch { $datasets = @() }

        $pipelines = @()
        try { $pipelines = Get-AzDataFactoryV2Pipeline -ResourceGroupName $rgName -DataFactoryName $dfName -ErrorAction Stop } catch { $pipelines = @() }

        # ---------------- Linked Services (Portal-like: used only) ----------------
        foreach ($l in $ls) {
            $rawType = Get-PropValue -Obj $l -Paths @('Properties.Type','Type')
            if (-not $rawType -and $l.Properties) { $rawType = $l.Properties.GetType().Name }
            if (-not $rawType) { $rawType = 'Unknown' }

            $portalType = Map-LSTypeToPortal -lsType ($rawType.ToString())

            # Portal-ish "Related": count occurrences of LS name as referenceName
            # (Datasets + Pipelines)
            $related = (Count-ReferenceNameInObject -Obj $datasets -Name $l.Name) +
                       (Count-ReferenceNameInObject -Obj $pipelines -Name $l.Name)

            # Keep only LS that appear in portal list (used)
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

        # ---------------- Integration Runtimes (Portal-like) ----------------
        $irs = @()
        try { $irs = Get-AzDataFactoryV2IntegrationRuntime -ResourceGroupName $rgName -DataFactoryName $dfName -ErrorAction Stop } catch { $irs = @() }

        foreach ($ir in $irs) {

            $ts = Get-IRPortalTypeSubType -Ir $ir
            $portalType    = $ts[0]
            $portalSubType = $ts[1]

            # Region (Portal)
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

            # Status + Version (needs RBAC)
            $sv = Get-IRStatusAndVersion -Rg $rgName -DfName $dfName -IrName $ir.Name
            $status  = $sv[0]
            $version = $sv[1]

            # Related (portal-ish): references to IR name across LS + pipelines
            $relatedCount = (Count-ReferenceNameInObject -Obj $ls -Name $ir.Name) +
                            (Count-ReferenceNameInObject -Obj $pipelines -Name $ir.Name)

            # Portal usually shows AutoResolve + IRs actually referenced
            if ($ir.Name -ne 'AutoResolveIntegrationRuntime' -and $relatedCount -le 0) { continue }

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

# ---------------- Output CSVs ONLY ----------------
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

if ($GrantRbac) {
    Write-Host "`nRBAC note: If Status still shows 'Unknown', wait 2-5 minutes and rerun (RBAC propagation)." -ForegroundColor Yellow
    Write-Host "Also ensure ADF artifacts are PUBLISHED (portal Git branch != published state)." -ForegroundColor Yellow
}
