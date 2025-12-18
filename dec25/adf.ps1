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

# ------------------------------------------------------------
# Helper: safe property getter for multiple object shapes
# ------------------------------------------------------------
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

# ------------------------------------------------------------
# Helper: count linked services using a given IR (connectVia)
# ------------------------------------------------------------
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

# ------------------------------------------------------------
# Helper: Map IR to Portal Type/Sub-type
# ------------------------------------------------------------
function Get-IRPortalTypeSubType {
    param([object]$Ir)

    # Portal defaults
    if ($Ir.Name -eq 'AutoResolveIntegrationRuntime') {
        return @('Azure','Public')
    }

    $rawType = Get-PropValue -Obj $Ir -Paths @('Properties.Type','Properties.type','Type','type')

    # Initial mapping
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

    # Managed VNet detection (multiple shapes across Az versions)
    $mvnet = Get-PropValue -Obj $Ir -Paths @(
        'Properties.TypeProperties.VNetProperties',
        'Properties.TypeProperties.VnetProperties',
        'Properties.TypeProperties.ManagedVirtualNetwork',
        'Properties.typeProperties.vNetProperties',
        'Properties.typeProperties.vnetProperties',
        'Properties.typeProperties.managedVirtualNetwork',
        'Properties.AdditionalProperties.ManagedVirtualNetwork',
        'Properties.AdditionalProperties.VNetProperties',
        'Properties.AdditionalProperties.VnetProperties',
        'Properties.additionalProperties.managedVirtualNetwork'
    )
    if ($mvnet) { $portalSub = 'Managed Virtual Network' }

    return @($portalType,$portalSub)
}

# ------------------------------------------------------------
# Helper: Fetch IR Status + Version (Portal "Status" / "Version")
# ------------------------------------------------------------
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
            'Properties.State',
            'Properties.state',
            'Properties.Status',
            'Properties.status',
            'Status',
            'status'
        )
        if ($statusVal) { $status = $statusVal.ToString() }

        $verVal = Get-PropValue -Obj $st -Paths @(
            'Properties.Version',
            'Properties.version',
            'Version',
            'version'
        )
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

# ------------------------------------------------------------
# Connect to Azure
# ------------------------------------------------------------
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure connection failed."
}

# ------------------------------------------------------------
# Resolve subscriptions
# ------------------------------------------------------------
$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
if ($subs -isnot [System.Collections.IEnumerable]) { $subs = ,$subs }

Write-Host "DEBUG: Subscriptions: $((($subs | Select-Object -ExpandProperty Name) -join ', '))"

$overview = @()
$lsRows   = @()
$irRows   = @()

foreach ($sub in $subs) {

    Write-Host "DEBUG: Processing subscription $($sub.Name)"
    Set-ScContext -Subscription $sub

    $dfs = Get-AzDataFactoryV2 -ErrorAction SilentlyContinue
    if (-not $dfs) { continue }

    foreach ($df in $dfs) {

        # Resolve DataFactory name safely (Portal Factory name)
        $dfName = Get-PropValue -Obj $df -Paths @('DataFactoryName','FactoryName','Name')
        if ([string]::IsNullOrWhiteSpace($dfName)) { $dfName = $df.Name }

        if ([string]::IsNullOrWhiteSpace($dfName)) {
            Write-Warning "DEBUG: ADF object has no detectable name. Skipping."
            continue
        }

        # ----------------- Overview -----------------
        $overview += [pscustomobject]@{
            SubscriptionName = $sub.Name
            SubscriptionId   = $sub.Id
            ResourceGroup    = $df.ResourceGroupName
            DataFactory      = $dfName
            Exists           = 'Yes'
            Location         = $df.Location
        }

        # ----------------- Linked Services -----------------
        try {
            $ls = Get-AzDataFactoryV2LinkedService `
                    -ResourceGroupName $df.ResourceGroupName `
                    -DataFactoryName   $dfName `
                    -ErrorAction Stop
        } catch {
            $ls = @()
        }

        foreach ($l in $ls) {
            $lsType = Get-PropValue -Obj $l -Paths @('Properties.Type','Type')
            if (-not $lsType -and $l.Properties) { $lsType = $l.Properties.GetType().Name }
            if (-not $lsType) { $lsType = 'Unknown' }

            $lsRows += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $df.ResourceGroupName
                DataFactory      = $dfName
                LinkedService    = $l.Name
                Type             = $lsType
            }
        }

        # ----------------- Integration Runtimes -----------------
        try {
            $irs = Get-AzDataFactoryV2IntegrationRuntime `
                     -ResourceGroupName $df.ResourceGroupName `
                     -DataFactoryName   $dfName `
                     -ErrorAction Stop
        } catch {
            $irs = @()
        }

        foreach ($ir in $irs) {

            # Portal Type/SubType
            $ts = Get-IRPortalTypeSubType -Ir $ir
            $portalType    = $ts[0]
            $portalSubType = $ts[1]

            # Portal Region
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

            # Portal Status / Version
            $sv = Get-IRStatusAndVersion -Rg $df.ResourceGroupName -DfName $dfName -IrName $ir.Name
            $status  = $sv[0]
            $version = $sv[1]

            # Portal Related (count LS with connectVia -> referenceName = IR)
            $relatedCount = Get-IRRelatedCount -LinkedServices $ls -IrName $ir.Name

            # IR CSV (portal-like order + trace columns)
            $irRows += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $df.ResourceGroupName
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

# ------------------------------------------------------------
# Fallback rows
# ------------------------------------------------------------
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

# ------------------------------------------------------------
# Output CSV + HTML
# ------------------------------------------------------------
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
