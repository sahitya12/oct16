param(
    [Parameter(Mandatory = $true)][string]$TenantId,
    [Parameter(Mandatory = $true)][string]$ClientId,
    [Parameter(Mandatory = $true)][string]$ClientSecret,
    [Parameter(Mandatory = $true)][string]$adh_group,
    [string]$adh_sub_group = '',
    [ValidateSet('nonprd','prd')][string]$adh_subscription_type = 'nonprd',
    [Parameter(Mandatory = $true)][string]$InputCsvPath,
    [Parameter(Mandatory = $true)][string]$OutputDir,
    [string]$BranchName = ''
)

Import-Module Az.Accounts, Az.Resources, Az.Storage -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

Write-Host "DEBUG: TenantId      = $TenantId"
Write-Host "DEBUG: ClientId      = $ClientId"
Write-Host "DEBUG: adh_group     = $adh_group"
Write-Host "DEBUG: adh_sub_group = $adh_sub_group"
Write-Host "DEBUG: subscription  = $adh_subscription_type"
Write-Host "DEBUG: InputCsvPath  = $InputCsvPath"
Write-Host "DEBUG: OutputDir     = $OutputDir"
Write-Host "DEBUG: BranchName    = $BranchName"

# ----------------------------------------------------------------------
# Ensure output dir
# ----------------------------------------------------------------------
Ensure-Dir -Path $OutputDir | Out-Null

if (-not (Test-Path -LiteralPath $InputCsvPath)) {
    throw "ADLS CSV not found: $InputCsvPath"
}

# ----------------------------------------------------------------------
# Connect to Azure
# ----------------------------------------------------------------------
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure connection failed."
}

# ----------------------------------------------------------------------
# Custodian / <Cust> helpers
# ----------------------------------------------------------------------
# Custodian = adh_group or adh_group_adh_sub_group
$Custodian = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) {
    $adh_group
} else {
    "${adh_group}_${adh_sub_group}"
}

# <Cust> = lowercase of Custodian, without underscores
$custLower = $Custodian.ToLower() -replace '_',''

Write-Host "DEBUG: Custodian = $Custodian"
Write-Host "DEBUG: <Cust>    = $custLower"

# ----------------------------------------------------------------------
# Identity cache + resolver
# ----------------------------------------------------------------------
$script:IdentityCache = @{}

function Resolve-IdentityObjectId {
    param(
        [Parameter(Mandatory = $true)][string]$IdentityName
    )

    if ($script:IdentityCache.ContainsKey($IdentityName)) {
        return $script:IdentityCache[$IdentityName]
    }

    $id = $null

    # Try group by display name
    try {
        $grp = Get-AzADGroup -DisplayName $IdentityName -ErrorAction Stop
        if ($grp -and $grp.Id) { $id = $grp.Id }
    } catch {}

    # Try SPN by display name
    if (-not $id) {
        try {
            $sp = Get-AzADServicePrincipal -DisplayName $IdentityName -ErrorAction Stop
            if ($sp -and $sp.Id) { $id = $sp.Id }
        } catch {}
    }

    # Try SPN by SearchString (looser)
    if (-not $id) {
        try {
            $sp2 = Get-AzADServicePrincipal -SearchString $IdentityName -ErrorAction Stop
            if ($sp2 -and $sp2.Count -ge 1) { $id = $sp2[0].Id }
        } catch {}
    }

    # If a GUID directly
    if (-not $id) {
        $guidRef = [ref]([Guid]::Empty)
        if ([Guid]::TryParse($IdentityName, $guidRef)) {
            $id = $IdentityName
        }
    }

    $script:IdentityCache[$IdentityName] = $id
    return $id
}

# ----------------------------------------------------------------------
# Load CSV
# ----------------------------------------------------------------------
$rows = Import-Csv -LiteralPath $InputCsvPath

# Resolve subscriptions for this adh_group
$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
if ($subs -isnot [System.Collections.IEnumerable]) { $subs = ,$subs }

$out = @()

foreach ($sub in $subs) {
    Set-ScContext -Subscription $sub

    Write-Host ""
    Write-Host "=== Subscription: $($sub.Name) ===" -ForegroundColor Cyan

    foreach ($r in $rows) {

        # ------------------------------------------------------------------
        # Placeholder substitution per row
        # ------------------------------------------------------------------
        $rgName = ($r.ResourceGroupName   -replace '<Custodian>', $Custodian).Trim()
        $saName = ($r.StorageAccountName  -replace '<Custodian>', $Custodian).Trim()
        $saName = ($saName                 -replace '<Cust>',      $custLower).Trim()
        $cont   = ($r.ContainerName       -replace '<Cust>',      $custLower).Trim()
        $iden   = ($r.Identity            -replace '<Custodian>', $Custodian).Trim()

        # AccessPath handling
        $accessPath = ($r.AccessPath -replace '<Custodian>', $Custodian) -replace '<Cust>', $custLower
        $accessPath = $accessPath.Trim()

        # /catalog → /adh_<adh_group_lower>...
        if ($accessPath -like '/catalog*') {
            $suffix     = $accessPath.Substring(8)   # after "/catalog"
            $adhLower   = $adh_group.ToLower()
            $accessPath = "/adh_${adhLower}${suffix}"
        }

        # For report: show "/" instead of empty
        $folderForReport = if ([string]::IsNullOrWhiteSpace($accessPath)) { '/' } else { $accessPath }

        Write-Host "DEBUG Row:"
        Write-Host "  RG      = $rgName"
        Write-Host "  Storage = $saName"
        Write-Host "  Cont    = $cont"
        Write-Host "  Id      = $iden"
        Write-Host "  Path    = $accessPath"

        # If ResourceGroupName or StorageAccountName ended empty, mark ERROR and continue
        if ([string]::IsNullOrWhiteSpace($rgName) -or [string]::IsNullOrWhiteSpace($saName)) {
            $out += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $rgName
                Storage          = $saName
                Container        = $cont
                Folder           = $folderForReport
                Identity         = $iden
                Permission       = $r.PermissionType
                Status           = 'ERROR'
                Notes            = 'After placeholder replacement ResourceGroupName or StorageAccountName is empty.'
            }
            continue
        }

        # ------------------------------------------------------------------
        # Resolve storage account and container
        # ------------------------------------------------------------------
        try {
            $sa = Get-AzStorageAccount -ResourceGroupName $rgName -Name $saName -ErrorAction Stop
        } catch {
            $out += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $rgName
                Storage          = $saName
                Container        = $cont
                Folder           = $folderForReport
                Identity         = $iden
                Permission       = $r.PermissionType
                Status           = 'ERROR'
                Notes            = "Storage account error: $($_.Exception.Message)"
            }
            continue
        }

        $ctx = $sa.Context

        try {
            $container = Get-AzStorageContainer -Name $cont -Context $ctx -ErrorAction Stop
        } catch {
            $out += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $rgName
                Storage          = $saName
                Container        = $cont
                Folder           = $folderForReport
                Identity         = $iden
                Permission       = $r.PermissionType
                Status           = 'ERROR'
                Notes            = "Container fetch error: $($_.Exception.Message)"
            }
            continue
        }

        # ------------------------------------------------------------------
        # Resolve identity objectId
        # ------------------------------------------------------------------
        $objectId = Resolve-IdentityObjectId -IdentityName $iden
        if (-not $objectId) {
            $out += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $rgName
                Storage          = $saName
                Container        = $cont
                Folder           = $folderForReport
                Identity         = $iden
                Permission       = $r.PermissionType
                Status           = 'ERROR'
                Notes            = "Identity '$iden' not found in Entra ID"
            }
            continue
        }

        # ------------------------------------------------------------------
        # Read ACLs for the target path
        # ------------------------------------------------------------------
        try {
            $params = @{
                FileSystem  = $cont
                Context     = $ctx
                ErrorAction = 'Stop'
            }

            if (-not [string]::IsNullOrWhiteSpace($accessPath)) {
                $params['Path'] = $accessPath.TrimStart('/')
            }

            $item      = Get-AzDataLakeGen2Item @params
            $aclString = $item.Acl

            # ACL entries are strings like:
            # user:<objectId>:rwx
            # group:<objectId>:r-x
            $permType  = $r.PermissionType
            $matchEntry = $aclString | Where-Object {
                ($_ -like "*$objectId*") -and ($_ -like "*$permType*")
            }

            $status = if ($matchEntry) { 'OK' } else { 'MISSING' }
            $notes  = if ($matchEntry) { 'ACL contains required permission' } else { 'Permissions missing or mismatched' }

        } catch {
            $status = 'ERROR'
            $notes  = "ACL read error: $($_.Exception.Message)"
        }

        $out += [pscustomobject]@{
            SubscriptionName = $sub.Name
            ResourceGroup    = $rgName
            Storage          = $saName
            Container        = $cont
            Folder           = $folderForReport
            Identity         = $iden
            Permission       = $r.PermissionType
            Status           = $status
            Notes            = $notes
        }
    }
}

# ----------------------------------------------------------------------
# Handle "no results" scenario
# ----------------------------------------------------------------------
if (-not $out -or $out.Count -eq 0) {
    $out += [pscustomobject]@{
        SubscriptionName = ''
        ResourceGroup    = ''
        Storage          = ''
        Container        = ''
        Folder           = ''
        Identity         = ''
        Permission       = ''
        Status           = 'NO_RESULTS'
        Notes            = 'Nothing matched in scan'
    }
}

# ----------------------------------------------------------------------
# Export CSV + HTML
# ----------------------------------------------------------------------
$csvOut  = New-StampedPath -BaseDir $OutputDir -Prefix ("adls_validation_{0}_{1}" -f $adh_group, $adh_subscription_type)
Write-CsvSafe -Rows $out -Path $csvOut

$htmlOut = $csvOut -replace '\.csv$','.html'
Convert-CsvToHtml -CsvPath $csvOut -HtmlPath $htmlOut -Title "ADLS Validation ($adh_group / $adh_subscription_type) $BranchName"

Write-Host "ADLS validation completed." -ForegroundColor Green
Write-Host "CSV : $csvOut"
Write-Host "HTML: $htmlOut"
