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

# ----------------------------------------------------------------------
# Normalise adh_sub_group (handle " " etc.)
# ----------------------------------------------------------------------
if ($null -ne $adh_sub_group) {
    $adh_sub_group = $adh_sub_group.Trim()
}
if ([string]::IsNullOrWhiteSpace($adh_sub_group)) {
    Write-Host "DEBUG: adh_sub_group is empty/space -> treating as <none>"
    $adh_sub_group = ''
}

Write-Host "DEBUG: TenantId      = $TenantId"
Write-Host "DEBUG: ClientId      = $ClientId"
Write-Host "DEBUG: adh_group     = $adh_group"
Write-Host "DEBUG: adh_sub_group = '$adh_sub_group'"
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
# Custodian helpers according to your rules
# ----------------------------------------------------------------------

# For RG / SA / Container & <Cust>:
#   - ALWAYS based on adh_group only (NO subgroup)
$BaseCustodian = $adh_group
$BaseCustLower = $adh_group.ToLower() -replace '_',''

# For Identity:
#   - If only adh_group:          CustIdentity = adh_group
#   - If adh_sub_group present:   CustIdentity = adh_group_adh_sub_group
$CustIdentity = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) {
    $adh_group
}
else {
    "${adh_group}_${adh_sub_group}"
}

Write-Host "DEBUG: BaseCustodian (RG/SA/Cont)  = $BaseCustodian"
Write-Host "DEBUG: <Cust> (lower, no _)        = $BaseCustLower"
Write-Host "DEBUG: CustIdentity (for Identity) = $CustIdentity"

# ----------------------------------------------------------------------
# Identity cache + resolver
# ----------------------------------------------------------------------
$script:IdentityCache = @{ }

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

    # If it is already a GUID
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
# Load CSV & subscriptions
# ----------------------------------------------------------------------
$rows = Import-Csv -LiteralPath $InputCsvPath

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

        # RG: <Custodian> => adh_group only
        $rgName = ($r.ResourceGroupName -replace '<Custodian>', $BaseCustodian).Trim()

        # StorageAccountName: <Custodian> / <Cust> => adh_group only
        $saName = $r.StorageAccountName
        $saName = ($saName -replace '<Custodian>', $BaseCustodian)
        $saName = ($saName -replace '<Cust>',      $BaseCustLower)
        $saName = $saName.Trim()

        # ContainerName: same rule as SA
        $cont = $r.ContainerName
        $cont = ($cont -replace '<Custodian>', $BaseCustodian)
        $cont = ($cont -replace '<Cust>',      $BaseCustLower)
        $cont = $cont.Trim()

        # Identity: <Custodian> based on CustIdentity
        $iden = ($r.Identity -replace '<Custodian>', $CustIdentity).Trim()

        # ---------- ENV FILTER (same as before) ----------
        if ($adh_subscription_type -eq 'prd') {
            # prd run -> skip *nonprd* accounts
            if ($saName -match 'adlsnonprd$') {
                Write-Host "SKIP (prd run): nonprod ADLS $saName" -ForegroundColor Yellow
                continue
            }
        }
        else {
            # nonprd run -> skip *prd* accounts
            if ($saName -match 'adlsprd$') {
                Write-Host "SKIP (nonprd run): prod ADLS $saName" -ForegroundColor Yellow
                continue
            }
        }

        # AccessPath handling
        $accessPath = $r.AccessPath
        $accessPath = ($accessPath -replace '<Custodian>', $BaseCustodian)
        $accessPath = ($accessPath -replace '<Cust>',      $BaseCustLower)
        $accessPath = $accessPath.Trim()

        # /catalog → /adh_<adh_group> or /adh_<adh_group>_<adh_sub_group>
        if ($accessPath -like '/catalog*') {
            $prefixLength = '/catalog'.Length
            $suffix       = $accessPath.Substring($prefixLength)  # includes leading / if present

            if ([string]::IsNullOrWhiteSpace($adh_sub_group)) {
                # Only adh_group
                $accessPath = "/adh_${adh_group}${suffix}"
            }
            else {
                # adh_group + adh_sub_group
                $accessPath = "/adh_${adh_group}_${adh_sub_group}${suffix}"
            }
        }

        # Normalise root: "/" means container root (no Path parameter)
        $normalizedPath = $accessPath
        if ($normalizedPath -eq '/') { $normalizedPath = '' }

        # Folder value for report
        $folderForReport = if ([string]::IsNullOrWhiteSpace($normalizedPath)) { '/' } else { $normalizedPath }

        Write-Host "DEBUG Row:"
        Write-Host "  RG      = $rgName"
        Write-Host "  Storage = $saName"
        Write-Host "  Cont    = $cont"
        Write-Host "  Id      = $iden"
        Write-Host "  Path    = $normalizedPath"

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

            # Only pass Path when we really have a sub-path. Root ("/") -> no Path.
            if (-not [string]::IsNullOrWhiteSpace($normalizedPath)) {
                $params['Path'] = $normalizedPath.TrimStart('/')
            }

            $item      = Get-AzDataLakeGen2Item @params
            $aclString = $item.Acl
            $permType  = $r.PermissionType

            # 1) Check explicit ACL entries: user:<objectId>:rwx / group:<objectId>:r-x etc.
            $matchEntry = $aclString | Where-Object {
                ($_ -like "*$objectId*") -and ($_ -like "*$permType*")
            }

            # 2) Also treat Owner / Group of the item as a valid match
            $ownerMatch = $false
            $groupMatch = $false

            if ($item.Owner) {
                if ($item.Owner -like "*$objectId*" -or $item.Owner -eq $iden) {
                    $ownerMatch = $true
                }
            }
            if ($item.Group) {
                if ($item.Group -like "*$objectId*" -or $item.Group -eq $iden) {
                    $groupMatch = $true
                }
            }

            $hasMatch = $matchEntry -or $ownerMatch -or $groupMatch

            $status = if ($hasMatch) { 'OK' } else { 'MISSING' }
            if ($matchEntry) {
                $notes = 'ACL contains required permission'
            }
            elseif ($ownerMatch -or $groupMatch) {
                $notes = 'Identity matches Owner/Group with required permission mask'
            }
            else {
                $notes = 'Permissions missing or mismatched'
            }

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
# Export CSV + HTML (include adh_sub_group when present)
# ----------------------------------------------------------------------
$groupForFile = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) {
    $adh_group
}
else {
    "${adh_group}_${adh_sub_group}"
}

$csvOut  = New-StampedPath -BaseDir $OutputDir -Prefix ("adls_validation_{0}_{1}" -f $groupForFile, $adh_subscription_type)
Write-CsvSafe -Rows $out -Path $csvOut

$htmlOut = $csvOut -replace '\.csv$','.html'
Convert-CsvToHtml -CsvPath $csvOut -HtmlPath $htmlOut -Title "ADLS Validation ($groupForFile / $adh_subscription_type) $BranchName"

Write-Host "ADLS validation completed." -ForegroundColor Green
Write-Host "CSV : $csvOut"
Write-Host "HTML: $htmlOut"
