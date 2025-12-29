param(
    [Parameter(Mandatory = $true)][string]$TenantId,
    [Parameter(Mandatory = $true)][string]$ClientId,
    [Parameter(Mandatory = $true)][string]$ClientSecret,
    [Parameter(Mandatory = $true)][string]$adh_group,

    [string]$adh_sub_group = '',

    [ValidateSet('nonprd','prd')][string]$adh_subscription_type = 'nonprd',

    [Parameter(Mandatory = $true)][string]$InputCsvPath,
    [Parameter(Mandatory = $true)][string]$OutputDir,
    [string]$BranchName = '',

    # optional: print ACL details for debugging
    [switch]$DebugAcls
)

Import-Module Az.Accounts, Az.Resources, Az.Storage -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

# ---------------- Normalise adh_sub_group ----------------
if ($null -ne $adh_sub_group) { $adh_sub_group = $adh_sub_group.Trim() }
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

Ensure-Dir -Path $OutputDir | Out-Null

if (-not (Test-Path -LiteralPath $InputCsvPath)) {
    throw "ADLS CSV not found: $InputCsvPath"
}

# ---------------- Connect to Azure ----------------
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure connection failed."
}

# ---------------- Custodian helpers ----------------
$BaseCustodian = $adh_group
$BaseCustLower = $adh_group.ToLower() -replace '_',''

# Identity placeholder only: adh_group OR adh_group_adh_sub_group
$CustIdentity = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) {
    $adh_group
} else {
    "${adh_group}_${adh_sub_group}"
}

Write-Host "DEBUG: BaseCustodian (RG/SA/Cont)  = $BaseCustodian"
Write-Host "DEBUG: <Cust> (lower, no _)        = $BaseCustLower"
Write-Host "DEBUG: CustIdentity (for Identity) = $CustIdentity"

# ---------------- Identity cache + resolver (SPNs + groups) ----------------
$script:IdentityCache = @{}

function Resolve-IdentityObjectId {
    param(
        [Parameter(Mandatory = $true)][string]$IdentityName
    )

    if ($script:IdentityCache.ContainsKey($IdentityName)) {
        return $script:IdentityCache[$IdentityName]
    }

    $id = $null

    # Group by display name
    try {
        $grp = Get-AzADGroup -DisplayName $IdentityName -ErrorAction Stop
        if ($grp -and $grp.Id) { $id = $grp.Id }
    } catch {}

    # SPN by display name
    if (-not $id) {
        try {
            $sp = Get-AzADServicePrincipal -DisplayName $IdentityName -ErrorAction Stop
            if ($sp -and $sp.Id) { $id = $sp.Id }
        } catch {}
    }

    # SPN by search string (FIX: avoid wrong [0])
    if (-not $id) {
        try {
            $sp2 = Get-AzADServicePrincipal -SearchString $IdentityName -ErrorAction Stop
            if ($sp2) {
                $exact = $sp2 | Where-Object { $_.DisplayName -eq $IdentityName } | Select-Object -First 1
                if ($exact) { $id = $exact.Id }
                elseif ($sp2.Count -eq 1) { $id = $sp2[0].Id }
                else { $id = $null } # ambiguous
            }
        } catch {}
    }

    # Accept GUID as-is
    if (-not $id) {
        $guidRef = [ref]([Guid]::Empty)
        if ([Guid]::TryParse($IdentityName, $guidRef)) {
            $id = $IdentityName
        }
    }

    $script:IdentityCache[$IdentityName] = $id
    return $id
}

function Perm-Ok {
    param([string]$acePerm, [string]$permType)
    switch ($permType) {
        'r-x' { return ($acePerm -eq 'r-x' -or $acePerm -eq 'rwx') }
        'rwx' { return ($acePerm -eq 'rwx') }
        'r--' { return ($acePerm.Length -ge 1 -and $acePerm[0] -eq 'r') }
        default { return ($acePerm -eq $permType) }
    }
}

# ---------------- Load CSV & subscriptions ----------------
$rows = Import-Csv -LiteralPath $InputCsvPath
Write-Host ("DEBUG: CSV rows loaded: {0}" -f $rows.Count)
Write-Host ("DEBUG: CSV headers     : " + ($rows[0].psobject.Properties.Name -join ', '))

$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
if ($subs -isnot [System.Collections.IEnumerable]) { $subs = ,$subs }
if (-not $subs -or $subs.Count -eq 0) {
    throw "No subscriptions resolved for $adh_group / $adh_subscription_type"
}
Write-Host "DEBUG: Subscriptions   = $($subs.Name -join ', ')"

$out = @()

foreach ($sub in $subs) {
    Set-ScContext -Subscription $sub
    Write-Host ""
    Write-Host "=== Subscription: $($sub.Name) ===" -ForegroundColor Cyan

    foreach ($r in $rows) {

        # -------- Placeholder substitution --------
        $rgName = ($r.ResourceGroupName -replace '<Custodian>', $BaseCustodian).Trim()

        $saName = $r.StorageAccountName
        $saName = ($saName -replace '<Custodian>', $BaseCustodian)
        $saName = ($saName -replace '<Cust>',      $BaseCustLower)
        $saName = $saName.Trim()

        $cont = $r.ContainerName
        $cont = ($cont -replace '<Custodian>', $BaseCustodian)
        $cont = ($cont -replace '<Cust>',      $BaseCustLower)
        $cont = $cont.Trim()

        # Identity column
        $iden = ($r.Identity -replace '<Custodian>', $CustIdentity).Trim()

        # -------- env filter --------
        if ($adh_subscription_type -eq 'prd') {
            if ($saName -match 'adlsnonprd$') {
                Write-Host "SKIP (prd run): nonprod ADLS $saName" -ForegroundColor Yellow
                continue
            }
        } else {
            if ($saName -match 'adlsprd$') {
                Write-Host "SKIP (nonprd run): prod ADLS $saName" -ForegroundColor Yellow
                continue
            }
        }

        # -------- AccessPath --------
        $accessPath = $r.AccessPath
        $accessPath = ($accessPath -replace '<Custodian>', $BaseCustodian)
        $accessPath = ($accessPath -replace '<Cust>',      $BaseCustLower)
        $accessPath = $accessPath.Trim()

        if ($accessPath -like '/catalog*') {
            $prefixLength = '/catalog'.Length
            $suffix       = $accessPath.Substring($prefixLength)
            $groupLower   = $adh_group.ToLower()

            if ([string]::IsNullOrWhiteSpace($adh_sub_group)) {
                $accessPath = "/adh_${groupLower}${suffix}"
            } else {
                $subLower   = $adh_sub_group.ToLower()
                $accessPath = "/adh_${groupLower}_${subLower}${suffix}"
            }
        }

        $normalizedPath = $accessPath
        if ($normalizedPath -eq '/') { $normalizedPath = '' }

        $folderForReport = if ([string]::IsNullOrWhiteSpace($normalizedPath)) { '/' } else { $normalizedPath }

        Write-Host "DEBUG Row:"
        Write-Host "  RG      = $rgName"
        Write-Host "  Storage = $saName"
        Write-Host "  Cont    = $cont"
        Write-Host "  Id      = $iden"
        Write-Host "  Path    = $normalizedPath"

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

        # -------- Resolve storage + container --------
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
            $null = Get-AzStorageContainer -Name $cont -Context $ctx -ErrorAction Stop
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

        # -------- Resolve identity objectId --------
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
                Notes            = "Identity '$iden' not found OR ambiguous in Entra ID"
            }
            continue
        }

        # -------- Read ACLs (FIXED: Access ACL + Default ACL) --------
        try {
            $params = @{
                FileSystem  = $cont
                Context     = $ctx
                ErrorAction = 'Stop'
            }

            if (-not [string]::IsNullOrWhiteSpace($normalizedPath)) {
                $cleanPath = $normalizedPath.TrimStart('/') -replace '//+', '/'
                $params['Path'] = $cleanPath
            }

            $item = Get-AzDataLakeGen2Item @params

            # ✅ Critical fix: merge Access ACL + Default ACL
            $aclEntries = @()
            if ($item.Acl)        { $aclEntries += $item.Acl }
            if ($item.DefaultAcl) { $aclEntries += $item.DefaultAcl }

            if ($DebugAcls) {
                Write-Host "DEBUG: Resolved objectId for '$iden' = $objectId" -ForegroundColor DarkGray
                Write-Host "DEBUG: item.Owner = $($item.Owner)" -ForegroundColor DarkGray
                Write-Host "DEBUG: item.Group = $($item.Group)" -ForegroundColor DarkGray
                foreach ($ace in $aclEntries) {
                    Write-Host ("ACE => Type={0} EntityId={1} Perm={2}" -f $ace.AccessControlType, $ace.EntityId, $ace.Permissions) -ForegroundColor DarkGray
                }
            }

            $permType      = $r.PermissionType
            $explicitMatch = $false
            $ownerEntryOk  = $false   # user::...
            $groupEntryOk  = $false   # group::...

            foreach ($ace in $aclEntries) {
                if ($ace.AccessControlType -notin @('user','group')) { continue }

                $acePerm = $ace.Permissions.ToString()
                if (-not (Perm-Ok -acePerm $acePerm -permType $permType)) { continue }

                # Explicit entry user:<oid> or group:<oid>
                if ($ace.EntityId -and $ace.EntityId -eq $objectId) {
                    $explicitMatch = $true
                    break
                }

                # Owner/group style entries (EntityId often empty)
                if (-not $ace.EntityId -and $ace.AccessControlType -eq 'user')  { $ownerEntryOk = $true }
                if (-not $ace.EntityId -and $ace.AccessControlType -eq 'group') { $groupEntryOk = $true }
            }

            # Owner/Group sometimes returns objectId, sometimes name; only trust objectId equality here
            $ownerMatch = $false
            $groupMatch = $false
            if ($item.Owner -and ($item.Owner -eq $objectId)) { $ownerMatch = $true }
            if ($item.Group -and ($item.Group -eq $objectId)) { $groupMatch = $true }

            $hasMatch = $explicitMatch -or ($ownerMatch -and $ownerEntryOk) -or ($groupMatch -and $groupEntryOk)

            $status = if ($hasMatch) { 'OK' } else { 'MISSING' }
            $notes  = if ($explicitMatch) {
                'ACL contains required explicit principal entry (Access or Default ACL)'
            } elseif (($ownerMatch -and $ownerEntryOk) -or ($groupMatch -and $groupEntryOk)) {
                'Permission satisfied via owning user/group ACL entry'
            } else {
                'No matching ACL entry found in Access ACL or Default ACL'
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

# ---------------- No-results safety ----------------
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

# ---------------- Export CSV with yyyyMMdd name ----------------
$groupForFile = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) {
    $adh_group
} else {
    "${adh_group}-${adh_sub_group}"
}

$stamp  = Get-Date -Format 'yyyyMMdd'
$csvOut = Join-Path $OutputDir ("adls_acl_{0}_{1}_{2}.csv" -f $groupForFile, $adh_subscription_type, $stamp)

Write-CsvSafe -Rows $out -Path $csvOut

Write-Host "ADLS validation completed." -ForegroundColor Green
Write-Host "CSV : $csvOut"

exit 0
