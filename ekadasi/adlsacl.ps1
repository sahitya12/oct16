[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$TenantId,
    [Parameter(Mandatory = $true)][string]$ClientId,
    [Parameter(Mandatory = $true)][string]$ClientSecret,
    [Parameter(Mandatory = $true)][string]$adh_group,          # e.g. ADH_MDM

    [string]$adh_sub_group = '',

    [ValidateSet('nonprd','prd')]
    [string]$adh_subscription_type = 'nonprd',

    [Parameter(Mandatory = $true)][string]$InputCsvPath,
    [Parameter(Mandatory = $true)][string]$OutputDir,
    [string]$BranchName = ''
)

Import-Module Az.Accounts, Az.Resources, Az.Storage -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

# ------------------------- Normalise subgroup --------------------------
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

Ensure-Dir -Path $OutputDir | Out-Null
if (-not (Test-Path -LiteralPath $InputCsvPath)) {
    throw "ADLS CSV not found: $InputCsvPath"
}

# ------------------------- Connect to Azure ----------------------------
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure connection failed."
}

# ------------------------- Custodian helpers ---------------------------
# adh_group is already full key, e.g. ADH_MDM
$BaseCustodian = $adh_group
$BaseCustLower = $BaseCustodian.ToLower() -replace '_',''

Write-Host "DEBUG: BaseCustodian (RG/SA/Cont)  = $BaseCustodian"
Write-Host "DEBUG: <Cust> (lower, no _)        = $BaseCustLower"

# ------------------------- Identity resolver ---------------------------
$script:IdentityCache = @{}

function Resolve-IdentityObjectId {
    param(
        [Parameter(Mandatory = $true)][string]$IdentityName,
        [Parameter(Mandatory = $true)][ValidateSet('Group','SPN')][string]$IdentityType
    )

    $cacheKey = "$IdentityType|$IdentityName"
    if ($script:IdentityCache.ContainsKey($cacheKey)) {
        return $script:IdentityCache[$cacheKey]
    }

    $id = $null

    if ($IdentityType -eq 'Group') {
        try {
            $grp = Get-AzADGroup -DisplayName $IdentityName -ErrorAction Stop
            if ($grp -and $grp.Id) { $id = $grp.Id }
        } catch {}
    }
    elseif ($IdentityType -eq 'SPN') {
        try {
            $sp = Get-AzADServicePrincipal -DisplayName $IdentityName -ErrorAction Stop
            if ($sp -and $sp.Id) { $id = $sp.Id }
        } catch {}

        if (-not $id) {
            try {
                $sp2 = Get-AzADServicePrincipal -SearchString $IdentityName -ErrorAction Stop
                if ($sp2 -and $sp2.Count -ge 1) { $id = $sp2[0].Id }
            } catch {}
        }
    }

    if (-not $id) {
        $guidRef = [ref]([Guid]::Empty)
        if ([Guid]::TryParse($IdentityName, $guidRef)) {
            $id = $IdentityName
        }
    }

    $script:IdentityCache[$cacheKey] = $id
    return $id
}

# ------------------------- ADLS ACL parser ---------------------------
function ConvertFrom-AdlsAclEntry {
    param([Parameter(Mandatory=$true)][string]$Entry)
    # Examples:
    # user:<objectId>:rwx
    # group:<objectId>:r-x
    # default:user:<objectId>:rwx  (we ignore 'default:' prefix)
    $e = $Entry.Trim()
    if ($e.StartsWith('default:')) { $e = $e.Substring(8) }
    if ($e -match '^(user|group):([^:]*):([rwx-]{3})$') {
        $etype = $Matches[1]
        $eid   = $Matches[2]
        $perm  = $Matches[3]
        if ([string]::IsNullOrWhiteSpace($eid)) { return $null }  # owner/owning group entries don't carry objectId
        return [pscustomobject]@{
            EntityType = $etype
            EntityId   = $eid
            Permissions = [pscustomobject]@{
                Read    = ($perm[0] -eq 'r')
                Write   = ($perm[1] -eq 'w')
                Execute = ($perm[2] -eq 'x')
            }
        }
    }
    return $null
}

function Get-AdlsAclEntries {
    param(
        [Parameter(Mandatory=$true)][hashtable]$ItemParams
    )
    # Best-effort: try to ask Az for AccessControl (already parsed).
    # If not supported by the module version, fall back to parsing the Acl string.
    try {
        $ac = Get-AzDataLakeGen2Item @ItemParams -GetAccessControl -ErrorAction Stop
        if ($ac -and $ac.Acl) { return $ac.Acl }
    } catch { }

    $item = Get-AzDataLakeGen2Item @ItemParams -ErrorAction Stop
    $raw  = $item.Acl
    if (-not $raw) { return @() }

    # $raw can be a single string 'user:..,group:..' or already a list
    $entries = @()
    if ($raw -is [string]) {
        $entries = $raw -split ','
    } else {
        $entries = @($raw)
    }

    $parsed = @()
    foreach ($en in $entries) {
        $p = ConvertFrom-AdlsAclEntry -Entry $en
        if ($p) { $parsed += $p }
    }
    return $parsed
}


# ------------------------- Load CSV & subs -----------------------------
$rows = Import-Csv -LiteralPath $InputCsvPath
Write-Host ("DEBUG: CSV rows loaded: {0}" -f $rows.Count)
if ($rows.Count -gt 0) {
    Write-Host ("DEBUG: CSV headers     : " + ($rows[0].psobject.Properties.Name -join ', '))
}

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

        # ------------ Placeholder replacement: RG / SA / Container -------
        $rgName = ($r.ResourceGroupName -replace '<Custodian>', $BaseCustodian).Trim()

        $saName = $r.StorageAccountName
        $saName = ($saName -replace '<Custodian>', $BaseCustodian)
        $saName = ($saName -replace '<Cust>',      $BaseCustLower)
        $saName = $saName.Trim()

        $cont = $r.ContainerName
        $cont = ($cont -replace '<Custodian>', $BaseCustodian)
        $cont = ($cont -replace '<Cust>',      $BaseCustLower)
        $cont = $cont.Trim()

        # ------------ Identity: apply <Custodian>/<Cust> -----------------
        $idenRaw = $r.Identity
        $iden    = $idenRaw
        $iden    = ($iden -replace '<Custodian>', $BaseCustodian)
        $iden    = ($iden -replace '<Cust>',      $BaseCustLower)
        $iden    = $iden.Trim()

        # ------------ Type: detect SPN by name, else CSV -----------------
        $typeRaw = $r.Type

        if ($iden.ToUpper().EndsWith('_SPN')) {
            $type = 'SPN'
        }
        else {
            if ([string]::IsNullOrWhiteSpace($typeRaw)) {
                $type = 'Group'
            }
            else {
                $t = $typeRaw.Trim().ToUpper()
                if ($t -eq 'SPN') { $type = 'SPN' } else { $type = 'Group' }
            }
        }

        # ------------ Env filter for nonprd/prd --------------------------
        if ($adh_subscription_type -eq 'prd') {
            if ($saName -match 'adlsnonprd$') {
                Write-Host "SKIP (prd run): nonprod ADLS $saName"
                continue
            }
        }
        else {
            if ($saName -match 'adlsprd$') {
                Write-Host "SKIP (nonprd run): prod ADLS $saName"
                continue
            }
        }

        # ------------ AccessPath handling -------------------------------
        $accessPath = $r.AccessPath
        $accessPath = ($accessPath -replace '<Custodian>', $BaseCustodian)
        $accessPath = ($accessPath -replace '<Cust>',      $BaseCustLower)
        $accessPath = $accessPath.Trim()

        if ($accessPath -like '/catalog*') {
            $prefixLength = '/catalog'.Length
            $suffix       = $accessPath.Substring($prefixLength)

            $groupLower = $adh_group.ToLower()
            if ([string]::IsNullOrWhiteSpace($adh_sub_group)) {
                $accessPath = "/adh_${groupLower}${suffix}"
            }
            else {
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
        Write-Host "  IdRaw   = $idenRaw"
        Write-Host "  IdUsed  = $iden"
        Write-Host "  TypeRaw = $typeRaw"
        Write-Host "  Type    = $type"
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

        # ------------ Resolve storage account / container ---------------
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

        # ------------ Resolve identity objectId -------------------------
        $objectId = Resolve-IdentityObjectId -IdentityName $iden -IdentityType $type
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
                Notes            = "Identity '$iden' of type '$type' not found in Entra ID"
            }
            continue
        }

        # ------------ ACL evaluation (root + parents) -------------------
        try {
            $permType    = $r.PermissionType
            $needRead    = $permType -like '*r*'
            $needExecute = $permType -like '*x*'
            $needWrite   = $false

            $segments = @()
            if (-not [string]::IsNullOrWhiteSpace($normalizedPath)) {
                $segments = $normalizedPath.Trim('/') -split '/'
            }

            $pathsToCheck = @('')   # container root
            if ($segments.Count -gt 0) {
                $current = ''
                foreach ($seg in $segments) {
                    if ([string]::IsNullOrWhiteSpace($current)) {
                        $current = $seg
                    } else {
                        $current = "$current/$seg"
                    }
                    $pathsToCheck += $current
                }
            }

            $hasMatch = $false

            foreach ($p in $pathsToCheck) {

                $params = @{
                    FileSystem  = $cont
                    Context     = $ctx
                    ErrorAction = 'Stop'
                }
                if (-not [string]::IsNullOrWhiteSpace($p)) {
                    $params['Path'] = $p
                }

                $aclEntries = Get-AdlsAclEntries -ItemParams $params

                Write-Host "DEBUG ACL: checking container=$cont path='$p' for Id=$objectId"

                foreach ($ace in $aclEntries) {
                    $aceObj = $ace
                    if ($aceObj -is [string]) { $aceObj = ConvertFrom-AdlsAclEntry -Entry $aceObj }
                    if (-not $aceObj) { continue }

                    $aceId = $aceObj.EntityId
                    if (-not $aceId) { continue }
                    if ($aceId -eq $objectId) {
                        $hasRead    = [bool]$aceObj.Permissions.Read
                        $hasWrite   = [bool]$aceObj.Permissions.Write
                        $hasExecute = [bool]$aceObj.Permissions.Execute

                        Write-Host "DEBUG ACL match candidate: Path='$p' R=$hasRead X=$hasExecute W=$hasWrite NeedR=$needRead NeedX=$needExecute"

                        $ok = $true
                        if ($needRead    -and -not $hasRead)    { $ok = $false }
                        if ($needExecute -and -not $hasExecute) { $ok = $false }

                        if ($ok) {
                            Write-Host "DEBUG ACL satisfied at Path='$p'"
                            $hasMatch = $true
                            break
                        }
                    }
                }

                if ($hasMatch) { break }
            }

            if ($hasMatch) {
                $status = 'OK'
                $notes  = 'Permissions Exists (via root or parent ACL)'
            }
            else {
                $status = 'MISSING'
                $notes  = 'Permission Missing on path and all parents'
            }
        }
        catch {
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

$groupForFile = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) { $adh_group } else { "${adh_group}-${adh_sub_group}" }

$csvOut = New-StampedPath -BaseDir $OutputDir -Prefix ("adls_validation_{0}_{1}" -f $groupForFile, $adh_subscription_type)
Write-CsvSafe -Rows $out -Path $csvOut

Write-Host "ADLS validation completed."
Write-Host "CSV : $csvOut"

exit 0
