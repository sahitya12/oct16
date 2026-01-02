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

# ------------------------- Normalize subgroup --------------------------
if ($null -ne $adh_sub_group) { $adh_sub_group = $adh_sub_group.Trim() }
if ([string]::IsNullOrWhiteSpace($adh_sub_group)) { $adh_sub_group = '' }

Ensure-Dir -Path $OutputDir | Out-Null
if (-not (Test-Path -LiteralPath $InputCsvPath)) {
    throw "Input CSV not found: $InputCsvPath"
}

# ------------------------- Connect to Azure ----------------------------
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure connection failed."
}

# ------------------------- Custodian helpers ---------------------------
$BaseCustodian = $adh_group
$BaseCustLower = $BaseCustodian.ToLower() -replace '_',''

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
    else {
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

    # If someone already put objectId in CSV
    if (-not $id) {
        $guidRef = [ref]([Guid]::Empty)
        if ([Guid]::TryParse($IdentityName, $guidRef)) { $id = $IdentityName }
    }

    $script:IdentityCache[$cacheKey] = $id
    return $id
}

# ------------------------- Permission helpers --------------------------
function PermStringToBits {
    param([Parameter(Mandatory=$true)][string]$p)
    $p = $p.Trim()
    if ($p.Length -ne 3) { return @{ r=$false; w=$false; x=$false } }
    return @{
        r = ($p[0] -eq 'r')
        w = ($p[1] -eq 'w')
        x = ($p[2] -eq 'x')
    }
}

function BitsToPermString {
    param($bits)
    $r = if ($bits.r) { 'r' } else { '-' }
    $w = if ($bits.w) { 'w' } else { '-' }
    $x = if ($bits.x) { 'x' } else { '-' }
    return "$r$w$x"
}

function AndBits($a,$b) {
    return @{
        r = ($a.r -and $b.r)
        w = ($a.w -and $b.w)
        x = ($a.x -and $b.x)
    }
}

function OrBits($a,$b) {
    return @{
        r = ($a.r -or $b.r)
        w = ($a.w -or $b.w)
        x = ($a.x -or $b.x)
    }
}

function RequiredBitsFromPermissionType {
    param([Parameter(Mandatory=$true)][string]$permType)
    $permType = $permType.Trim().ToLower()
    return @{
        r = ($permType -like '*r*')
        w = ($permType -like '*w*')
        x = ($permType -like '*x*')
    }
}

# ------------------------- ACL parsing --------------------------
function Parse-AclString {
    param(
        [Parameter(Mandatory=$true)][string]$AclString,
        [Parameter(Mandatory=$true)][ValidateSet('access','default')][string]$Kind
    )
    # Returns hashtable:
    # entries: array of {etype, eid, permBits}
    # maskBits: {r,w,x} (if present)
    $result = @{
        entries  = @()
        maskBits = $null
    }

    if ([string]::IsNullOrWhiteSpace($AclString)) { return $result }

    $parts = $AclString -split ','
    foreach ($raw in $parts) {
        $e = $raw.Trim()
        if ([string]::IsNullOrWhiteSpace($e)) { continue }

        # For default kind, entries typically start with 'default:' prefix.
        if ($Kind -eq 'default') {
            if ($e.StartsWith('default:')) { $e = $e.Substring(8) } else { continue }
        }
        else {
            # For access kind, ignore default:* entries if present
            if ($e.StartsWith('default:')) { continue }
        }

        # mask::rwx
        if ($e -match '^mask::([rwx-]{3})$') {
            $result.maskBits = (PermStringToBits -p $Matches[1])
            continue
        }

        # user:<id>:rwx or group:<id>:r-x
        if ($e -match '^(user|group):([^:]*):([rwx-]{3})$') {
            $etype = $Matches[1]
            $eid   = $Matches[2]
            $perm  = $Matches[3]

            # owner/owning group entries can have empty id, ignore for identity match
            if ([string]::IsNullOrWhiteSpace($eid)) { continue }

            $result.entries += [pscustomobject]@{
                EntityType = $etype
                EntityId   = $eid
                PermBits   = (PermStringToBits -p $perm)
            }
        }
    }

    return $result
}

function Get-AclStringsForPath {
    param(
        [Parameter(Mandatory=$true)][string]$FileSystem,
        [Parameter(Mandatory=$true)]$Context,
        [string]$Path
    )

    $params = @{
        FileSystem  = $FileSystem
        Context     = $Context
        ErrorAction = 'Stop'
    }
    if (-not [string]::IsNullOrWhiteSpace($Path)) { $params.Path = $Path }

    # Try AccessControl first (works in many Az.Storage versions)
    try {
        $ac = Get-AzDataLakeGen2Item @params -GetAccessControl -ErrorAction Stop
        # Different Az versions expose these differently; handle both.
        $access = $null
        $default = $null

        if ($ac.PSObject.Properties.Name -contains 'Acl')        { $access  = $ac.Acl }
        if ($ac.PSObject.Properties.Name -contains 'DefaultAcl') { $default = $ac.DefaultAcl }

        # Fallback: sometimes DefaultAcl not present even with -GetAccessControl
        if (-not $default) {
            $item = Get-AzDataLakeGen2Item @params -ErrorAction Stop
            if ($item.PSObject.Properties.Name -contains 'DefaultAcl') { $default = $item.DefaultAcl }
        }

        return @{
            AccessAcl  = $access
            DefaultAcl = $default
        }
    }
    catch {
        # Fallback: normal item properties
        $item = Get-AzDataLakeGen2Item @params -ErrorAction Stop
        $access = $null
        $default = $null
        if ($item.PSObject.Properties.Name -contains 'Acl')        { $access  = $item.Acl }
        if ($item.PSObject.Properties.Name -contains 'DefaultAcl') { $default = $item.DefaultAcl }

        return @{
            AccessAcl  = $access
            DefaultAcl = $default
        }
    }
}

function Get-EffectiveBitsFromAclSet {
    param(
        [Parameter(Mandatory=$true)]$ParsedAcl,
        [Parameter(Mandatory=$true)][string]$ObjectId
    )
    # Find exact identity entry; apply mask if present
    $bits = @{ r=$false; w=$false; x=$false }

    foreach ($e in $ParsedAcl.entries) {
        if ($e.EntityId -eq $ObjectId) {
            $b = $e.PermBits
            if ($ParsedAcl.maskBits) {
                $b = AndBits $b $ParsedAcl.maskBits
            }
            $bits = OrBits $bits $b
        }
    }
    return $bits
}

function Compare-RequiredVsActual {
    param(
        [Parameter(Mandatory=$true)]$RequiredBits,
        [Parameter(Mandatory=$true)]$ActualBits
    )

    $missing = @{
        r = ($RequiredBits.r -and -not $ActualBits.r)
        w = ($RequiredBits.w -and -not $ActualBits.w)
        x = ($RequiredBits.x -and -not $ActualBits.x)
    }

    $status =
        if (-not $RequiredBits.r -and -not $RequiredBits.w -and -not $RequiredBits.x) { 'OK' }
        elseif (-not $missing.r -and -not $missing.w -and -not $missing.x) { 'OK' }
        elseif ($missing.r -and $missing.w -and $missing.x) { 'MISSING' }
        else { 'PARTIAL' }

    return @{
        Status = $status
        MissingBits = $missing
    }
}

# ------------------------- Load CSV & subs -----------------------------
$rows = Import-Csv -LiteralPath $InputCsvPath

$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
if ($subs -isnot [System.Collections.IEnumerable]) { $subs = ,$subs }
if (-not $subs -or $subs.Count -eq 0) {
    throw "No subscriptions resolved for $adh_group / $adh_subscription_type"
}

$out = @()

foreach ($sub in $subs) {

    Set-ScContext -Subscription $sub
    Write-Host "=== Subscription: $($sub.Name) ===" -ForegroundColor Cyan

    foreach ($r in $rows) {

        # Placeholder replacement
        $rgName = ($r.ResourceGroupName -replace '<Custodian>', $BaseCustodian).Trim()

        $saName = ($r.StorageAccountName -replace '<Custodian>', $BaseCustodian)
        $saName = ($saName -replace '<Cust>', $BaseCustLower).Trim()

        $cont = ($r.ContainerName -replace '<Custodian>', $BaseCustodian)
        $cont = ($cont -replace '<Cust>', $BaseCustLower).Trim()

        $idenRaw = $r.Identity
        $iden = ($idenRaw -replace '<Custodian>', $BaseCustodian)
        $iden = ($iden -replace '<Cust>', $BaseCustLower).Trim()

        $typeRaw = $r.Type
        if ($iden.ToUpper().EndsWith('_SPN')) { $type = 'SPN' }
        else {
            $t = ($typeRaw | ForEach-Object { "$_".Trim().ToUpper() })
            $type = if ($t -eq 'SPN') { 'SPN' } else { 'Group' }
        }

        # Env filter
        if ($adh_subscription_type -eq 'prd') {
            if ($saName -match 'adlsnonprd$') { continue }
        } else {
            if ($saName -match 'adlsprd$') { continue }
        }

        # AccessPath transform
        $accessPath = ($r.AccessPath -replace '<Custodian>', $BaseCustodian)
        $accessPath = ($accessPath -replace '<Cust>', $BaseCustLower).Trim()

        if ($accessPath -like '/catalog*') {
            $suffix = $accessPath.Substring('/catalog'.Length)
            $groupLower = $adh_group.ToLower()

            if ([string]::IsNullOrWhiteSpace($adh_sub_group)) {
                $accessPath = "/adh_${groupLower}${suffix}"
            } else {
                $subLower = $adh_sub_group.ToLower()
                $accessPath = "/adh_${groupLower}_${subLower}${suffix}"
            }
        }

        $normalizedPath = $accessPath
        if ($normalizedPath -eq '/') { $normalizedPath = '' }
        $folderForReport = if ([string]::IsNullOrWhiteSpace($normalizedPath)) { '/' } else { $normalizedPath }

        # Resolve storage account / container
        try {
            $sa = Get-AzStorageAccount -ResourceGroupName $rgName -Name $saName -ErrorAction Stop
            $ctx = $sa.Context
            $null = Get-AzStorageContainer -Name $cont -Context $ctx -ErrorAction Stop
        } catch {
            $out += [pscustomobject]@{
                SubscriptionName  = $sub.Name
                ResourceGroup     = $rgName
                Storage           = $saName
                Container         = $cont
                Folder            = $folderForReport
                Identity          = $iden
                RequiredPermission= $r.PermissionType
                ActualPermission  = ''
                MissingPermission = ''
                Status            = 'ERROR'
                Notes             = "Storage/container error: $($_.Exception.Message)"
            }
            continue
        }

        # Resolve identity objectId
        $objectId = Resolve-IdentityObjectId -IdentityName $iden -IdentityType $type
        if (-not $objectId) {
            $out += [pscustomobject]@{
                SubscriptionName  = $sub.Name
                ResourceGroup     = $rgName
                Storage           = $saName
                Container         = $cont
                Folder            = $folderForReport
                Identity          = $iden
                RequiredPermission= $r.PermissionType
                ActualPermission  = ''
                MissingPermission = ''
                Status            = 'ERROR'
                Notes             = "Identity '$iden' ($type) not found in Entra ID"
            }
            continue
        }

        # Check ACLs on: root + each parent + target
        $segments = @()
        if (-not [string]::IsNullOrWhiteSpace($normalizedPath)) {
            $segments = $normalizedPath.Trim('/') -split '/'
        }

        $pathsToCheck = @('')   # container root
        if ($segments.Count -gt 0) {
            $current = ''
            foreach ($seg in $segments) {
                $current = if ([string]::IsNullOrWhiteSpace($current)) { $seg } else { "$current/$seg" }
                $pathsToCheck += $current
            }
        }

        $requiredBits = RequiredBitsFromPermissionType -permType $r.PermissionType
        $actualBitsOverall = @{ r=$false; w=$false; x=$false }

        try {
            foreach ($p in $pathsToCheck) {

                $aclStrings = Get-AclStringsForPath -FileSystem $cont -Context $ctx -Path $p

                $parsedAccess  = Parse-AclString -AclString ($aclStrings.AccessAcl)  -Kind 'access'
                $parsedDefault = Parse-AclString -AclString ($aclStrings.DefaultAcl) -Kind 'default'

                $accessBits  = Get-EffectiveBitsFromAclSet -ParsedAcl $parsedAccess  -ObjectId $objectId
                $defaultBits = Get-EffectiveBitsFromAclSet -ParsedAcl $parsedDefault -ObjectId $objectId

                # Combine (scan all): access OR default (each already mask-limited)
                $combined = OrBits $accessBits $defaultBits

                $actualBitsOverall = OrBits $actualBitsOverall $combined
            }

            $cmp = Compare-RequiredVsActual -RequiredBits $requiredBits -ActualBits $actualBitsOverall

            $actualPerm  = BitsToPermString $actualBitsOverall
            $missingPerm = BitsToPermString $cmp.MissingBits

            $note =
                if ($cmp.Status -eq 'OK') { 'Required permissions satisfied (considering Access+Default with mask limits).' }
                elseif ($cmp.Status -eq 'PARTIAL') { 'Some required bits are missing. Actual computed from Access+Default with mask limits.' }
                else { 'No required bits found. Actual computed from Access+Default with mask limits.' }

            $out += [pscustomobject]@{
                SubscriptionName   = $sub.Name
                ResourceGroup      = $rgName
                Storage            = $saName
                Container          = $cont
                Folder             = $folderForReport
                Identity           = $iden
                RequiredPermission = $r.PermissionType
                ActualPermission   = $actualPerm
                MissingPermission  = $missingPerm
                Status             = $cmp.Status
                Notes              = $note
            }
        }
        catch {
            $out += [pscustomobject]@{
                SubscriptionName   = $sub.Name
                ResourceGroup      = $rgName
                Storage            = $saName
                Container          = $cont
                Folder             = $folderForReport
                Identity           = $iden
                RequiredPermission = $r.PermissionType
                ActualPermission   = ''
                MissingPermission  = ''
                Status             = 'ERROR'
                Notes              = "ACL read/compute error: $($_.Exception.Message)"
            }
        }
    }
}

if (-not $out -or $out.Count -eq 0) {
    $out += [pscustomobject]@{
        SubscriptionName   = ''
        ResourceGroup      = ''
        Storage            = ''
        Container          = ''
        Folder             = ''
        Identity           = ''
        RequiredPermission = ''
        ActualPermission   = ''
        MissingPermission  = ''
        Status             = 'NO_RESULTS'
        Notes              = 'Nothing matched in scan.'
    }
}

# ------------------------- Output filename format ----------------------
$yyyymmdd = (Get-Date).ToString('yyyyMMdd')

$prefix =
    if ([string]::IsNullOrWhiteSpace($adh_sub_group)) {
        "adls_acl_{0}_{1}" -f $adh_group, $yyyymmdd
    }
    else {
        "adls_acl_{0}_{1}_{2}" -f $adh_group, $adh_sub_group, $yyyymmdd
    }

$csvOut = Join-Path $OutputDir ($prefix + ".csv")
Write-CsvSafe -Rows $out -Path $csvOut

Write-Host "ADLS ACL scan completed."
Write-Host "CSV : $csvOut"
exit 0
