# sanitychecks/scripts/Scan-ADLS-Acls.ps1
# FINAL working code (compatible with very old Az.Storage on ADO agents)
# - Uses ONLY: Get-AzDataLakeGen2Item -IncludeAcl  (no -GetAccessControl, no Get-AzDataLakeGen2ItemAclObject)
# - Scans Access + Default + Mask (mask-limited) across root + parents + target path
# - If input has rwx and actual is r-x => Status PARTIAL and MissingPermission = -w-
# - If Access ACL missing OR Default ACL missing => NOT ERROR (treated as empty, as you asked)
# - Output filename:
#     adls_acl_<adh_group>_YYYYMMDD.csv
#     adls_acl_<adh_group>_<adh_sub_group>_YYYYMMDD.csv (if adh_sub_group passed)

[CmdletBinding()]
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

# ------------------------- Normalize subgroup --------------------------
if ($null -ne $adh_sub_group) { $adh_sub_group = $adh_sub_group.Trim() }
if ([string]::IsNullOrWhiteSpace($adh_sub_group)) { $adh_sub_group = '' }

Ensure-Dir -Path $OutputDir | Out-Null
if (-not (Test-Path -LiteralPath $InputCsvPath)) { throw "Input CSV not found: $InputCsvPath" }

Write-Host "DEBUG: TenantId      = $TenantId"
Write-Host "DEBUG: ClientId      = $ClientId"
Write-Host "DEBUG: adh_group     = $adh_group"
Write-Host "DEBUG: adh_sub_group = '$adh_sub_group'"
Write-Host "DEBUG: subscription  = $adh_subscription_type"
Write-Host "DEBUG: InputCsvPath  = $InputCsvPath"
Write-Host "DEBUG: OutputDir     = $OutputDir"
Write-Host "DEBUG: BranchName    = $BranchName"

# ------------------------- Connect to Azure ----------------------------
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure connection failed."
}

$BaseCustodian = $adh_group
$BaseCustLower = $BaseCustodian.ToLower() -replace '_',''

# ------------------------- Caches ------------------------
$script:IdentityCache   = @{}
$script:AclCache        = @{}  # key: "<subId>|<sa>|<fs>|<path>" => @{ AccessAcl=..., DefaultAcl=... }
$script:ContainerCache  = @{}  # key: "<subId>|<rg>|<sa>|<fs>" => $true
$script:StorageCtxCache = @{}  # key: "<subId>|<rg>|<sa>" => StorageContext

# ------------------------- Identity resolver ---------------------------
function Resolve-IdentityObjectId {
    param(
        [Parameter(Mandatory = $true)][string]$IdentityName,
        [Parameter(Mandatory = $true)][ValidateSet('Group','SPN')][string]$IdentityType
    )

    $cacheKey = "$IdentityType|$IdentityName"
    if ($script:IdentityCache.ContainsKey($cacheKey)) { return $script:IdentityCache[$cacheKey] }

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

    # allow objectId directly in CSV
    if (-not $id) {
        $guidRef = [ref]([Guid]::Empty)
        if ([Guid]::TryParse($IdentityName, $guidRef)) { $id = $IdentityName }
    }

    $script:IdentityCache[$cacheKey] = $id
    return $id
}

# ------------------------- Permission helpers --------------------------
function PermStringToBits([string]$p) {
    $p = "$p".Trim()
    if ($p.Length -ne 3) { return @{ r=$false; w=$false; x=$false } }
    return @{ r=($p[0]-eq'r'); w=($p[1]-eq'w'); x=($p[2]-eq'x') }
}
function BitsToPermString($b) {
    return ("{0}{1}{2}" -f ($(if($b.r){'r'}else{'-'}), $(if($b.w){'w'}else{'-'}), $(if($b.x){'x'}else{'-'})))
}
function AndBits($a,$b){ @{ r=($a.r -and $b.r); w=($a.w -and $b.w); x=($a.x -and $b.x) } }
function OrBits($a,$b){ @{ r=($a.r -or  $b.r); w=($a.w -or  $b.w); x=($a.x -or  $b.x) } }

function RequiredBitsFromPermissionType([string]$permType) {
    $permType = "$permType".Trim().ToLower()
    return @{ r=($permType -like '*r*'); w=($permType -like '*w*'); x=($permType -like '*x*') }
}
function Compare-RequiredVsActual($req,$act) {
    $missing = @{
        r = ($req.r -and -not $act.r)
        w = ($req.w -and -not $act.w)
        x = ($req.x -and -not $act.x)
    }
    $status =
        if (-not $req.r -and -not $req.w -and -not $req.x) { 'OK' }
        elseif (-not $missing.r -and -not $missing.w -and -not $missing.x) { 'OK' }
        elseif ($missing.r -and $missing.w -and $missing.x) { 'MISSING' }
        else { 'PARTIAL' }

    return @{ Status=$status; MissingBits=$missing }
}

# ------------------------- ACL normalization & parsing --------------------------
function Normalize-AclToString($Acl) {
    if ($null -eq $Acl) { return '' }
    if ($Acl -is [string]) { return $Acl }
    if ($Acl -is [System.Collections.IEnumerable]) { return (($Acl | ForEach-Object { "$_" }) -join ',') }
    return [string]$Acl
}

function Parse-AclString {
    param(
        [AllowNull()][AllowEmptyString()][string]$AclString = '',
        [Parameter(Mandatory=$true)][ValidateSet('access','default')][string]$Kind
    )

    $result = @{
        Present     = $false
        MaskPresent = $false
        entries     = @()
        maskBits    = $null
    }

    if ([string]::IsNullOrWhiteSpace($AclString)) { return $result }
    $result.Present = $true

    $parts = $AclString -split ','
    foreach ($raw in $parts) {
        $e = $raw.Trim()
        if ([string]::IsNullOrWhiteSpace($e)) { continue }

        if ($Kind -eq 'default') {
            if ($e.StartsWith('default:')) { $e = $e.Substring(8) } else { continue }
        } else {
            if ($e.StartsWith('default:')) { continue }
        }

        if ($e -match '^mask::([rwx-]{3})$') {
            $result.maskBits = (PermStringToBits $Matches[1])
            $result.MaskPresent = $true
            continue
        }

        if ($e -match '^(user|group):([^:]*):([rwx-]{3})$') {
            $etype = $Matches[1]
            $eid   = $Matches[2]
            $perm  = $Matches[3]
            if ([string]::IsNullOrWhiteSpace($eid)) { continue } # owner entries
            $result.entries += [pscustomobject]@{
                EntityType = $etype
                EntityId   = $eid
                PermBits   = (PermStringToBits $perm)
            }
        }
    }

    return $result
}

function Get-EffectiveBitsFromParsedAcl($ParsedAcl, [string]$ObjectId) {
    $bits = @{ r=$false; w=$false; x=$false }
    foreach ($e in $ParsedAcl.entries) {
        if ($e.EntityId -eq $ObjectId) {
            $b = $e.PermBits
            if ($ParsedAcl.maskBits) { $b = AndBits $b $ParsedAcl.maskBits }
            $bits = OrBits $bits $b
        }
    }
    return $bits
}

function Find-IdentityEntryText {
    param(
        [AllowNull()][AllowEmptyString()][string]$AclString = '',
        [Parameter(Mandatory=$true)][string]$ObjectId,
        [ValidateSet('access','default')][string]$Kind = 'access'
    )

    if ([string]::IsNullOrWhiteSpace($AclString)) { return '' }

    $parts = $AclString -split ','
    foreach ($raw in $parts) {
        $e = $raw.Trim()
        if ([string]::IsNullOrWhiteSpace($e)) { continue }

        if ($Kind -eq 'default') {
            if ($e.StartsWith('default:')) { $e = $e.Substring(8) } else { continue }
        } else {
            if ($e.StartsWith('default:')) { continue }
        }

        if ($e -match "^(user|group):$([regex]::Escape($ObjectId)):([rwx-]{3})$") {
            return $e
        }
    }
    return ''
}

# ------------------------- Storage helpers --------------------------
function Get-StorageContextCached([string]$SubscriptionId,[string]$ResourceGroupName,[string]$StorageAccountName) {
    $key = "$SubscriptionId|$ResourceGroupName|$StorageAccountName"
    if ($script:StorageCtxCache.ContainsKey($key)) { return $script:StorageCtxCache[$key] }
    $sa  = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction Stop
    $ctx = $sa.Context
    $script:StorageCtxCache[$key] = $ctx
    return $ctx
}

function Ensure-ContainerExistsCached([string]$SubscriptionId,[string]$ResourceGroupName,[string]$StorageAccountName,[string]$FileSystemName,$Context) {
    $key = "$SubscriptionId|$ResourceGroupName|$StorageAccountName|$FileSystemName"
    if ($script:ContainerCache.ContainsKey($key)) { return }
    $null = Get-AzStorageContainer -Name $FileSystemName -Context $Context -ErrorAction Stop
    $script:ContainerCache[$key] = $true
}

# ------------------------- ACL fetch (MOST compatible) --------------------------
function Get-AclStringsForPathCached {
    param(
        [Parameter(Mandatory=$true)][string]$SubscriptionId,
        [Parameter(Mandatory=$true)][string]$StorageAccountName,
        [Parameter(Mandatory=$true)][string]$FileSystem,
        [Parameter(Mandatory=$true)]$Context,
        [string]$Path
    )

    $p = if ($null -eq $Path) { '' } else { $Path }
    $cacheKey = "$SubscriptionId|$StorageAccountName|$FileSystem|$p"
    if ($script:AclCache.ContainsKey($cacheKey)) { return $script:AclCache[$cacheKey] }

    $params = @{
        FileSystem  = $FileSystem
        Context     = $Context
        ErrorAction = 'Stop'
    }
    if (-not [string]::IsNullOrWhiteSpace($p)) { $params.Path = $p }

    Write-Host "DEBUG ACL FETCH: fs=$FileSystem path='$p'"

    # ✅ Works on older Az.Storage: returns item + AccessControl object
    $item = Get-AzDataLakeGen2Item @params -IncludeAcl

    $access  = $null
    $default = $null

    if ($item -and $item.AccessControl) {
        $access  = $item.AccessControl.Acl
        $default = $item.AccessControl.DefaultAcl
    }

    $res = @{ AccessAcl=$access; DefaultAcl=$default }
    $script:AclCache[$cacheKey] = $res
    return $res
}

# ------------------------- Load CSV & subs -----------------------------
$rows = Import-Csv -LiteralPath $InputCsvPath

$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
if ($subs -isnot [System.Collections.IEnumerable]) { $subs = ,$subs }
if (-not $subs -or $subs.Count -eq 0) { throw "No subscriptions resolved for $adh_group / $adh_subscription_type" }

$out = @()

foreach ($sub in $subs) {
    Set-ScContext -Subscription $sub
    $subId = "$($sub.Id)"
    Write-Host ""
    Write-Host "=== Subscription: $($sub.Name) ($subId) ===" -ForegroundColor Cyan

    foreach ($r in $rows) {
        $missingSrc = New-Object System.Collections.Generic.List[string]

        # Replace placeholders
        $rgName = ("$($r.ResourceGroupName)" -replace '<Custodian>', $BaseCustodian).Trim()

        $saName = ("$($r.StorageAccountName)" -replace '<Custodian>', $BaseCustodian)
        $saName = ($saName -replace '<Cust>', $BaseCustLower).Trim()

        $fsName = ("$($r.ContainerName)" -replace '<Custodian>', $BaseCustodian)
        $fsName = ($fsName -replace '<Cust>', $BaseCustLower).Trim()

        $iden = ("$($r.Identity)" -replace '<Custodian>', $BaseCustodian)
        $iden = ($iden -replace '<Cust>', $BaseCustLower).Trim()

        # Type
        $typeRaw = "$($r.Type)"
        $type =
            if ($iden.ToUpper().EndsWith('_SPN')) { 'SPN' }
            elseif ($typeRaw.Trim().ToUpper() -eq 'SPN') { 'SPN' }
            else { 'Group' }

        # env filter
        if ($adh_subscription_type -eq 'prd') { if ($saName -match 'adlsnonprd$') { continue } }
        else { if ($saName -match 'adlsprd$') { continue } }

        # AccessPath
        $accessPath = ("$($r.AccessPath)" -replace '<Custodian>', $BaseCustodian)
        $accessPath = ($accessPath -replace '<Cust>', $BaseCustLower).Trim()

        # /catalog -> /adh_<group>[_<subgroup>]
        if ($accessPath -like '/catalog*') {
            $suffix = $accessPath.Substring('/catalog'.Length)
            $g = $adh_group.ToLower()
            if ([string]::IsNullOrWhiteSpace($adh_sub_group)) {
                $accessPath = "/adh_${g}${suffix}"
            } else {
                $accessPath = "/adh_${g}_$($adh_sub_group.ToLower())${suffix}"
            }
        }

        $normalizedPath = $accessPath
        if ($normalizedPath -eq '/') { $normalizedPath = '' }
        $folderForReport = if ([string]::IsNullOrWhiteSpace($normalizedPath)) { '/' } else { $normalizedPath }

        # Resolve identity objectId
        $objectId = Resolve-IdentityObjectId -IdentityName $iden -IdentityType $type
        if (-not $objectId) {
            $out += [pscustomobject]@{
                SubscriptionName   = $sub.Name
                ResourceGroup      = $rgName
                Storage            = $saName
                Container          = $fsName
                Folder             = $folderForReport
                Identity           = $iden
                RequiredPermission = $r.PermissionType
                ActualPermission   = ''
                MissingPermission  = ''
                Status             = 'ERROR'
                MissingSources     = 'IDENTITY'
                AccessAclRaw       = ''
                DefaultAclRaw      = ''
                AccessEntryForId   = ''
                DefaultEntryForId  = ''
                Notes              = "Identity '$iden' ($type) not found in Entra ID."
            }
            continue
        }

        # Resolve storage context + ensure filesystem exists
        try {
            $ctx = Get-StorageContextCached -SubscriptionId $subId -ResourceGroupName $rgName -StorageAccountName $saName
            Ensure-ContainerExistsCached -SubscriptionId $subId -ResourceGroupName $rgName -StorageAccountName $saName -FileSystemName $fsName -Context $ctx
        } catch {
            $out += [pscustomobject]@{
                SubscriptionName   = $sub.Name
                ResourceGroup      = $rgName
                Storage            = $saName
                Container          = $fsName
                Folder             = $folderForReport
                Identity           = $iden
                RequiredPermission = $r.PermissionType
                ActualPermission   = ''
                MissingPermission  = ''
                Status             = 'ERROR'
                MissingSources     = 'STORAGE'
                AccessAclRaw       = ''
                DefaultAclRaw      = ''
                AccessEntryForId   = ''
                DefaultEntryForId  = ''
                Notes              = "Storage/container error: $($_.Exception.Message)"
            }
            continue
        }

        # Build path chain: root + parents + target
        $segments = @()
        if (-not [string]::IsNullOrWhiteSpace($normalizedPath)) { $segments = $normalizedPath.Trim('/') -split '/' }

        $pathsToCheck = @('')
        if ($segments.Count -gt 0) {
            $current = ''
            foreach ($seg in $segments) {
                $current = if ([string]::IsNullOrWhiteSpace($current)) { $seg } else { "$current/$seg" }
                $pathsToCheck += $current
            }
        }

        $requiredBits = RequiredBitsFromPermissionType -permType $r.PermissionType
        $actualBitsOverall = @{ r=$false; w=$false; x=$false }

        # Visibility for TARGET path only
        $targetAccessAclStr = ''
        $targetDefaultAclStr = ''
        $targetAccessEntry = ''
        $targetDefaultEntry = ''

        try {
            foreach ($p in $pathsToCheck) {
                $aclObj = Get-AclStringsForPathCached -SubscriptionId $subId -StorageAccountName $saName -FileSystem $fsName -Context $ctx -Path $p

                $accessAclStr  = Normalize-AclToString $aclObj.AccessAcl
                $defaultAclStr = Normalize-AclToString $aclObj.DefaultAcl

                # Per your requirement: missing Access/Default is treated as EMPTY (NOT ERROR)
                $parsedAccess  = Parse-AclString -AclString $accessAclStr  -Kind 'access'
                $parsedDefault = Parse-AclString -AclString $defaultAclStr -Kind 'default'

                if (-not $parsedAccess.Present)  { $missingSrc.Add("AccessACL@'$p'")  | Out-Null }
                if (-not $parsedDefault.Present) { $missingSrc.Add("DefaultACL@'$p'") | Out-Null }
                if ($parsedAccess.Present -and -not $parsedAccess.MaskPresent)   { $missingSrc.Add("AccessMask@'$p'")  | Out-Null }
                if ($parsedDefault.Present -and -not $parsedDefault.MaskPresent) { $missingSrc.Add("DefaultMask@'$p'") | Out-Null }

                $accessBits  = Get-EffectiveBitsFromParsedAcl -ParsedAcl $parsedAccess  -ObjectId $objectId
                $defaultBits = Get-EffectiveBitsFromParsedAcl -ParsedAcl $parsedDefault -ObjectId $objectId

                # Access + Default => OR
                $combined = OrBits $accessBits $defaultBits
                $actualBitsOverall = OrBits $actualBitsOverall $combined

                # capture TARGET path ACL strings + identity entry
                if ($p -eq $pathsToCheck[-1]) {
                    $targetAccessAclStr  = $accessAclStr
                    $targetDefaultAclStr = $defaultAclStr
                    $targetAccessEntry   = Find-IdentityEntryText -AclString $accessAclStr  -ObjectId $objectId -Kind 'access'
                    $targetDefaultEntry  = Find-IdentityEntryText -AclString $defaultAclStr -ObjectId $objectId -Kind 'default'
                }
            }

            $cmp = Compare-RequiredVsActual -req $requiredBits -act $actualBitsOverall
            $actualPerm  = BitsToPermString $actualBitsOverall
            $missingPerm = BitsToPermString $cmp.MissingBits
            $missingSourcesText = (($missingSrc | Select-Object -Unique) -join '; ')

            $note =
                if ($cmp.Status -eq 'OK') { 'Required permissions satisfied (computed from Access+Default with mask limits).' }
                elseif ($cmp.Status -eq 'PARTIAL') { 'Some required bits are missing (computed from Access+Default with mask limits).' }
                else { 'Required bits not satisfied (computed from Access+Default with mask limits).' }

            $out += [pscustomobject]@{
                SubscriptionName   = $sub.Name
                ResourceGroup      = $rgName
                Storage            = $saName
                Container          = $fsName
                Folder             = $folderForReport
                Identity           = $iden
                RequiredPermission = $r.PermissionType
                ActualPermission   = $actualPerm
                MissingPermission  = $missingPerm
                Status             = $cmp.Status
                MissingSources     = $missingSourcesText
                AccessAclRaw       = $targetAccessAclStr
                DefaultAclRaw      = $targetDefaultAclStr
                AccessEntryForId   = $targetAccessEntry
                DefaultEntryForId  = $targetDefaultEntry
                Notes              = $note
            }
        }
        catch {
            $out += [pscustomobject]@{
                SubscriptionName   = $sub.Name
                ResourceGroup      = $rgName
                Storage            = $saName
                Container          = $fsName
                Folder             = $folderForReport
                Identity           = $iden
                RequiredPermission = $r.PermissionType
                ActualPermission   = ''
                MissingPermission  = ''
                Status             = 'ERROR'
                MissingSources     = 'ACL_READ'
                AccessAclRaw       = $targetAccessAclStr
                DefaultAclRaw      = $targetDefaultAclStr
                AccessEntryForId   = $targetAccessEntry
                DefaultEntryForId  = $targetDefaultEntry
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
        MissingSources     = ''
        AccessAclRaw       = ''
        DefaultAclRaw      = ''
        AccessEntryForId   = ''
        DefaultEntryForId  = ''
        Notes              = 'Nothing matched in scan.'
    }
}

# ------------------------- Output filename ----------------------
$yyyymmdd = (Get-Date).ToString('yyyyMMdd')
$prefix =
    if ([string]::IsNullOrWhiteSpace($adh_sub_group)) {
        "adls_acl_{0}_{1}" -f $adh_group, $yyyymmdd
    } else {
        "adls_acl_{0}_{1}_{2}" -f $adh_group, $adh_sub_group, $yyyymmdd
    }

$csvOut = Join-Path $OutputDir ($prefix + ".csv")
Write-CsvSafe -Rows $out -Path $csvOut

Write-Host ""
Write-Host "ADLS ACL scan completed."
Write-Host "CSV : $csvOut"
exit 0
