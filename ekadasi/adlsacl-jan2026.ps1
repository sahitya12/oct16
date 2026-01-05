# sanitychecks/scripts/Scan-ADLS-Acls.ps1
# FINAL SCRIPT (v2): fixes "PARTIAL" + fixes confusing MissingSources
# ✅ Reads ACLs using Azure CLI (az storage fs access show)
# ✅ ROOT path fix: uses --path "/"
# ✅ Missing Access/Default ACL => treated as empty (NOT ERROR)
# ✅ Status logic: if ANY required bit is missing => Status=MISSING (no PARTIAL)
# ✅ MissingSources: only populated when Status != OK, and only for the TARGET path
# ✅ Adds SatisfiedBy + ResolvedObjectId for easy troubleshooting
# ✅ Output filename:
#    adls_acl_<adh_group>_YYYYMMDD.csv
#    adls_acl_<adh_group>_<adh_sub_group>_YYYYMMDD.csv

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$TenantId,
    [Parameter(Mandatory=$true)][string]$ClientId,
    [Parameter(Mandatory=$true)][string]$ClientSecret,
    [Parameter(Mandatory=$true)][string]$adh_group,
    [string]$adh_sub_group = '',
    [ValidateSet('nonprd','prd')][string]$adh_subscription_type = 'nonprd',
    [Parameter(Mandatory=$true)][string]$InputCsvPath,
    [Parameter(Mandatory=$true)][string]$OutputDir,
    [string]$BranchName = ''
)

Import-Module Az.Accounts, Az.Resources -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

Ensure-Dir -Path $OutputDir | Out-Null
if (-not (Test-Path -LiteralPath $InputCsvPath)) { throw "Input CSV not found: $InputCsvPath" }

if ($null -ne $adh_sub_group) { $adh_sub_group = $adh_sub_group.Trim() }
if ([string]::IsNullOrWhiteSpace($adh_sub_group)) { $adh_sub_group = '' }

Write-Host "DEBUG: TenantId      = $TenantId"
Write-Host "DEBUG: ClientId      = $ClientId"
Write-Host "DEBUG: adh_group     = $adh_group"
Write-Host "DEBUG: adh_sub_group = '$adh_sub_group'"
Write-Host "DEBUG: subscription  = $adh_subscription_type"
Write-Host "DEBUG: InputCsvPath  = $InputCsvPath"
Write-Host "DEBUG: OutputDir     = $OutputDir"
Write-Host "DEBUG: BranchName    = $BranchName"

# --- Connect Az (subscription resolution helpers) ---
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure connection failed."
}

# --- Ensure Azure CLI is present + login with SPN ---
try { $null = az version | Out-String } catch { throw "Azure CLI 'az' not found on agent." }

& az login --service-principal -u $ClientId -p $ClientSecret --tenant $TenantId 1>$null 2>$null
if ($LASTEXITCODE -ne 0) { throw "az login failed for the provided SPN." }

$BaseCustodian = $adh_group
$BaseCustLower = $BaseCustodian.ToLower() -replace '_',''

$script:IdentityCache = @{}
$script:AclCache      = @{}

# -------------------- Identity resolver --------------------
function Resolve-IdentityObjectId {
    param(
        [Parameter(Mandatory=$true)][string]$IdentityName,
        [Parameter(Mandatory=$true)][ValidateSet('Group','SPN')][string]$IdentityType
    )

    $cacheKey = "$IdentityType|$IdentityName"
    if ($script:IdentityCache.ContainsKey($cacheKey)) { return $script:IdentityCache[$cacheKey] }

    $id = $null

    if ($IdentityType -eq 'Group') {
        try {
            $grp = Get-AzADGroup -DisplayName $IdentityName -ErrorAction Stop
            if ($grp -and $grp.Id) { $id = $grp.Id }
        } catch {}
    } else {
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

# -------------------- permission helpers --------------------
function PermStringToBits([string]$p) {
    $p = "$p".Trim()
    if ($p.Length -ne 3) { return @{ r=$false; w=$false; x=$false } }
    @{ r=($p[0]-eq'r'); w=($p[1]-eq'w'); x=($p[2]-eq'x') }
}
function BitsToPermString($b) {
    ("{0}{1}{2}" -f ($(if($b.r){'r'}else{'-'}), $(if($b.w){'w'}else{'-'}), $(if($b.x){'x'}else{'-'})))
}
function AndBits($a,$b){ @{ r=($a.r -and $b.r); w=($a.w -and $b.w); x=($a.x -and $b.x) } }
function OrBits($a,$b){ @{ r=($a.r -or  $b.r); w=($a.w -or  $b.w); x=($a.x -or  $b.x) } }

function RequiredBitsFromPermissionType([string]$permType) {
    $permType = "$permType".Trim().ToLower()
    @{ r=($permType -like '*r*'); w=($permType -like '*w*'); x=($permType -like '*x*') }
}

# ✅ No PARTIAL: any missing bit => MISSING
function Compare-RequiredVsActual($req,$act) {
    $missing = @{
        r = ($req.r -and -not $act.r)
        w = ($req.w -and -not $act.w)
        x = ($req.x -and -not $act.x)
    }
    $status = if (-not $missing.r -and -not $missing.w -and -not $missing.x) { 'OK' } else { 'MISSING' }
    @{ Status=$status; MissingBits=$missing }
}

# -------------------- ACL parsing --------------------
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

        # CLI default entries look like: default:user:<id>:r-x and default:mask::r-x
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
            if ([string]::IsNullOrWhiteSpace($eid)) { continue } # skip user::, group::
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

# -------------------- ACL fetch via Azure CLI (with ROOT fix) --------------------
function Get-AclStringsForPathCached {
    param(
        [Parameter(Mandatory=$true)][string]$SubscriptionId,
        [Parameter(Mandatory=$true)][string]$StorageAccountName,
        [Parameter(Mandatory=$true)][string]$FileSystem,
        [string]$Path
    )

    $p = if ($null -eq $Path) { '' } else { $Path }
    $cacheKey = "$SubscriptionId|$StorageAccountName|$FileSystem|$p"
    if ($script:AclCache.ContainsKey($cacheKey)) { return $script:AclCache[$cacheKey] }

    & az account set --subscription $SubscriptionId 1>$null 2>$null
    if ($LASTEXITCODE -ne 0) {
        $res = @{ AccessAcl=''; DefaultAcl=''; Err="az account set failed for subscription $SubscriptionId" }
        $script:AclCache[$cacheKey] = $res
        return $res
    }

    $argsBase = @("storage","fs","access","show","--account-name",$StorageAccountName,"--file-system",$FileSystem,"--auth-mode","login","-o","tsv")

    # Root fix: always pass a path, root must be "/"
    $argsPath = if ([string]::IsNullOrWhiteSpace($p)) { @("--path","/") } else { @("--path",$p) }

    $accessAcl = ''
    $defaultAcl = ''

    try {
        $accessAcl = & az @argsBase @argsPath "--query" "acl" 2>$null
        if ($LASTEXITCODE -ne 0) { $accessAcl = '' }
    } catch { $accessAcl = '' }

    try {
        $defaultAcl = & az @argsBase @argsPath "--query" "defaultAcl" 2>$null
        if ($LASTEXITCODE -ne 0) { $defaultAcl = '' }
    } catch { $defaultAcl = '' }

    $res = @{ AccessAcl="$accessAcl"; DefaultAcl="$defaultAcl"; Err='' }
    $script:AclCache[$cacheKey] = $res
    return $res
}

# -------------------- Load input + subscriptions --------------------
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
        $rgName = ("$($r.ResourceGroupName)" -replace '<Custodian>', $BaseCustodian).Trim()

        $saName = ("$($r.StorageAccountName)" -replace '<Custodian>', $BaseCustodian)
        $saName = ($saName -replace '<Cust>', $BaseCustLower).Trim()

        $fsName = ("$($r.ContainerName)" -replace '<Custodian>', $BaseCustodian)
        $fsName = ($fsName -replace '<Cust>', $BaseCustLower).Trim()

        $iden = ("$($r.Identity)" -replace '<Custodian>', $BaseCustodian)
        $iden = ($iden -replace '<Cust>', $BaseCustLower).Trim()

        $typeRaw = "$($r.Type)"
        $type =
            if ($iden.ToUpper().EndsWith('_SPN')) { 'SPN' }
            elseif ($typeRaw.Trim().ToUpper() -eq 'SPN') { 'SPN' }
            else { 'Group' }

        # env filter
        if ($adh_subscription_type -eq 'prd') { if ($saName -match 'adlsnonprd$') { continue } }
        else { if ($saName -match 'adlsprd$') { continue } }

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

        $objectId = Resolve-IdentityObjectId -IdentityName $iden -IdentityType $type
        if (-not $objectId) {
            $out += [pscustomobject]@{
                SubscriptionName   = $sub.Name
                ResourceGroup      = $rgName
                Storage            = $saName
                Container          = $fsName
                Folder             = $folderForReport
                Identity           = $iden
                ResolvedObjectId   = ''
                RequiredPermission = $r.PermissionType
                ActualPermission   = ''
                MissingPermission  = ''
                Status             = 'ERROR'
                SatisfiedBy        = 'NONE'
                MissingSources     = 'IDENTITY'
                AccessAclRaw       = ''
                DefaultAclRaw      = ''
                AccessEntryForId   = ''
                DefaultEntryForId  = ''
                Notes              = "Identity '$iden' ($type) not found in Entra ID."
            }
            continue
        }

        # Build chain: root + parents + target
        $segments = @()
        if (-not [string]::IsNullOrWhiteSpace($normalizedPath)) { $segments = $normalizedPath.Trim('/') -split '/' }

        $pathsToCheck = @('')  # root marker
        if ($segments.Count -gt 0) {
            $current = ''
            foreach ($seg in $segments) {
                $current = if ([string]::IsNullOrWhiteSpace($current)) { $seg } else { "$current/$seg" }
                $pathsToCheck += $current
            }
        }

        $requiredBits = RequiredBitsFromPermissionType -permType $r.PermissionType
        $actualBitsOverall = @{ r=$false; w=$false; x=$false }

        # track contributions
        $anyAccessContribution  = $false
        $anyDefaultContribution = $false

        # target visibility
        $targetAccessAclStr = ''
        $targetDefaultAclStr = ''
        $targetAccessEntry = ''
        $targetDefaultEntry = ''

        # last path presence (for MissingSources)
        $lastPath = $pathsToCheck[-1]
        $lastAccessPresent = $false
        $lastDefaultPresent = $false

        try {
            foreach ($p in $pathsToCheck) {
                $aclObj = Get-AclStringsForPathCached -SubscriptionId $subId -StorageAccountName $saName -FileSystem $fsName -Path $p
                if (-not [string]::IsNullOrWhiteSpace($aclObj.Err)) { throw $aclObj.Err }

                $accessAclStr  = "$($aclObj.AccessAcl)"
                $defaultAclStr = "$($aclObj.DefaultAcl)"

                $parsedAccess  = Parse-AclString -AclString $accessAclStr  -Kind 'access'
                $parsedDefault = Parse-AclString -AclString $defaultAclStr -Kind 'default'

                $accessBits  = Get-EffectiveBitsFromParsedAcl -ParsedAcl $parsedAccess  -ObjectId $objectId
                $defaultBits = Get-EffectiveBitsFromParsedAcl -ParsedAcl $parsedDefault -ObjectId $objectId

                if ($accessBits.r -or $accessBits.w -or $accessBits.x) { $anyAccessContribution = $true }
                if ($defaultBits.r -or $defaultBits.w -or $defaultBits.x) { $anyDefaultContribution = $true }

                $combined = OrBits $accessBits $defaultBits
                $actualBitsOverall = OrBits $actualBitsOverall $combined

                if ($p -eq $pathsToCheck[-1]) {
                    $targetAccessAclStr  = $accessAclStr
                    $targetDefaultAclStr = $defaultAclStr
                    $targetAccessEntry   = Find-IdentityEntryText -AclString $accessAclStr  -ObjectId $objectId -Kind 'access'
                    $targetDefaultEntry  = Find-IdentityEntryText -AclString $defaultAclStr -ObjectId $objectId -Kind 'default'
                    $lastPath = $p
                    $lastAccessPresent  = $parsedAccess.Present
                    $lastDefaultPresent = $parsedDefault.Present
                }
            }

            $cmp = Compare-RequiredVsActual -req $requiredBits -act $actualBitsOverall

            $actualPerm  = BitsToPermString $actualBitsOverall
            $missingPerm = BitsToPermString $cmp.MissingBits

            $satisfiedBy =
                if ($cmp.Status -eq 'OK' -and $anyAccessContribution -and $anyDefaultContribution) { 'BOTH' }
                elseif ($cmp.Status -eq 'OK' -and $anyAccessContribution) { 'ACCESS' }
                elseif ($cmp.Status -eq 'OK' -and $anyDefaultContribution) { 'DEFAULT' }
                elseif ($cmp.Status -eq 'OK') { 'UNKNOWN' }
                else { 'NONE' }

            # ✅ MissingSources only when permission is actually missing, and only for TARGET path
            $missingSourcesText = ''
            if ($cmp.Status -ne 'OK') {
                $ms = New-Object System.Collections.Generic.List[string]
                if (-not $lastAccessPresent)  { $ms.Add("AccessACL@'$lastPath'")  | Out-Null }
                if (-not $lastDefaultPresent) { $ms.Add("DefaultACL@'$lastPath'") | Out-Null }
                $missingSourcesText = ($ms | Select-Object -Unique) -join '; '
            }

            $note =
                if ($cmp.Status -eq 'OK') { 'Required permissions satisfied (computed from Access+Default with mask limits).' }
                else { 'Required bits not satisfied (computed from Access+Default with mask limits).' }

            $out += [pscustomobject]@{
                SubscriptionName   = $sub.Name
                ResourceGroup      = $rgName
                Storage            = $saName
                Container          = $fsName
                Folder             = $folderForReport
                Identity           = $iden
                ResolvedObjectId   = $objectId
                RequiredPermission = $r.PermissionType
                ActualPermission   = $actualPerm
                MissingPermission  = $missingPerm
                Status             = $cmp.Status
                SatisfiedBy        = $satisfiedBy
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
                ResolvedObjectId   = $objectId
                RequiredPermission = $r.PermissionType
                ActualPermission   = ''
                MissingPermission  = ''
                Status             = 'ERROR'
                SatisfiedBy        = 'NONE'
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
        ResolvedObjectId   = ''
        RequiredPermission = ''
        ActualPermission   = ''
        MissingPermission  = ''
        Status             = 'NO_RESULTS'
        SatisfiedBy        = 'NONE'
        MissingSources     = ''
        AccessAclRaw       = ''
        DefaultAclRaw      = ''
        AccessEntryForId   = ''
        DefaultEntryForId  = ''
        Notes              = 'Nothing matched in scan.'
    }
}

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
