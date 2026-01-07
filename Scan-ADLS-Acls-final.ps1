# sanitychecks/scripts/Scan-ADLS-Acls.ps1
# FINAL SCRIPT (v8 - compliance mode)
# ✅ Validate ONLY the exact AccessPath from input (no parent/root inheritance)
# ✅ Scope-aware validation:
#    - scope=access  -> evaluate Access ACL only
#    - scope=default -> evaluate Default ACL only
#    - scope=both/empty -> evaluate Access+Default (union)
# ✅ MissingSources is STRICTLY scope-aware and target-path-only:
#    - AccessACLMissing / AccessEntryMissing
#    - DefaultACLMissing / DefaultEntryMissing
# ✅ Missing ACL strings are treated as empty (NOT ERROR)
# ✅ Root "/" always queried with --path "/"
# ✅ Status logic (based on target path only):
#    - OK      : all required bits present
#    - MISSING : none of required bits present
#    - PARTIAL : some present, some missing
# ✅ Excel #NAME? fix for perms like r--/---/--x via ExcelSafe everywhere
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

# -------------------- IO --------------------
Ensure-Dir -Path $OutputDir | Out-Null
if (-not (Test-Path -LiteralPath $InputCsvPath)) { throw "Input CSV not found: $InputCsvPath" }

if ($null -ne $adh_sub_group) { $adh_sub_group = $adh_sub_group.Trim() }
if ([string]::IsNullOrWhiteSpace($adh_sub_group)) { $adh_sub_group = '' }

# Custodian placeholder resolution:
# <Custodian> -> adh_group OR adh_group_adh_sub_group (underscore when subgroup provided)
$CustodianToken =
    if ([string]::IsNullOrWhiteSpace($adh_sub_group)) {
        $adh_group
    } else {
        "${adh_group}_${adh_sub_group}"
    }

Write-Host "DEBUG: TenantId      = $TenantId"
Write-Host "DEBUG: ClientId      = $ClientId"
Write-Host "DEBUG: adh_group     = $adh_group"
Write-Host "DEBUG: adh_sub_group = '$adh_sub_group'"
Write-Host "DEBUG: subscription  = $adh_subscription_type"
Write-Host "DEBUG: InputCsvPath  = $InputCsvPath"
Write-Host "DEBUG: OutputDir     = $OutputDir"
Write-Host "DEBUG: BranchName    = $BranchName"

# -------------------- Connect Az (your Common.psm1 helper) --------------------
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure connection failed."
}

# -------------------- Ensure Azure CLI + login --------------------
try { $null = az version | Out-String } catch { throw "Azure CLI 'az' not found on agent." }

& az login --service-principal -u $ClientId -p $ClientSecret --tenant $TenantId 1>$null 2>$null
if ($LASTEXITCODE -ne 0) { throw "az login failed for the provided SPN." }

# -------------------- Globals / caches --------------------
$BaseCustodian = $adh_group
$BaseCustLower = $BaseCustodian.ToLower() -replace '_',''

$script:IdentityCache = @{}
$script:AclCache      = @{}

# -------------------- Excel-safe helper (fix #NAME?) --------------------
function ExcelSafe([string]$s) {
    if ($null -eq $s) { return '' }
    $s = "$s"
    # Excel treats strings like --- or --x as formulas -> #NAME?
    if ($s -match '^[rwx-]{3}$') { return "'" + $s }
    return $s
}

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

# OK: none missing | MISSING: none satisfied | PARTIAL: some satisfied, some missing
function Compare-RequiredVsActual($req,$act) {
    $missing = @{
        r = ($req.r -and -not $act.r)
        w = ($req.w -and -not $act.w)
        x = ($req.x -and -not $act.x)
    }

    $satR = ($req.r -and $act.r)
    $satW = ($req.w -and $act.w)
    $satX = ($req.x -and $act.x)
    $anySatisfied = ($satR -or $satW -or $satX)

    $status =
        if (-not $missing.r -and -not $missing.w -and -not $missing.x) { 'OK' }
        elseif (-not $anySatisfied) { 'MISSING' }
        else { 'PARTIAL' }

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

    # Treat missing as empty (NOT ERROR)
    if ([string]::IsNullOrWhiteSpace($AclString)) { return $result }
    $result.Present = $true

    $parts = $AclString -split ','
    foreach ($raw in $parts) {
        $e = $raw.Trim()
        if ([string]::IsNullOrWhiteSpace($e)) { continue }

        # CLI default entries: default:user:<id>:r-x and default:mask::r-x
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

    # ROOT path fix: always query --path "/"
    $argsPath = if ([string]::IsNullOrWhiteSpace($p)) { @("--path","/") } else { @("--path",$p) }

    $accessAcl  = ''
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

        # Scope from input row:
        # expected values: Access | Default | Both (empty => Both)
        $scope = "$($r.Scope)".Trim().ToLower()
        if ([string]::IsNullOrWhiteSpace($scope)) { $scope = 'both' }
        if ($scope -notin @('access','default','both')) { $scope = 'both' }

        $rgName = ("$($r.ResourceGroupName)" -replace '<Custodian>', $BaseCustodian).Trim()

        $saName = ("$($r.StorageAccountName)" -replace '<Custodian>', $BaseCustodian)
        $saName = ($saName -replace '<Cust>', $BaseCustLower).Trim()

        $fsName = ("$($r.ContainerName)" -replace '<Custodian>', $BaseCustodian)
        $fsName = ($fsName -replace '<Cust>', $BaseCustLower).Trim()

        $iden = ("$($r.Identity)" -replace '<Custodian>', $CustodianToken).Trim()
$typeRaw = "$($r.Type)"
        $type =
            if ($iden.ToUpper().EndsWith('_SPN')) { 'SPN' }
            elseif ($typeRaw.Trim().ToUpper() -eq 'SPN') { 'SPN' }
            else { 'Group' }

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

        # normalize root
        $normalizedPath  = $accessPath
        if ($normalizedPath -eq '/') { $normalizedPath = '' } # root marker
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
                ValidationScope    = $scope

                RequiredPermission = ExcelSafe "$($r.PermissionType)"
                ActualPermission   = ExcelSafe ''
                MissingPermission  = ExcelSafe ''

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

        $requiredBits = RequiredBitsFromPermissionType -permType $r.PermissionType

        $targetAccessAclStr  = ''
        $targetDefaultAclStr = ''
        $targetAccessEntry   = ''
        $targetDefaultEntry  = ''

        try {
            # ✅ fetch ONLY the target path from input
            $aclObj = Get-AclStringsForPathCached -SubscriptionId $subId -StorageAccountName $saName -FileSystem $fsName -Path $normalizedPath
            if (-not [string]::IsNullOrWhiteSpace($aclObj.Err)) { throw $aclObj.Err }

            $targetAccessAclStr  = "$($aclObj.AccessAcl)"
            $targetDefaultAclStr = "$($aclObj.DefaultAcl)"

            $parsedAccess  = Parse-AclString -AclString $targetAccessAclStr  -Kind 'access'
            $parsedDefault = Parse-AclString -AclString $targetDefaultAclStr -Kind 'default'

            $targetAccessEntry   = Find-IdentityEntryText -AclString $targetAccessAclStr  -ObjectId $objectId -Kind 'access'
            $targetDefaultEntry  = Find-IdentityEntryText -AclString $targetDefaultAclStr -ObjectId $objectId -Kind 'default'

            $actualBits = @{ r=$false; w=$false; x=$false }

            if ($scope -eq 'access' -or $scope -eq 'both') {
                $actualBits = OrBits $actualBits (Get-EffectiveBitsFromParsedAcl -ParsedAcl $parsedAccess -ObjectId $objectId)
            }
            if ($scope -eq 'default' -or $scope -eq 'both') {
                $actualBits = OrBits $actualBits (Get-EffectiveBitsFromParsedAcl -ParsedAcl $parsedDefault -ObjectId $objectId)
            }

            $cmp = Compare-RequiredVsActual -req $requiredBits -act $actualBits

            $reqPerm     = ExcelSafe "$($r.PermissionType)"
            $actualPerm  = ExcelSafe (BitsToPermString $actualBits)
            $missingPerm = ExcelSafe (BitsToPermString $cmp.MissingBits)

            $missingSourcesText = ''
            if ($cmp.Status -ne 'OK') {
                $ms = New-Object System.Collections.Generic.List[string]

                if ($scope -eq 'access') {
                    if (-not $parsedAccess.Present) { $ms.Add("AccessACLMissing@'$folderForReport'") | Out-Null }
                    elseif ([string]::IsNullOrWhiteSpace($targetAccessEntry)) { $ms.Add("AccessEntryMissing@'$folderForReport'") | Out-Null }
                }
                elseif ($scope -eq 'default') {
                    if (-not $parsedDefault.Present) { $ms.Add("DefaultACLMissing@'$folderForReport'") | Out-Null }
                    elseif ([string]::IsNullOrWhiteSpace($targetDefaultEntry)) { $ms.Add("DefaultEntryMissing@'$folderForReport'") | Out-Null }
                }
                else {
                    if (-not $parsedAccess.Present) { $ms.Add("AccessACLMissing@'$folderForReport'") | Out-Null }
                    elseif ([string]::IsNullOrWhiteSpace($targetAccessEntry)) { $ms.Add("AccessEntryMissing@'$folderForReport'") | Out-Null }

                    if (-not $parsedDefault.Present) { $ms.Add("DefaultACLMissing@'$folderForReport'") | Out-Null }
                    elseif ([string]::IsNullOrWhiteSpace($targetDefaultEntry)) { $ms.Add("DefaultEntryMissing@'$folderForReport'") | Out-Null }
                }

                $missingSourcesText = ($ms | Select-Object -Unique) -join '; '
            }

            $note =
                if ($cmp.Status -eq 'OK') { 'Required permissions satisfied at target path (scope-aware, mask applied).' }
                elseif ($cmp.Status -eq 'PARTIAL') { 'Some required bits are satisfied at target path, but not all (scope-aware, mask applied).' }
                else { 'No required bits are satisfied at target path (scope-aware, mask applied).' }

            $out += [pscustomobject]@{
                SubscriptionName   = $sub.Name
                ResourceGroup      = $rgName
                Storage            = $saName
                Container          = $fsName
                Folder             = $folderForReport
                Identity           = $iden
                ResolvedObjectId   = $objectId
                ValidationScope    = $scope

                RequiredPermission = $reqPerm
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
                ResolvedObjectId   = $objectId
                ValidationScope    = $scope

                RequiredPermission = ExcelSafe "$($r.PermissionType)"
                ActualPermission   = ExcelSafe ''
                MissingPermission  = ExcelSafe ''

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
        ResolvedObjectId   = ''
        ValidationScope    = ''
        RequiredPermission = ExcelSafe ''
        ActualPermission   = ExcelSafe ''
        MissingPermission  = ExcelSafe ''
        Status             = 'NO_RESULTS'
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
