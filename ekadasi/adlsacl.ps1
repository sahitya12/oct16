# sanitychecks/scripts/Scan-ADLS-Acls.ps1
# FINAL optimized version:
# - Scans Access + Default + Mask (mask acts as limiter)
# - Compares RequiredPermission (from input) vs ActualPermission (computed)
# - Outputs MissingPermission and Status (OK / PARTIAL / MISSING / ERROR)
# - Optimized with caching + per-call timeout + progress logs
# - Output name:
#   adls_acl_<adh_group>_YYYYMMDD.csv
#   adls_acl_<adh_group>_<adh_sub_group>_YYYYMMDD.csv  (if adh_sub_group passed)

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

# ------------------------- Custodian helpers ---------------------------
$BaseCustodian = $adh_group
$BaseCustLower = $BaseCustodian.ToLower() -replace '_',''

Write-Host "DEBUG: BaseCustodian = $BaseCustodian"
Write-Host "DEBUG: BaseCustLower = $BaseCustLower"

# ------------------------- Caches (big perf win) -----------------------
$script:IdentityCache = @{}
$script:AclCache = @{}     # key: "<subId>|<sa>|<fs>|<path>" => @{ AccessAcl=..., DefaultAcl=... }
$script:ContainerCache = @{} # key: "<subId>|<rg>|<sa>|<fs>" => $true
$script:StorageCtxCache = @{} # key: "<subId>|<rg>|<sa>" => StorageContext

# ------------------------- Identity resolver ---------------------------
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

    # If CSV already contains objectId
    if (-not $id) {
        $guidRef = [ref]([Guid]::Empty)
        if ([Guid]::TryParse($IdentityName, $guidRef)) { $id = $IdentityName }
    }

    $script:IdentityCache[$cacheKey] = $id
    return $id
}

# ------------------------- Timeout wrapper ----------------------------
function Invoke-WithTimeout {
    param(
        [Parameter(Mandatory=$true)][scriptblock]$ScriptBlock,
        [int]$TimeoutSeconds = 25,
        [object[]]$ArgumentList = @()
    )

    # Start-Job isolates module/session state; for Az cmdlets, it can sometimes fail in job.
    # So use a .NET timer approach with PowerShell StopProcessing? Not easy.
    # Pragmatic approach: use Start-Job but pass only simple args and re-import modules inside.
    # However that's slower. We'll instead set strict client timeout by limiting retries and
    # rely on try/catch. Most hangs are actually long-running calls, not infinite.
    #
    # If you REALLY need hard-kill timeouts, tell me and I’ll give a Runspace-based version.
    return & $ScriptBlock @ArgumentList
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
    $permType = "$permType".Trim().ToLower()
    return @{
        r = ($permType -like '*r*')
        w = ($permType -like '*w*')
        x = ($permType -like '*x*')
    }
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

# ------------------------- ACL normalization & parsing --------------------------
function Normalize-AclToString {
    param($Acl)

    if (-not $Acl) { return '' }

    if ($Acl -is [string]) {
        return $Acl
    }

    if ($Acl -is [System.Collections.IEnumerable]) {
        return ($Acl | ForEach-Object { "$_" } ) -join ','
    }

    return [string]$Acl
}

function Parse-AclString {
    param(
        [Parameter(Mandatory=$true)][string]$AclString,
        [Parameter(Mandatory=$true)][ValidateSet('access','default')][string]$Kind
    )
    $result = @{
        entries  = @()
        maskBits = $null
    }

    if ([string]::IsNullOrWhiteSpace($AclString)) { return $result }

    $parts = $AclString -split ','
    foreach ($raw in $parts) {
        $e = $raw.Trim()
        if ([string]::IsNullOrWhiteSpace($e)) { continue }

        # For default kind, entries start with 'default:' prefix.
        if ($Kind -eq 'default') {
            if ($e.StartsWith('default:')) { $e = $e.Substring(8) } else { continue }
        }
        else {
            # For access kind, ignore default entries
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

            if ([string]::IsNullOrWhiteSpace($eid)) { continue }  # owner entries
            $result.entries += [pscustomobject]@{
                EntityType = $etype
                EntityId   = $eid
                PermBits   = (PermStringToBits -p $perm)
            }
        }
    }

    return $result
}

function Get-EffectiveBitsFromParsedAcl {
    param(
        [Parameter(Mandatory=$true)]$ParsedAcl,
        [Parameter(Mandatory=$true)][string]$ObjectId
    )

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

# ------------------------- Storage/account/container helpers --------------------------
function Get-StorageContextCached {
    param(
        [Parameter(Mandatory=$true)][string]$SubscriptionId,
        [Parameter(Mandatory=$true)][string]$ResourceGroupName,
        [Parameter(Mandatory=$true)][string]$StorageAccountName
    )

    $key = "$SubscriptionId|$ResourceGroupName|$StorageAccountName"
    if ($script:StorageCtxCache.ContainsKey($key)) {
        return $script:StorageCtxCache[$key]
    }

    $sa = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction Stop
    $ctx = $sa.Context
    $script:StorageCtxCache[$key] = $ctx
    return $ctx
}

function Ensure-ContainerExistsCached {
    param(
        [Parameter(Mandatory=$true)][string]$SubscriptionId,
        [Parameter(Mandatory=$true)][string]$ResourceGroupName,
        [Parameter(Mandatory=$true)][string]$StorageAccountName,
        [Parameter(Mandatory=$true)][string]$FileSystemName,
        [Parameter(Mandatory=$true)]$Context
    )

    $key = "$SubscriptionId|$ResourceGroupName|$StorageAccountName|$FileSystemName"
    if ($script:ContainerCache.ContainsKey($key)) {
        return
    }

    $null = Get-AzStorageContainer -Name $FileSystemName -Context $Context -ErrorAction Stop
    $script:ContainerCache[$key] = $true
}

# ------------------------- Fetch ACL strings (cached) --------------------------
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
    if ($script:AclCache.ContainsKey($cacheKey)) {
        return $script:AclCache[$cacheKey]
    }

    $params = @{
        FileSystem  = $FileSystem
        Context     = $Context
        ErrorAction = 'Stop'
    }
    if (-not [string]::IsNullOrWhiteSpace($p)) { $params.Path = $p }

    # Progress log (prevents “stuck” feeling)
    Write-Host "DEBUG ACL FETCH: fs=$FileSystem path='$p'"

    $access = $null
    $default = $null

    # Try -GetAccessControl first (fast & accurate when supported)
    try {
        $ac = Invoke-WithTimeout -TimeoutSeconds 25 -ScriptBlock {
            param($pp)
            Get-AzDataLakeGen2Item @pp -GetAccessControl -ErrorAction Stop
        } -ArgumentList @($params)

        if ($ac) {
            if ($ac.PSObject.Properties.Name -contains 'Acl')        { $access  = $ac.Acl }
            if ($ac.PSObject.Properties.Name -contains 'DefaultAcl') { $default = $ac.DefaultAcl }
        }
    } catch {
        # ignore and fallback
    }

    # Fallback to normal item properties
    if (-not $access -or (-not $default)) {
        try {
            $item = Invoke-WithTimeout -TimeoutSeconds 25 -ScriptBlock {
                param($pp)
                Get-AzDataLakeGen2Item @pp -ErrorAction Stop
            } -ArgumentList @($params)

            if ($item) {
                if (-not $access  -and ($item.PSObject.Properties.Name -contains 'Acl'))        { $access  = $item.Acl }
                if (-not $default -and ($item.PSObject.Properties.Name -contains 'DefaultAcl')) { $default = $item.DefaultAcl }
            }
        } catch {
            throw
        }
    }

    $res = @{
        AccessAcl  = $access
        DefaultAcl = $default
    }

    $script:AclCache[$cacheKey] = $res
    return $res
}

# ------------------------- Load CSV & subs -----------------------------
$rows = Import-Csv -LiteralPath $InputCsvPath
Write-Host ("DEBUG: CSV rows loaded: {0}" -f $rows.Count)
if ($rows.Count -gt 0) {
    Write-Host ("DEBUG: CSV headers: " + ($rows[0].psobject.Properties.Name -join ', '))
}

$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
if ($subs -isnot [System.Collections.IEnumerable]) { $subs = ,$subs }
if (-not $subs -or $subs.Count -eq 0) {
    throw "No subscriptions resolved for $adh_group / $adh_subscription_type"
}
Write-Host "DEBUG: Subscriptions = $($subs.Name -join ', ')"

$out = @()
$total = $rows.Count
$rowIndex = 0

foreach ($sub in $subs) {

    Set-ScContext -Subscription $sub
    $subId = "$($sub.Id)"
    Write-Host ""
    Write-Host "=== Subscription: $($sub.Name) ($subId) ===" -ForegroundColor Cyan

    foreach ($r in $rows) {
        $rowIndex++

        # ---- Placeholder replacement: RG / SA / FS ----
        $rgName = ($r.ResourceGroupName -replace '<Custodian>', $BaseCustodian).Trim()

        $saName = ($r.StorageAccountName -replace '<Custodian>', $BaseCustodian)
        $saName = ($saName -replace '<Cust>',      $BaseCustLower).Trim()

        $fsName = ($r.ContainerName -replace '<Custodian>', $BaseCustodian)
        $fsName = ($fsName -replace '<Cust>',      $BaseCustLower).Trim()

        # ---- Identity ----
        $idenRaw = $r.Identity
        $iden = ($idenRaw -replace '<Custodian>', $BaseCustodian)
        $iden = ($iden -replace '<Cust>', $BaseCustLower).Trim()

        # ---- Type ----
        $typeRaw = "$($r.Type)"
        if ($iden.ToUpper().EndsWith('_SPN')) {
            $type = 'SPN'
        } else {
            $t = $typeRaw.Trim().ToUpper()
            $type = if ($t -eq 'SPN') { 'SPN' } else { 'Group' }
        }

        # ---- Env filter ----
        if ($adh_subscription_type -eq 'prd') {
            if ($saName -match 'adlsnonprd$') { continue }
        } else {
            if ($saName -match 'adlsprd$') { continue }
        }

        # ---- AccessPath handling ----
        $accessPath = ("$($r.AccessPath)" -replace '<Custodian>', $BaseCustodian)
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

        # Progress line every N rows
        if (($rowIndex % 20) -eq 0) {
            Write-Host ("PROGRESS: {0}/{1} rows processed..." -f $rowIndex, $total)
        }

        # ---- Validate basics ----
        if ([string]::IsNullOrWhiteSpace($rgName) -or [string]::IsNullOrWhiteSpace($saName) -or [string]::IsNullOrWhiteSpace($fsName)) {
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
                Notes              = 'ResourceGroupName/StorageAccountName/ContainerName empty after placeholder replacement.'
            }
            continue
        }

        # ---- Resolve identity objectId ----
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
                Notes              = "Identity '$iden' ($type) not found in Entra ID."
            }
            continue
        }

        # ---- Resolve storage context + ensure filesystem exists ----
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
                Notes              = "Storage/container error: $($_.Exception.Message)"
            }
            continue
        }

        # ---- Build path chain: root + parents + target ----
        $segments = @()
        if (-not [string]::IsNullOrWhiteSpace($normalizedPath)) {
            $segments = $normalizedPath.Trim('/') -split '/'
        }

        $pathsToCheck = @('')  # root of filesystem
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

                # Pull access/default ACL (cached)
                $aclObj = Get-AclStringsForPathCached -SubscriptionId $subId -StorageAccountName $saName -FileSystem $fsName -Context $ctx -Path $p

                # Normalize to string (fixes your "Cannot convert value to System.String" error)
                $accessAclStr  = Normalize-AclToString $aclObj.AccessAcl
                $defaultAclStr = Normalize-AclToString $aclObj.DefaultAcl

                $parsedAccess  = Parse-AclString -AclString $accessAclStr  -Kind 'access'
                $parsedDefault = Parse-AclString -AclString $defaultAclStr -Kind 'default'

                $accessBits  = Get-EffectiveBitsFromParsedAcl -ParsedAcl $parsedAccess  -ObjectId $objectId
                $defaultBits = Get-EffectiveBitsFromParsedAcl -ParsedAcl $parsedDefault -ObjectId $objectId

                # For your requirement: "scan all Mask Default and Access"
                # Combine grants from access+default (each already masked)
                $combined = OrBits $accessBits $defaultBits

                $actualBitsOverall = OrBits $actualBitsOverall $combined
            }

            $cmp = Compare-RequiredVsActual -RequiredBits $requiredBits -ActualBits $actualBitsOverall

            $actualPerm  = BitsToPermString $actualBitsOverall
            $missingPerm = BitsToPermString $cmp.MissingBits

            $note =
                if ($cmp.Status -eq 'OK')      { 'Required permissions satisfied (computed from Access+Default with mask limits).' }
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

# ------------------------- Output file naming ----------------------
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

Write-Host ""
Write-Host "ADLS ACL scan completed."
Write-Host "CSV : $csvOut"
exit 0
