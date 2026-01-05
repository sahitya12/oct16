# sanitychecks/scripts/Scan-AdlsAcl.ps1
# Purpose:
#  - Validate ADLS Gen2 ACLs for given identities and paths (Access/Default)
#  - Fix MissingSources logic for ROOT '/' (must be AccessACL@'/')
#  - Use Azure CLI to fetch ACL (az storage fs access show) for reliability on agents
#
# INPUT CSV expected columns (minimum):
#   SubscriptionName (or SubscriptionId)
#   ResourceGroup
#   Storage          (storage account name)
#   Container        (filesystem)
#   Folder           (path, e.g. "/", "/adh_ktk", "/adh_ktk/ops")
#   Identity         (display name)
#   ValidationScope  ("access" or "default")
#   RequiredPerm     (e.g. "r-x", "rwx")
#
# OUTPUT CSV:
#   adls_acl_<adh_group>_<subscription_type>_YYYYMMDD.csv

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$ClientId,
    [Parameter(Mandatory)][string]$ClientSecret,

    [Parameter(Mandatory)][string]$adh_group,
    [ValidateSet('nonprd','prd')][string]$adh_subscription_type = 'nonprd',

    [Parameter(Mandatory)][string]$InputCsvPath,
    [Parameter(Mandatory)][string]$OutputDir
)

# -------------------- Utils --------------------
function Ensure-Dir {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
    return (Get-Item -LiteralPath $Path).FullName
}

function Is-RootPath {
    param([string]$Path)
    return ($Path -eq '/' -or [string]::IsNullOrWhiteSpace($Path))
}

function Normalize-Path {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return '/' }
    $p = $Path.Trim()
    if (-not $p.StartsWith('/')) { $p = '/' + $p }
    if ($p.Length -gt 1) { $p = $p.TrimEnd('/') } # keep "/" as "/"
    if ($p -eq '') { $p = '/' }
    return $p
}

function Get-ParentPath {
    param([string]$Path)
    $p = Normalize-Path $Path
    if (Is-RootPath $p) { return '' }
    $idx = $p.LastIndexOf('/')
    if ($idx -le 0) { return '/' }
    return $p.Substring(0, $idx)
}

function Perm-HasAllBits {
    param(
        [Parameter(Mandatory)][string]$Actual,
        [Parameter(Mandatory)][string]$Required
    )
    # perms look like: r-x, rwx, ---
    $a = $Actual.ToLowerInvariant()
    $r = $Required.ToLowerInvariant()

    $needR = ($r[0] -eq 'r')
    $needW = ($r[1] -eq 'w')
    $needX = ($r[2] -eq 'x')

    $hasR = ($a.Length -ge 1 -and $a[0] -eq 'r')
    $hasW = ($a.Length -ge 2 -and $a[1] -eq 'w')
    $hasX = ($a.Length -ge 3 -and $a[2] -eq 'x')

    if ($needR -and -not $hasR) { return $false }
    if ($needW -and -not $hasW) { return $false }
    if ($needX -and -not $hasX) { return $false }
    return $true
}

function Perm-MissingBits {
    param(
        [Parameter(Mandatory)][string]$Actual,
        [Parameter(Mandatory)][string]$Required
    )
    $a = $Actual.ToLowerInvariant()
    $r = $Required.ToLowerInvariant()

    $out = @('-','-','-')
    if ($r[0] -eq 'r' -and ($a.Length -lt 1 -or $a[0] -ne 'r')) { $out[0] = 'r' }
    if ($r[1] -eq 'w' -and ($a.Length -lt 2 -or $a[1] -ne 'w')) { $out[1] = 'w' }
    if ($r[2] -eq 'x' -and ($a.Length -lt 3 -or $a[2] -ne 'x')) { $out[2] = 'x' }
    return ($out -join '')
}

function Parse-AclString {
    param([Parameter(Mandatory)][string]$Acl)

    # Returns:
    #  Access = @{ userObjectIdPerms = @{}; groupObjectIdPerms=@{}; mask="rwx" }
    #  Default = @{ userObjectIdPerms = @{}; groupObjectIdPerms=@{}; mask="rwx" }
    $accUser = @{}
    $accGroup = @{}
    $defUser = @{}
    $defGroup = @{}
    $accMask = $null
    $defMask = $null

    $parts = $Acl.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }

    foreach ($p in $parts) {
        $isDefault = $false
        $entry = $p
        if ($entry.StartsWith('default:')) {
            $isDefault = $true
            $entry = $entry.Substring(8)
        }

        # examples:
        # user::rwx
        # user:<oid>:r-x
        # group:<oid>:r-x
        # mask::rwx
        # default:user:<oid>:r-x
        $tokens = $entry.Split(':')
        if ($tokens.Count -lt 3) { continue }

        $kind = $tokens[0]  # user/group/mask/other
        $idOrEmpty = $tokens[1]
        $perm = $tokens[2]

        if ($kind -eq 'mask' -and $idOrEmpty -eq '') {
            if ($isDefault) { $defMask = $perm } else { $accMask = $perm }
            continue
        }

        if ($kind -eq 'user' -and -not [string]::IsNullOrWhiteSpace($idOrEmpty)) {
            if ($isDefault) { $defUser[$idOrEmpty] = $perm } else { $accUser[$idOrEmpty] = $perm }
            continue
        }

        if ($kind -eq 'group' -and -not [string]::IsNullOrWhiteSpace($idOrEmpty)) {
            if ($isDefault) { $defGroup[$idOrEmpty] = $perm } else { $accGroup[$idOrEmpty] = $perm }
            continue
        }
    }

    return @{
        Access  = @{ User=$accUser; Group=$accGroup; Mask=$accMask }
        Default = @{ User=$defUser; Group=$defGroup; Mask=$defMask }
    }
}

function Apply-Mask {
    param(
        [Parameter(Mandatory)][string]$Perm,
        [string]$Mask
    )
    if ([string]::IsNullOrWhiteSpace($Mask)) { return $Perm }

    $p = $Perm.ToLowerInvariant()
    $m = $Mask.ToLowerInvariant()
    $out = @('-','-','-')

    if ($p[0] -eq 'r' -and $m[0] -eq 'r') { $out[0] = 'r' }
    if ($p[1] -eq 'w' -and $m[1] -eq 'w') { $out[1] = 'w' }
    if ($p[2] -eq 'x' -and $m[2] -eq 'x') { $out[2] = 'x' }

    return ($out -join '')
}

function AzCli {
    param([Parameter(Mandatory)][string]$Args)
    $out = & az $Args 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ($out | Out-String)
    }
    return ($out | Out-String)
}

function Ensure-AzCliLogin {
    # Use SPN login for CLI
    try { & az account show 1>$null 2>$null } catch {}
    try {
        & az login --service-principal -u $ClientId -p $ClientSecret --tenant $TenantId 1>$null 2>$null
    } catch {
        throw "Azure CLI login failed: $($_.Exception.Message)"
    }
}

function Set-AzCliSubscription {
    param([string]$SubscriptionIdOrName)
    & az account set --subscription $SubscriptionIdOrName 1>$null 2>$null
}

function Get-PathAclViaCli {
    param(
        [Parameter(Mandatory)][string]$Storage,
        [Parameter(Mandatory)][string]$Container,
        [Parameter(Mandatory)][string]$Path
    )
    $p = Normalize-Path $Path
    # az expects path without leading "/" for file system paths in many cases
    $cliPath = $p
    if ($cliPath.StartsWith('/')) { $cliPath = $cliPath.Substring(1) }
    if ($cliPath -eq '') { $cliPath = '/' } # root

    $json = AzCli "storage fs access show --account-name `"$Storage`" --file-system `"$Container`" --path `"$cliPath`" --auth-mode login --output json"
    return ($json | ConvertFrom-Json)
}

function Resolve-ObjectIdBestEffort {
    param(
        [string]$Identity,
        [string]$MaybeObjectId
    )
    # If CSV already has an object id, keep it
    if ($MaybeObjectId -and $MaybeObjectId -match '^[0-9a-fA-F-]{8,}$') { return $MaybeObjectId }

    # Best-effort resolve via AzureAD in subscription tenant
    try {
        Import-Module Az.Resources -ErrorAction Stop | Out-Null
        $sp = Get-AzADServicePrincipal -DisplayName $Identity -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($sp -and $sp.Id) { return $sp.Id }

        $grp = Get-AzADGroup -DisplayName $Identity -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($grp -and $grp.Id) { return $grp.Id }

        $usr = Get-AzADUser -UserPrincipalName $Identity -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($usr -and $usr.Id) { return $usr.Id }
    } catch {}
    return ''
}

# -------------------- Start --------------------
Import-Module Az.Accounts, Az.Resources -ErrorAction Stop

Ensure-Dir -Path $OutputDir | Out-Null
if (-not (Test-Path -LiteralPath $InputCsvPath)) { throw "InputCsvPath not found: $InputCsvPath" }

Ensure-AzCliLogin

$rows = Import-Csv -LiteralPath $InputCsvPath
if (-not $rows -or @($rows).Count -eq 0) { throw "Input CSV is empty." }

$results = New-Object System.Collections.Generic.List[object]

foreach ($r in $rows) {

    $subName = $r.SubscriptionName
    $subId   = $r.SubscriptionId
    $subKey  = if ($subId) { $subId } else { $subName }

    if ([string]::IsNullOrWhiteSpace($subKey)) {
        $results.Add([pscustomobject]@{
            SubscriptionName = $subName
            ResourceGroup    = $r.ResourceGroup
            Storage          = $r.Storage
            Container        = $r.Container
            Folder           = $r.Folder
            Identity         = $r.Identity
            ResolvedObjectId = ''
            ValidationScope  = $r.ValidationScope
            RequiredPerm     = $r.RequiredPerm
            ActualPerm       = ''
            MissingPerm      = ''
            Status           = 'ERROR'
            SatisfiedBy      = 'NONE'
            MissingSources   = 'NONE'
            AccessAcl        = ''
            DefaultAcl       = ''
            Note             = 'Missing SubscriptionName/Id'
        }) | Out-Null
        continue
    }

    try {
        Set-AzCliSubscription -SubscriptionIdOrName $subKey

        $storage = $r.Storage
        $container = $r.Container
        $folder = Normalize-Path $r.Folder
        $scope = ($r.ValidationScope ?? '').ToString().Trim().ToLowerInvariant()
        $required = ($r.RequiredPerm ?? '').ToString().Trim().ToLowerInvariant()
        $objId = Resolve-ObjectIdBestEffort -Identity $r.Identity -MaybeObjectId $r.ResolvedObjectId

        if ([string]::IsNullOrWhiteSpace($storage) -or [string]::IsNullOrWhiteSpace($container) -or [string]::IsNullOrWhiteSpace($folder)) {
            throw "Missing Storage/Container/Folder in CSV row."
        }
        if ($scope -notin @('access','default')) {
            throw "ValidationScope must be 'access' or 'default'."
        }
        if ($required.Length -ne 3) {
            throw "RequiredPerm must be like r-x / rwx / ---"
        }

        $aclObj = Get-PathAclViaCli -Storage $storage -Container $container -Path $folder
        $aclStr = $aclObj.acl
        if ([string]::IsNullOrWhiteSpace($aclStr)) { throw "ACL string empty from CLI." }

        $parsed = Parse-AclString -Acl $aclStr

        # Extract raw strings for output (optional)
        $accessAclText = ($aclStr.Split(',') | Where-Object { -not $_.Trim().StartsWith('default:') }) -join ','
        $defaultAclText = ($aclStr.Split(',') | Where-Object { $_.Trim().StartsWith('default:') }) -join ','

        # Choose map based on scope
        $map = if ($scope -eq 'access') { $parsed.Access } else { $parsed.Default }
        $mask = $map.Mask

        # Determine actual perm (prefer user entry, else group entry; you can extend if needed)
        $actualRaw = '---'
        $satisfiedBy = 'NONE'

        if ($objId -and $map.User.ContainsKey($objId)) {
            $actualRaw = $map.User[$objId]
            $satisfiedBy = "user:$objId"
        }
        elseif ($objId -and $map.Group.ContainsKey($objId)) {
            $actualRaw = $map.Group[$objId]
            $satisfiedBy = "group:$objId"
        }
        else {
            # Not found explicitly
            $actualRaw = '---'
            $satisfiedBy = 'NONE'
        }

        # Apply mask (mask applies to named user/group entries in POSIX ACL evaluation)
        $actual = Apply-Mask -Perm $actualRaw -Mask $mask

        $ok = Perm-HasAllBits -Actual $actual -Required $required
        $missingPerm = if ($ok) { '---' } else { Perm-MissingBits -Actual $actual -Required $required }
        $status = if ($ok) { 'OK' } else { 'MISSING' }

        # ---------- MissingSources (FIXED for root '/') ----------
        $missingSources = @()

        if ($status -eq 'MISSING') {
            if (Is-RootPath $folder) {
                # ROOT PATH: only Access ACL is relevant in practice.
                # Even if user asked "default", root can't "inherit", so show source clearly.
                $missingSources += "AccessACL@'/'"
            }
            else {
                if ($scope -eq 'access') {
                    $missingSources += "AccessACL@'$folder'"
                }
                else {
                    # default scope: the default ACL is defined on the folder itself
                    $missingSources += "DefaultACL@'$folder'"
                }
            }
        }

        $missingSourcesText = if ($missingSources.Count -eq 0) { 'NONE' } else { ($missingSources -join '; ') }

        $results.Add([pscustomobject]@{
            SubscriptionName = $subName
            ResourceGroup    = $r.ResourceGroup
            Storage          = $storage
            Container        = $container
            Folder           = $folder
            Identity         = $r.Identity
            ResolvedObjectId = $objId
            ValidationScope  = $scope
            RequiredPerm     = $required
            ActualPerm       = $actual
            MissingPerm      = $missingPerm
            Status           = $status
            SatisfiedBy      = $satisfiedBy
            MissingSources   = $missingSourcesText
            AccessAcl        = $accessAclText
            DefaultAcl       = $defaultAclText
            Note             = ''
        }) | Out-Null
    }
    catch {
        $results.Add([pscustomobject]@{
            SubscriptionName = $r.SubscriptionName
            ResourceGroup    = $r.ResourceGroup
            Storage          = $r.Storage
            Container        = $r.Container
            Folder           = $r.Folder
            Identity         = $r.Identity
            ResolvedObjectId = $r.ResolvedObjectId
            ValidationScope  = $r.ValidationScope
            RequiredPerm     = $r.RequiredPerm
            ActualPerm       = ''
            MissingPerm      = ''
            Status           = 'ERROR'
            SatisfiedBy      = 'NONE'
            MissingSources   = 'NONE'
            AccessAcl        = ''
            DefaultAcl       = ''
            Note             = $_.Exception.Message
        }) | Out-Null
    }
}

$stamp = Get-Date -Format 'yyyyMMdd'
$outFile = Join-Path $OutputDir ("adls_acl_{0}_{1}_{2}.csv" -f $adh_group, $adh_subscription_type, $stamp)

$results | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $outFile

Write-Host "DONE. Output: $outFile" -ForegroundColor Green
exit 0
