# sanitychecks/scripts/Scan-ADLS-Acls.ps1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$TenantId,
    [Parameter(Mandatory = $true)][string]$ClientId,
    [Parameter(Mandatory = $true)][string]$ClientSecret,

    [Parameter(Mandatory = $true)][string]$adh_group,

    # comes as "" or " " from pipeline when optional
    [string]$adh_sub_group = '',

    [ValidateSet('nonprd','prd')][string]$adh_subscription_type = 'nonprd',

    [Parameter(Mandatory = $true)][string]$InputCsvPath,
    [Parameter(Mandatory = $true)][string]$OutputDir,

    # keep this so pipeline can pass it without failing
    [string]$BranchName = ''
)

Import-Module Az.Accounts, Az.Resources, Az.Storage -ErrorAction Stop

# ----------------------------- Common helpers (self-contained) -----------------------------
function Ensure-Dir([Parameter(Mandatory)][string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}
function Write-CsvSafe([Parameter(Mandatory)]$Rows, [Parameter(Mandatory)][string]$Path) {
    $Rows | Export-Csv -Path $Path -NoTypeInformation -Force -Encoding UTF8
}
function New-StampedPath([Parameter(Mandatory)][string]$BaseDir, [Parameter(Mandatory)][string]$Prefix) {
    $stamp = Get-Date -Format 'yyyyMMdd'
    return (Join-Path $BaseDir ("{0}_{1}.csv" -f $Prefix, $stamp))
}

# ----------------------------- Normalize adh_sub_group -----------------------------
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

Ensure-Dir -Path $OutputDir | Out-Null
if (-not (Test-Path -LiteralPath $InputCsvPath)) { throw "ADLS CSV not found: $InputCsvPath" }

# ----------------------------- Connect (same style as RG permissions, but SAFE) -----------------------------
function Connect-ScAz {
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$ClientSecret
    )
    try {
        Disable-AzContextAutosave -Scope Process -ErrorAction SilentlyContinue | Out-Null

        $sec  = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential($ClientId, $sec)

        Connect-AzAccount -ServicePrincipal -TenantId $TenantId -Credential $cred -ErrorAction Stop | Out-Null
        return $true
    } catch {
        Write-Host "ERROR: Azure login failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure connection failed."
}

# ----------------------------- Pick ONLY the intended subscription -----------------------------
function Get-TargetSubscription {
    param(
        [Parameter(Mandatory)][string]$adh_group,
        [Parameter(Mandatory)][ValidateSet('nonprd','prd')][string]$adh_subscription_type
    )

    $prefix = if ($adh_subscription_type -eq 'prd') { 'prd_azure_' } else { 'dev_azure_' }
    $token  = "ADH$($adh_group.ToUpper())"

    # Example: dev_azure_20481_ADHCIT  OR  prd_azure_30991_ADHCIT
    $regex = "^(?i)$prefix.+_$token$"

    $matches = Get-AzSubscription -ErrorAction Stop | Where-Object { $_.Name -match $regex }

    if (-not $matches) {
        throw "No subscription found matching pattern: $regex"
    }

    if ($matches.Count -gt 1) {
        # If multiple match, pick the first but print all so you can see it
        Write-Host "WARNING: Multiple subscriptions match. Using the first:" -ForegroundColor Yellow
        $matches | ForEach-Object { Write-Host " - $($_.Name)" }
    }

    return $matches[0]
}

$targetSub = Get-TargetSubscription -adh_group $adh_group -adh_subscription_type $adh_subscription_type
Set-AzContext -SubscriptionId $targetSub.Id -ErrorAction Stop | Out-Null
Write-Host "Scanning ONLY subscription: $($targetSub.Name) / $($targetSub.Id)" -ForegroundColor Cyan

# ----------------------------- Custodian helpers -----------------------------
$BaseCustodian = $adh_group
$BaseCustLower = $adh_group.ToLower() -replace '_',''

# Identity placeholder: adh_group OR adh_group-adh_sub_group (as per your naming)
$CustIdentity = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) { $adh_group } else { "${adh_group}-${adh_sub_group}" }

Write-Host "DEBUG: BaseCustodian (RG/SA/Cont)  = $BaseCustodian"
Write-Host "DEBUG: <Cust> (lower, no _)        = $BaseCustLower"
Write-Host "DEBUG: CustIdentity (for Identity) = $CustIdentity"

# ----------------------------- Identity resolver -----------------------------
$script:IdentityCache = @{}

function Resolve-IdentityObjectId {
    param([Parameter(Mandatory)][string]$IdentityName)

    if ($script:IdentityCache.ContainsKey($IdentityName)) { return $script:IdentityCache[$IdentityName] }

    $id = $null

    try {
        $grp = Get-AzADGroup -DisplayName $IdentityName -ErrorAction Stop
        if ($grp -and $grp.Id) { $id = $grp.Id }
    } catch {}

    if (-not $id) {
        try {
            $sp = Get-AzADServicePrincipal -DisplayName $IdentityName -ErrorAction Stop
            if ($sp -and $sp.Id) { $id = $sp.Id }
        } catch {}
    }

    if (-not $id) {
        try {
            $sp2 = Get-AzADServicePrincipal -SearchString $IdentityName -ErrorAction Stop
            if ($sp2 -and $sp2.Count -ge 1) { $id = $sp2[0].Id }
        } catch {}
    }

    if (-not $id) {
        $guidRef = [ref]([Guid]::Empty)
        if ([Guid]::TryParse($IdentityName, $guidRef)) { $id = $IdentityName }
    }

    $script:IdentityCache[$IdentityName] = $id
    return $id
}

# ----------------------------- ACL parsing + matching -----------------------------
function Parse-AclEntries {
    param([Parameter(Mandatory)]$Acl)

    # $Acl can be:
    # - string: "user::rwx,group::r-x,user:<id>:r-x,default:user:<id>:rwx,..."
    # - array of strings
    $raw = @()
    if ($Acl -is [string]) {
        $raw = $Acl -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    } elseif ($Acl -is [System.Collections.IEnumerable]) {
        foreach ($a in $Acl) {
            if ($a -is [string]) {
                $raw += ($a -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            } else {
                $raw += ($a.ToString().Trim())
            }
        }
    } else {
        $raw = @($Acl.ToString().Trim())
    }

    $entries = @()
    foreach ($e in $raw) {
        # format examples:
        # user::<perm>
        # group::<perm>
        # user:<oid>:<perm>
        # group:<oid>:<perm>
        # default:user:<oid>:<perm>
        $isDefault = $false
        $x = $e
        if ($x -like 'default:*') { $isDefault = $true; $x = $x.Substring(8) }

        $parts = $x -split ':'
        if ($parts.Count -lt 3) { continue }

        $type = $parts[0]
        $id   = $parts[1]
        $perm = $parts[2]

        $entries += [pscustomobject]@{
            Raw       = $e
            IsDefault = $isDefault
            Type      = $type
            EntityId  = $id
            Perm      = $perm
        }
    }
    return $entries
}

function Perm-Satisfies {
    param(
        [Parameter(Mandatory)][string]$Have,
        [Parameter(Mandatory)][string]$Need
    )
    # Superset-friendly:
    # - Need r-x is satisfied by r-x or rwx
    # - Need r-- satisfied by r--, r-x, rwx
    switch ($Need) {
        'rwx' { return ($Have -eq 'rwx') }
        'r-x' { return ($Have -eq 'r-x' -or $Have -eq 'rwx') }
        'r--' { return ($Have.StartsWith('r')) }
        default { return ($Have -eq $Need) }
    }
}

function Get-Gen2ItemSafe {
    param(
        [Parameter(Mandatory)][string]$FileSystem,
        [Parameter(Mandatory)]$Context,
        [string]$Path
    )
    $p = @{
        FileSystem  = $FileSystem
        Context     = $Context
        ErrorAction = 'Stop'
    }
    if (-not [string]::IsNullOrWhiteSpace($Path)) {
        $p['Path'] = $Path.TrimStart('/')
    }
    return (Get-AzDataLakeGen2Item @p)
}

function Get-ParentPaths {
    param([Parameter(Mandatory)][string]$NormalizedPath)

    # Input: "" (root) OR "/a/b/c" OR "a/b/c"
    $p = $NormalizedPath.Trim()
    if ($p -eq '/' -or [string]::IsNullOrWhiteSpace($p)) { return @('') }

    $p = $p.TrimStart('/')
    $segments = $p -split '/' | Where-Object { $_ -ne '' }

    $paths = @()
    for ($i = $segments.Count; $i -ge 1; $i--) {
        $paths += (($segments[0..($i-1)] -join '/'))
    }
    $paths += '' # container root last
    return $paths
}

function Find-AclMatchInFolderOrParents {
    param(
        [Parameter(Mandatory)][string]$FileSystem,
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$NormalizedPath,   # "" for root or "a/b"
        [Parameter(Mandatory)][string]$ObjectId,
        [Parameter(Mandatory)][string]$NeedPerm
    )

    $pathsToCheck = Get-ParentPaths -NormalizedPath $NormalizedPath

    foreach ($p in $pathsToCheck) {
        try {
            $item = Get-Gen2ItemSafe -FileSystem $FileSystem -Context $Context -Path $p

            $entries = Parse-AclEntries -Acl $item.Acl

            $match = $entries | Where-Object {
                ($_.Type -in @('user','group')) -and
                ($_.EntityId -eq $ObjectId) -and
                (Perm-Satisfies -Have $_.Perm -Need $NeedPerm)
            } | Select-Object -First 1

            if ($match) {
                return [pscustomobject]@{
                    Found  = $true
                    Where  = (if ([string]::IsNullOrWhiteSpace($p)) { '/' } else { "/$p" })
                    Reason = "Matched ACL entry: $($match.Raw)"
                }
            }

            # Owner/Group fallback (rarely used, but keep)
            if ($item.Owner -and $item.Owner -eq $ObjectId) {
                return [pscustomobject]@{
                    Found  = $true
                    Where  = (if ([string]::IsNullOrWhiteSpace($p)) { '/' } else { "/$p" })
                    Reason = "Matched as Owner on item"
                }
            }
            if ($item.Group -and $item.Group -eq $ObjectId) {
                return [pscustomobject]@{
                    Found  = $true
                    Where  = (if ([string]::IsNullOrWhiteSpace($p)) { '/' } else { "/$p" })
                    Reason = "Matched as Owning Group on item"
                }
            }

        } catch {
            # keep checking parents, but if root fails, return error
            if ([string]::IsNullOrWhiteSpace($p)) {
                return [pscustomobject]@{
                    Found  = $false
                    Where  = '/'
                    Reason = "ACL read error at root: $($_.Exception.Message)"
                    Error  = $true
                }
            }
        }
    }

    return [pscustomobject]@{
        Found  = $false
        Where  = ''
        Reason = 'No matching ACL entry found on folder, parents, or container root'
    }
}

# ----------------------------- Load CSV -----------------------------
$rows = Import-Csv -LiteralPath $InputCsvPath
Write-Host ("DEBUG: CSV rows loaded: {0}" -f $rows.Count)
Write-Host ("DEBUG: CSV headers     : " + ($rows[0].psobject.Properties.Name -join ', '))

# ----------------------------- Scan -----------------------------
$out = @()

foreach ($r in $rows) {

    # Placeholders
    $rgName = ($r.ResourceGroupName -replace '<Custodian>', $BaseCustodian).Trim()

    $saName = $r.StorageAccountName
    $saName = ($saName -replace '<Custodian>', $BaseCustodian)
    $saName = ($saName -replace '<Cust>',      $BaseCustLower)
    $saName = $saName.Trim()

    $cont = $r.ContainerName
    $cont = ($cont -replace '<Custodian>', $BaseCustodian)
    $cont = ($cont -replace '<Cust>',      $BaseCustLower)
    $cont = $cont.Trim()

    $iden = ($r.Identity -replace '<Custodian>', $CustIdentity).Trim()

    # Access path
    $accessPath = $r.AccessPath
    $accessPath = ($accessPath -replace '<Custodian>', $BaseCustodian)
    $accessPath = ($accessPath -replace '<Cust>',      $BaseCustLower)
    $accessPath = $accessPath.Trim()

    # /catalog rewrite (your rule)
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

    # Normalize "/" => root => empty path for cmdlet
    $normalizedPath = $accessPath
    if ($normalizedPath -eq '/') { $normalizedPath = '' }
    $folderForReport = if ([string]::IsNullOrWhiteSpace($normalizedPath)) { '/' } else { $normalizedPath }

    $permType = $r.PermissionType

    Write-Host ""
    Write-Host "Row:" -ForegroundColor DarkCyan
    Write-Host "  RG      = $rgName"
    Write-Host "  Storage = $saName"
    Write-Host "  Cont    = $cont"
    Write-Host "  Id      = $iden"
    Write-Host "  Path    = $folderForReport"
    Write-Host "  Need    = $permType"

    if ([string]::IsNullOrWhiteSpace($rgName) -or [string]::IsNullOrWhiteSpace($saName) -or [string]::IsNullOrWhiteSpace($cont)) {
        $out += [pscustomobject]@{
            SubscriptionName = $targetSub.Name
            ResourceGroup    = $rgName
            Storage          = $saName
            Container        = $cont
            Folder           = $folderForReport
            Identity         = $iden
            Permission       = $permType
            Status           = 'ERROR'
            Notes            = 'After placeholder replacement, RG/Storage/Container is empty.'
        }
        continue
    }

    # Storage
    try {
        $sa = Get-AzStorageAccount -ResourceGroupName $rgName -Name $saName -ErrorAction Stop
        $ctx = $sa.Context
    } catch {
        $out += [pscustomobject]@{
            SubscriptionName = $targetSub.Name
            ResourceGroup    = $rgName
            Storage          = $saName
            Container        = $cont
            Folder           = $folderForReport
            Identity         = $iden
            Permission       = $permType
            Status           = 'ERROR'
            Notes            = "Storage account error: $($_.Exception.Message)"
        }
        continue
    }

    # Container
    try {
        Get-AzStorageContainer -Name $cont -Context $ctx -ErrorAction Stop | Out-Null
    } catch {
        $out += [pscustomobject]@{
            SubscriptionName = $targetSub.Name
            ResourceGroup    = $rgName
            Storage          = $saName
            Container        = $cont
            Folder           = $folderForReport
            Identity         = $iden
            Permission       = $permType
            Status           = 'ERROR'
            Notes            = "Container fetch error: $($_.Exception.Message)"
        }
        continue
    }

    # Identity
    $objectId = Resolve-IdentityObjectId -IdentityName $iden
    if (-not $objectId) {
        $out += [pscustomobject]@{
            SubscriptionName = $targetSub.Name
            ResourceGroup    = $rgName
            Storage          = $saName
            Container        = $cont
            Folder           = $folderForReport
            Identity         = $iden
            Permission       = $permType
            Status           = 'ERROR'
            Notes            = "Identity '$iden' not found in Entra ID"
        }
        continue
    }

    # ACL check on folder + parents + root
    try {
        $np = $normalizedPath
        if ($np -eq '/') { $np = '' }

        $result = Find-AclMatchInFolderOrParents -FileSystem $cont -Context $ctx -NormalizedPath $np -ObjectId $objectId -NeedPerm $permType

        if ($result.PSObject.Properties.Name -contains 'Error' -and $result.Error) {
            $status = 'ERROR'
            $notes  = $result.Reason
        } elseif ($result.Found) {
            $status = 'OK'
            $notes  = "$($result.Reason) (found at: $($result.Where))"
        } else {
            $status = 'MISSING'
            $notes  = $result.Reason
        }

    } catch {
        $status = 'ERROR'
        $notes  = "ACL evaluation error: $($_.Exception.Message)"
    }

    $out += [pscustomobject]@{
        SubscriptionName = $targetSub.Name
        ResourceGroup    = $rgName
        Storage          = $saName
        Container        = $cont
        Folder           = $folderForReport
        Identity         = $iden
        Permission       = $permType
        Status           = $status
        Notes            = $notes
    }
}

if (-not $out -or $out.Count -eq 0) {
    $out += [pscustomobject]@{
        SubscriptionName = $targetSub.Name
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
$csvOut = New-StampedPath -BaseDir $OutputDir -Prefix ("adls_acl_{0}_{1}" -f $groupForFile, $adh_subscription_type)

Write-CsvSafe -Rows $out -Path $csvOut

Write-Host ""
Write-Host "ADLS ACL validation completed." -ForegroundColor Green
Write-Host "Subscription scanned: $($targetSub.Name)" -ForegroundColor Green
Write-Host "CSV : $csvOut" -ForegroundColor Green

exit 0
