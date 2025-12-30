# sanitychecks/scripts/Scan-ADLS-Acls.ps1
# ADLS Gen2 ACL validator (Common.psm1 style)
# - Uses Common.psm1 for Ensure-Dir / Connect-ScAz / Resolve-ScSubscriptions / Set-ScContext
# - STRICT subscription filter by prefix:
#     prd    => ^prd[_-]
#     nonprd => ^dev[_-]
# - Parent path checking: folder + parents + root
# - Graph-based identity resolution (works even when AzAD cmdlets are blocked)
# - Accepts GUID identity (objectId or appId; appId resolved to SP objectId via Graph)
# - Outputs CSV always

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$TenantId,
    [Parameter(Mandatory = $true)][string]$ClientId,
    [Parameter(Mandatory = $true)][string]$ClientSecret,

    [Parameter(Mandatory = $true)][string]$adh_group,
    [string]$adh_sub_group = '',

    [ValidateSet('nonprd','prd')]
    [string]$adh_subscription_type = 'nonprd',

    [Parameter(Mandatory = $true)][string]$InputCsvPath,
    [Parameter(Mandatory = $true)][string]$OutputDir,

    # keep optional, because your pipeline passes it sometimes
    [string]$BranchName = '',

    # optional override: comma-separated subscriptionIds (if needed later)
    [string]$SubscriptionIds = '',

    [switch]$DebugAcls
)

Import-Module Az.Accounts, Az.Resources, Az.Storage -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

# ---------------- Normalise adh_sub_group ----------------
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

if (-not (Test-Path -LiteralPath $InputCsvPath)) {
    throw "ADLS CSV not found: $InputCsvPath"
}

# ---------------- Connect to Azure (Common.psm1 style) ----------------
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure connection failed."
}

# ---------------- Graph token (for identity resolution) ----------------
function Get-GraphToken {
    param([string]$TenantId,[string]$ClientId,[string]$ClientSecret)

    $body = @{
        client_id     = $ClientId
        client_secret = $ClientSecret
        grant_type    = 'client_credentials'
        scope         = 'https://graph.microsoft.com/.default'
    }

    $resp = Invoke-RestMethod -Method Post `
        -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
        -Body $body -ContentType 'application/x-www-form-urlencoded'

    return $resp.access_token
}

function Invoke-GraphGet {
    param([string]$Token,[string]$Uri)
    $headers = @{ Authorization = "Bearer $Token" }
    Invoke-RestMethod -Method Get -Uri $Uri -Headers $headers
}

function Escape-ODataString {
    param([string]$s)
    return ($s -replace "'", "''")
}

$graphToken = $null
try {
    $graphToken = Get-GraphToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
    Write-Host "DEBUG: Graph token acquired." -ForegroundColor Green
} catch {
    Write-Warning "Graph token NOT acquired. Identity resolution may be limited. Error: $($_.Exception.Message)"
}

# ---------------- Custodian helpers ----------------
$BaseCustodian = $adh_group
$BaseCustLower = $adh_group.ToLower() -replace '_',''
$CustIdentity  = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) { $adh_group } else { "${adh_group}_${adh_sub_group}" }

Write-Host "DEBUG: BaseCustodian (RG/SA/Cont)  = $BaseCustodian"
Write-Host "DEBUG: <Cust> (lower, no _)        = $BaseCustLower"
Write-Host "DEBUG: CustIdentity (for Identity) = $CustIdentity"

# ---------------- Identity cache + resolver ----------------
$script:IdentityCache = @{}

function Resolve-ServicePrincipalObjectIdFromAppId {
    param([string]$Token,[string]$AppIdGuid)

    if (-not $Token) { return $null }

    try {
        $u = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$AppIdGuid'&`$select=id,appId"
        $r = Invoke-GraphGet -Token $Token -Uri $u
        if ($r.value.Count -eq 1) { return $r.value[0].id }
    } catch { }
    return $null
}

function Resolve-IdentityViaGraph {
    param([string]$Token,[string]$Name)

    if (-not $Token) { return $null }

    $n = Escape-ODataString $Name

    # SP exact
    try {
        $u = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=displayName eq '$n'&`$select=id,displayName"
        $r = Invoke-GraphGet -Token $Token -Uri $u
        if ($r.value.Count -eq 1) { return $r.value[0].id }
    } catch {}

    # Group exact
    try {
        $u = "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$n'&`$select=id,displayName"
        $r = Invoke-GraphGet -Token $Token -Uri $u
        if ($r.value.Count -eq 1) { return $r.value[0].id }
    } catch {}

    # startsWith fallback
    try {
        $u = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=startsWith(displayName,'$n')&`$select=id,displayName"
        $r = Invoke-GraphGet -Token $Token -Uri $u
        if ($r.value.Count -eq 1) { return $r.value[0].id }
    } catch {}

    try {
        $u = "https://graph.microsoft.com/v1.0/groups?`$filter=startsWith(displayName,'$n')&`$select=id,displayName"
        $r = Invoke-GraphGet -Token $Token -Uri $u
        if ($r.value.Count -eq 1) { return $r.value[0].id }
    } catch {}

    return $null
}

function Resolve-IdentityObjectId {
    param([Parameter(Mandatory)][string]$IdentityName)

    $IdentityName = $IdentityName.Trim()
    if ($script:IdentityCache.ContainsKey($IdentityName)) { return $script:IdentityCache[$IdentityName] }

    $id = $null
    $guidRef = [ref]([Guid]::Empty)

    # GUID? treat as objectId unless it looks like appId (resolve to SP objectId)
    if ([Guid]::TryParse($IdentityName, $guidRef)) {
        $spObj = Resolve-ServicePrincipalObjectIdFromAppId -Token $graphToken -AppIdGuid $IdentityName
        if ($spObj) {
            $script:IdentityCache[$IdentityName] = $spObj
            return $spObj
        }

        $script:IdentityCache[$IdentityName] = $IdentityName
        return $IdentityName
    }

    # Prefer Graph name resolution
    $id = Resolve-IdentityViaGraph -Token $graphToken -Name $IdentityName
    if ($id) {
        $script:IdentityCache[$IdentityName] = $id
        return $id
    }

    # Fallback to AzAD (may fail in your tenant depending on permissions)
    $matches = @()
    try { $matches += Get-AzADGroup -DisplayName $IdentityName -ErrorAction SilentlyContinue } catch {}
    try { $matches += Get-AzADServicePrincipal -DisplayName $IdentityName -ErrorAction SilentlyContinue } catch {}

    if (-not $matches -or $matches.Count -eq 0) {
        try { $matches += Get-AzADGroup -SearchString $IdentityName -ErrorAction SilentlyContinue } catch {}
        try { $matches += Get-AzADServicePrincipal -SearchString $IdentityName -ErrorAction SilentlyContinue } catch {}
    }

    $matches = $matches | Sort-Object DisplayName -Unique
    if ($matches.Count -eq 1) { $id = $matches[0].Id }

    $script:IdentityCache[$IdentityName] = $id
    return $id
}

# ---------------- ACL helpers ----------------
function Perm-Ok {
    param([string]$acePerm, [string]$permType)
    switch ($permType) {
        'r-x' { return ($acePerm -eq 'r-x' -or $acePerm -eq 'rwx') }
        'rwx' { return ($acePerm -eq 'rwx') }
        'r--' { return ($acePerm.Length -ge 1 -and $acePerm[0] -eq 'r') }
        default { return ($acePerm -eq $permType) }
    }
}

function Get-PathsToCheck {
    param([string]$NormalizedPath)

    if ([string]::IsNullOrWhiteSpace($NormalizedPath) -or $NormalizedPath -eq '/') { return @('') }

    $p = $NormalizedPath.Trim().TrimStart('/') -replace '//+','/'
    $parts = $p.Split('/', [System.StringSplitOptions]::RemoveEmptyEntries)

    $paths = New-Object System.Collections.Generic.List[string]
    for ($i = $parts.Length; $i -ge 1; $i--) {
        $paths.Add(($parts[0..($i-1)] -join '/'))
    }
    $paths.Add('')
    return $paths.ToArray()
}

function Read-AclEntries {
    param(
        [Parameter(Mandatory)][string]$FileSystem,
        [Parameter(Mandatory)]$Context,
        [string]$Path
    )

    $p = @{ FileSystem = $FileSystem; Context = $Context; ErrorAction = 'Stop' }
    if ($Path -and $Path.Trim() -ne '') { $p['Path'] = $Path }

    $item = Get-AzDataLakeGen2Item @p

    $entries = @()
    if ($item.Acl)        { $entries += $item.Acl }
    if ($item.DefaultAcl) { $entries += $item.DefaultAcl }
    return ,@($entries)
}

function Has-MatchingAce {
    param(
        [Parameter(Mandatory)][object[]]$Entries,
        [Parameter(Mandatory)][string]$ObjectId,
        [Parameter(Mandatory)][string]$PermType
    )

    foreach ($ace in $Entries) {
        if ($ace.AccessControlType -notin @('user','group')) { continue }

        $acePerm = $ace.Permissions.ToString()
        if (-not (Perm-Ok -acePerm $acePerm -permType $PermType)) { continue }

        # main match
        if ($ace.EntityId -and ($ace.EntityId -eq $ObjectId)) { return $true }
    }
    return $false
}

# ---------------- Load CSV ----------------
$rows = Import-Csv -LiteralPath $InputCsvPath
Write-Host ("DEBUG: CSV rows loaded: {0}" -f $rows.Count)
if ($rows.Count -gt 0) {
    Write-Host ("DEBUG: CSV headers     : " + ($rows[0].psobject.Properties.Name -join ', '))
}

# ---------------- Subscriptions (Common.psm1 + STRICT prefix filter) ----------------
$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
if ($subs -isnot [System.Collections.IEnumerable]) { $subs = ,$subs }

# Optional hard override by ids if provided
if (-not [string]::IsNullOrWhiteSpace($SubscriptionIds)) {
    $wanted = $SubscriptionIds.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    $subs = $subs | Where-Object { $wanted -contains $_.Id }
}

# STRICT by prefix requirement
if ($adh_subscription_type -eq 'prd') {
    $subs = $subs | Where-Object { $_.Name -match '^(?i)prd[_-]' }
} else {
    $subs = $subs | Where-Object { $_.Name -match '^(?i)dev[_-]' }
}

if (-not $subs -or $subs.Count -eq 0) {
    throw "No subscriptions matched strict prefix filter for '$adh_subscription_type'. Expected: prd => ^prd[_-], nonprd => ^dev[_-]"
}

Write-Host "DEBUG: Subscriptions (filtered) = $($subs.Name -join ', ')" -ForegroundColor Cyan

# ---------------- Scan ----------------
$out = @()

foreach ($sub in $subs) {
    Set-ScContext -Subscription $sub

    Write-Host ""
    Write-Host "=== Subscription: $($sub.Name) ===" -ForegroundColor Cyan

    foreach ($r in $rows) {

        # -------- Placeholder substitution --------
        $rgName = ($r.ResourceGroupName -replace '<Custodian>', $BaseCustodian).Trim()

        $saName = ($r.StorageAccountName -replace '<Custodian>', $BaseCustodian)
        $saName = ($saName -replace '<Cust>',      $BaseCustLower).Trim()

        $cont = ($r.ContainerName -replace '<Custodian>', $BaseCustodian)
        $cont = ($cont -replace '<Cust>',      $BaseCustLower).Trim()

        # Identity: supports comma-separated values
        $identities = @()
        if ($r.Identity) {
            $identities = $r.Identity.Split(',') |
                ForEach-Object { ($_ -replace '<Custodian>', $CustIdentity).Trim() } |
                Where-Object { $_ }
        }

        # -------- AccessPath --------
        $accessPath = ($r.AccessPath -replace '<Custodian>', $BaseCustodian)
        $accessPath = ($accessPath -replace '<Cust>',      $BaseCustLower).Trim()

        if ($accessPath -like '/catalog*') {
            $suffix     = $accessPath.Substring('/catalog'.Length)
            $groupLower = $adh_group.ToLower()

            if ([string]::IsNullOrWhiteSpace($adh_sub_group)) {
                $accessPath = "/adh_${groupLower}${suffix}"
            } else {
                $accessPath = "/adh_${groupLower}_$($adh_sub_group.ToLower())${suffix}"
            }
        }

        $normalizedPath = $accessPath
        if ($normalizedPath -eq '/') { $normalizedPath = '' }

        $folderForReport = if ([string]::IsNullOrWhiteSpace($normalizedPath)) { '/' } else { $normalizedPath }

        if ([string]::IsNullOrWhiteSpace($rgName) -or [string]::IsNullOrWhiteSpace($saName)) {
            foreach ($iden in $identities) {
                $out += [pscustomobject]@{
                    SubscriptionName = $sub.Name
                    ResourceGroup    = $rgName
                    Storage          = $saName
                    Container        = $cont
                    Folder           = $folderForReport
                    Identity         = $iden
                    Permission       = $r.PermissionType
                    Status           = 'ERROR'
                    Notes            = 'After placeholder replacement RG or Storage is empty.'
                }
            }
            continue
        }

        # -------- Resolve storage + container --------
        try {
            $sa  = Get-AzStorageAccount -ResourceGroupName $rgName -Name $saName -ErrorAction Stop
            $ctx = $sa.Context
        } catch {
            foreach ($iden in $identities) {
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
            }
            continue
        }

        try {
            $null = Get-AzStorageContainer -Name $cont -Context $ctx -ErrorAction Stop
        } catch {
            foreach ($iden in $identities) {
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
            }
            continue
        }

        # -------- ACL validation per identity --------
        $permType     = $r.PermissionType
        $pathsToCheck = Get-PathsToCheck -NormalizedPath $normalizedPath

        foreach ($iden in $identities) {

            $objectId = Resolve-IdentityObjectId -IdentityName $iden
            if (-not $objectId) {
                $out += [pscustomobject]@{
                    SubscriptionName = $sub.Name
                    ResourceGroup    = $rgName
                    Storage          = $saName
                    Container        = $cont
                    Folder           = $folderForReport
                    Identity         = $iden
                    Permission       = $permType
                    Status           = 'UNRESOLVED_IDENTITY'
                    Notes            = "Cannot resolve '$iden' to objectId. Use GUID objectId/appId in CSV or fix Graph app permissions/consent."
                }
                continue
            }

            $matchedAt = $null
            try {
                foreach ($p in $pathsToCheck) {
                    $entries = Read-AclEntries -FileSystem $cont -Context $ctx -Path $p

                    if ($DebugAcls) {
                        $disp = if ($p -and $p.Trim() -ne '') { "/$p" } else { "/" }
                        Write-Host "DEBUG ACLs for '$disp' (Identity=$iden ObjectId=$objectId Perm=$permType):" -ForegroundColor DarkGray
                        foreach ($ace in $entries) {
                            Write-Host ("ACE => Type={0} EntityId={1} Perm={2}" -f $ace.AccessControlType, $ace.EntityId, $ace.Permissions) -ForegroundColor DarkGray
                        }
                    }

                    if (Has-MatchingAce -Entries $entries -ObjectId $objectId -PermType $permType) {
                        $matchedAt = if ($p -and $p.Trim() -ne '') { "/$p" } else { "/" }
                        break
                    }
                }

                if ($matchedAt) {
                    $status = 'OK'
                    $notes  = "ACL requirement satisfied (matched at '$matchedAt')"
                } else {
                    $status = 'MISSING'
                    $notes  = "No matching ACL entry found on folder, parents, or container root"
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
                Permission       = $permType
                Status           = $status
                Notes            = $notes
            }
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

# ---------------- Export CSV ----------------
$groupForFile = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) { $adh_group } else { "${adh_group}-${adh_sub_group}" }
$stamp  = Get-Date -Format 'yyyyMMdd'
$csvOut = Join-Path $OutputDir ("adls_acl_{0}_{1}_{2}.csv" -f $groupForFile, $adh_subscription_type, $stamp)

Write-CsvSafe -Rows $out -Path $csvOut

Write-Host "ADLS validation completed." -ForegroundColor Green
Write-Host "CSV : $csvOut"
exit 0
