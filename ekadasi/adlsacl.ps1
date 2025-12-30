# Scan-ADLS-Acls.ps1
# ADLS Gen2 ACL validator (WORKING)
# Fixes:
# 1) Reliable SPN login when SPN has access to MANY subscriptions (avoids 0000.. subscription bug)
# 2) Scans ONLY the subscription(s) matching naming convention:
#       <dev|prd>_azure_<digits>_ADH<adh_group>
#    Example (adh_group=CIT):
#       dev_azure_20481_ADHCIT   (nonprd)
#       prd_azure_20481_ADHCIT   (prd)
# 3) Resolves identities robustly:
#    - Accepts GUID directly (objectId or appId)
#    - Resolves displayName using Microsoft Graph (client_credentials)
#    - Falls back to AzAD cmdlets (if allowed)
# 4) Checks ACL on folder + parents + container root
# 5) Supports comma-separated Identity values
# 6) CSV output always written (even if NO_RESULTS)

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

    [switch]$DebugAcls
)

Import-Module Az.Accounts, Az.Resources, Az.Storage -ErrorAction Stop

# ---------------- Basic helpers ----------------
function Ensure-Dir([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Write-CsvSafe {
    param(
        [Parameter(Mandatory)][object[]]$Rows,
        [Parameter(Mandatory)][string]$Path
    )
    Ensure-Dir -Path (Split-Path -Parent $Path)
    $Rows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $Path -Force
}

# ---------------- Azure Login (SAFE) ----------------
# IMPORTANT: Do not bind a subscription at login when SPN has access to many subs.
function Connect-ScAz {
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$ClientSecret
    )
    try {
        $sec  = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential($ClientId, $sec)

        Connect-AzAccount -ServicePrincipal -Tenant $TenantId -Credential $cred -ErrorAction Stop | Out-Null

        # Ensure no broken default subscription is carried over
        Clear-AzContext -Scope Process -Force -ErrorAction SilentlyContinue | Out-Null

        Write-Host "Azure login successful (tenant-only, no default subscription bound)." -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Connect-AzAccount failed: $($_.Exception.Message)"
        return $false
    }
}

function Set-ScContext {
    param([Parameter(Mandatory)]$Subscription)
    Set-AzContext -SubscriptionId $Subscription.Id -ErrorAction Stop | Out-Null
}

# ---------------- Subscription resolver (STRICT) ----------------
# Requirement:
#   Scan ONLY subscription(s) matching:
#       <dev|prd>_azure_<digits>_ADH<adh_group>
function Resolve-SubscriptionsStrict {
    param(
        [Parameter(Mandatory)][string]$adh_group,
        [Parameter(Mandatory)][ValidateSet('nonprd','prd')]$adh_subscription_type
    )

    $prefix = if ($adh_subscription_type -eq 'prd') { 'prd' } else { 'dev' }
    $grp    = $adh_group.Trim().ToUpper()

    # Example: ^dev_azure_\d+_ADHCIT$
    $pattern = "^(?i)$prefix" + "_azure_\d+_ADH" + [regex]::Escape($grp) + "$"

    $all = Get-AzSubscription -ErrorAction Stop
    $matched = $all | Where-Object { $_.Name -match $pattern }

    Write-Host "DEBUG: Subscription name regex = $pattern"
    Write-Host "DEBUG: Matched subscriptions    = $($matched.Name -join ', ')"

    return $matched
}

# ---------------- Graph token + helper ----------------
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
        -Body $body `
        -ContentType 'application/x-www-form-urlencoded'

    return $resp.access_token
}

function Invoke-GraphGet {
    param([string]$Token,[string]$Uri)
    $headers = @{ Authorization = "Bearer $Token" }
    return Invoke-RestMethod -Method Get -Uri $Uri -Headers $headers
}

# ---------------- Identity cache + resolver ----------------
$script:IdentityCache = @{}

function Resolve-IdentityObjectId {
    param(
        [Parameter(Mandatory)][string]$IdentityName,
        [string]$GraphToken = $null
    )

    $name = $IdentityName.Trim()
    if ([string]::IsNullOrWhiteSpace($name)) { return $null }

    if ($script:IdentityCache.ContainsKey($name)) {
        return $script:IdentityCache[$name]
    }

    $guidRef = [ref]([Guid]::Empty)

    # If GUID is given:
    # - try SP by appId (Graph) -> objectId
    # - else accept as objectId (best-effort)
    if ([Guid]::TryParse($name, $guidRef)) {
        if ($GraphToken) {
            try {
                $uri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$name'&`$select=id,appId"
                $sp = Invoke-GraphGet -Token $GraphToken -Uri $uri
                if ($sp.value.Count -eq 1) {
                    $script:IdentityCache[$name] = $sp.value[0].id
                    return $sp.value[0].id
                }
            } catch { }
        }

        $script:IdentityCache[$name] = $name
        return $name
    }

    # 1) Prefer Graph exact match by displayName (service principals)
    if ($GraphToken) {
        try {
            $escaped = $name.Replace("'", "''")
            $spUri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=displayName eq '$escaped'&`$select=id,displayName"
            $sp = Invoke-GraphGet -Token $GraphToken -Uri $spUri
            if ($sp.value.Count -eq 1) {
                $script:IdentityCache[$name] = $sp.value[0].id
                return $sp.value[0].id
            }
        } catch { }

        # 2) Graph exact match by displayName (groups)
        try {
            $escaped = $name.Replace("'", "''")
            $gUri = "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$escaped'&`$select=id,displayName"
            $g = Invoke-GraphGet -Token $GraphToken -Uri $gUri
            if ($g.value.Count -eq 1) {
                $script:IdentityCache[$name] = $g.value[0].id
                return $g.value[0].id
            }
        } catch { }
    }

    # 3) Fallback to AzAD lookups (may require directory read permissions)
    $matches = @()
    try { $matches += Get-AzADServicePrincipal -DisplayName $name -ErrorAction SilentlyContinue } catch { }
    try { $matches += Get-AzADGroup -DisplayName $name -ErrorAction SilentlyContinue } catch { }

    if (-not $matches -or $matches.Count -eq 0) {
        try { $matches += Get-AzADServicePrincipal -SearchString $name -ErrorAction SilentlyContinue } catch { }
        try { $matches += Get-AzADGroup -SearchString $name -ErrorAction SilentlyContinue } catch { }
    }

    $matches = $matches | Sort-Object DisplayName -Unique

    $id = $null
    if ($matches.Count -eq 1) { $id = $matches[0].Id }

    $script:IdentityCache[$name] = $id
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

    if ([string]::IsNullOrWhiteSpace($NormalizedPath) -or $NormalizedPath -eq '/') {
        return @('')  # root only
    }

    $p = $NormalizedPath.Trim().TrimStart('/') -replace '//+','/'
    $parts = $p.Split('/', [System.StringSplitOptions]::RemoveEmptyEntries)

    $paths = New-Object System.Collections.Generic.List[string]
    for ($i = $parts.Length; $i -ge 1; $i--) {
        $paths.Add( ($parts[0..($i-1)] -join '/') )
    }
    $paths.Add('') # root
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
    return $entries
}

function Has-MatchingAce {
    param(
        [Parameter(Mandatory)][object[]]$Entries,
        [Parameter(Mandatory)][string]$ObjectId,
        [Parameter(Mandatory)][string]$PermType
    )

    foreach ($ace in $Entries) {
        if ($ace.AccessControlType -notin @('user','group')) { continue }
        if (-not $ace.EntityId) { continue }

        if ($ace.EntityId -eq $ObjectId) {
            $acePerm = $ace.Permissions.ToString()
            if (Perm-Ok -acePerm $acePerm -permType $PermType) {
                return $true
            }
        }
    }
    return $false
}

# ---------------- Normalize adh_sub_group ----------------
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

# ---------------- Connect ----------------
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure connection failed."
}

# ---------------- Graph token (identity name resolution) ----------------
$graphToken = $null
try {
    $graphToken = Get-GraphToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
    Write-Host "Graph token acquired." -ForegroundColor Green
} catch {
    Write-Warning "Graph token NOT acquired. Identity resolution may fail unless you use GUID in CSV. Error: $($_.Exception.Message)"
}

# ---------------- Custodian helpers ----------------
$BaseCustodian = $adh_group
$BaseCustLower = $adh_group.ToLower() -replace '_',''

$CustIdentity = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) { $adh_group } else { "${adh_group}_${adh_sub_group}" }

Write-Host "DEBUG: BaseCustodian (RG/SA/Cont)  = $BaseCustodian"
Write-Host "DEBUG: <Cust> (lower, no _)        = $BaseCustLower"
Write-Host "DEBUG: CustIdentity (for Identity) = $CustIdentity"

# ---------------- Load CSV ----------------
$rows = Import-Csv -LiteralPath $InputCsvPath
Write-Host ("DEBUG: CSV rows loaded: {0}" -f $rows.Count)
if ($rows.Count -gt 0) { Write-Host ("DEBUG: CSV headers     : " + ($rows[0].psobject.Properties.Name -join ', ')) }

# ---------------- Subscriptions (STRICT) ----------------
$subs = Resolve-SubscriptionsStrict -adh_group $adh_group -adh_subscription_type $adh_subscription_type
if (-not $subs -or $subs.Count -eq 0) {
    throw "No subscriptions matched the pattern <dev|prd>_azure_<digits>_ADH$($adh_group.ToUpper())."
}

Write-Host "DEBUG: Subscriptions to scan = $($subs.Name -join ', ')" -ForegroundColor Cyan

$out = @()

foreach ($sub in $subs) {
    Set-ScContext -Subscription $sub
    Write-Host ""
    Write-Host "=== Subscription: $($sub.Name) ===" -ForegroundColor Cyan

    foreach ($r in $rows) {

        # --- Placeholder substitution ---
        $rgName = ($r.ResourceGroupName -replace '<Custodian>', $BaseCustodian).Trim()

        $saName = ($r.StorageAccountName -replace '<Custodian>', $BaseCustodian)
        $saName = ($saName -replace '<Cust>', $BaseCustLower).Trim()

        $cont = ($r.ContainerName -replace '<Custodian>', $BaseCustodian)
        $cont = ($cont -replace '<Cust>', $BaseCustLower).Trim()

        # Supports comma-separated identities in CSV
        $identities = @()
        if ($r.Identity) {
            $identities = $r.Identity.Split(',') |
                ForEach-Object { ($_ -replace '<Custodian>', $CustIdentity).Trim() } |
                Where-Object { $_ }
        }

        # --- env filter for storage naming conventions (optional safety) ---
        if ($adh_subscription_type -eq 'prd') {
            if ($saName -match 'adlsnonprd$') { continue }
        } else {
            if ($saName -match 'adlsprd$') { continue }
        }

        # --- AccessPath normalization ---
        $accessPath = ($r.AccessPath -replace '<Custodian>', $BaseCustodian)
        $accessPath = ($accessPath -replace '<Cust>', $BaseCustLower).Trim()

        # If using '/catalog...' style, rewrite to '/adh_<group>...'
        if ($accessPath -like '/catalog*') {
            $suffix = $accessPath.Substring('/catalog'.Length)
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
                    MatchedAtPath    = ''
                    ResolvedObjectId = ''
                }
            }
            continue
        }

        # --- Resolve storage + container ---
        $ctx = $null
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
                    MatchedAtPath    = ''
                    ResolvedObjectId = ''
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
                    MatchedAtPath    = ''
                    ResolvedObjectId = ''
                }
            }
            continue
        }

        # --- ACL validation (folder + parents + root) ---
        $permType = $r.PermissionType
        $pathsToCheck = Get-PathsToCheck -NormalizedPath $normalizedPath

        foreach ($iden in $identities) {

            $objectId = Resolve-IdentityObjectId -IdentityName $iden -GraphToken $graphToken

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
                    Notes            = "Cannot resolve '$iden' to an Entra objectId. Use GUID or fix Graph perms/consent."
                    MatchedAtPath    = ''
                    ResolvedObjectId = ''
                }
                continue
            }

            $matchedAt = $null

            try {
                foreach ($p in $pathsToCheck) {
                    $entries = Read-AclEntries -FileSystem $cont -Context $ctx -Path $p

                    if ($DebugAcls) {
                        $disp = if ($p -and $p.Trim() -ne '') { "/$p" } else { "/" }
                        Write-Host "DEBUG ACLs for '$disp' :" -ForegroundColor DarkGray
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
                Permission       = $permType
                Status           = $status
                Notes            = $notes
                MatchedAtPath    = ($matchedAt ? $matchedAt : '')
                ResolvedObjectId = $objectId
            }
        }
    }
}

# Safety: always output something
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
        MatchedAtPath    = ''
        ResolvedObjectId = ''
    }
}

$groupForFile = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) { $adh_group } else { "${adh_group}-${adh_sub_group}" }
$stamp  = Get-Date -Format 'yyyyMMdd'
$csvOut = Join-Path $OutputDir ("adls_acl_{0}_{1}_{2}.csv" -f $groupForFile, $adh_subscription_type, $stamp)

Write-CsvSafe -Rows $out -Path $csvOut

Write-Host "ADLS validation completed." -ForegroundColor Green
Write-Host "CSV : $csvOut"
exit 0
