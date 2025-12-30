# Scan-ADLS-Acls.ps1
# ADLS Gen2 ACL validator (WORKING)
# - Works in Azure DevOps agents
# - Supports -BranchName (pipeline compatibility)
# - Resolves identities via Microsoft Graph (preferred) and falls back to AzAD
# - Accepts GUIDs in Identity column (objectId OR appId for SPN)
# - Supports comma-separated Identity values in CSV
# - Validates ACLs on folder + parent folders + container root
# - Writes CSV output

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

    # ✅ Keep for ADO pipeline compatibility (optional)
    [string]$BranchName = '',

    [switch]$DebugAcls
)

# ---------------- Modules ----------------
Import-Module Az.Accounts, Az.Resources, Az.Storage -ErrorAction Stop

# ---------------- Helpers ----------------
function Ensure-Dir([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Write-CsvSafe {
    param([Parameter(Mandatory)][object[]]$Rows,[Parameter(Mandatory)][string]$Path)
    Ensure-Dir -Path (Split-Path -Parent $Path)
    $Rows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $Path -Force
}

function Connect-ScAz {
    param([string]$TenantId,[string]$ClientId,[string]$ClientSecret)
    $sec  = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential($ClientId, $sec)
    Connect-AzAccount -ServicePrincipal -Tenant $TenantId -Credential $cred -ErrorAction Stop | Out-Null
}

function Set-ScContext { param($Subscription) Set-AzContext -SubscriptionId $Subscription.Id -ErrorAction Stop | Out-Null }

# Best-effort subscription selection. If Common.psm1 has Resolve-ScSubscriptions, we use it.
function Resolve-Subscriptions {
    param([string]$adh_group,[ValidateSet('nonprd','prd')]$adh_subscription_type)

    $all = Get-AzSubscription -ErrorAction Stop

    # Try to narrow by custodian name
    $byGroup = $all | Where-Object { $_.Name -match [regex]::Escape($adh_group) }
    $subs = if ($byGroup) { $byGroup } else { $all }

    # Then narrow by env keywords
    if ($adh_subscription_type -eq 'prd') {
        $envFiltered = $subs | Where-Object { $_.Name -match '(?i)\b(prd|prod|production)\b' }
    } else {
        $envFiltered = $subs | Where-Object { $_.Name -match '(?i)\b(nonprd|non-prd|dev|tst|test|qa|uat)\b' }
    }

    if ($envFiltered) { return $envFiltered }
    return $subs
}

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

    # '' means container root
    if ([string]::IsNullOrWhiteSpace($NormalizedPath) -or $NormalizedPath -eq '/') {
        return @('')
    }

    $p = $NormalizedPath.Trim().TrimStart('/') -replace '//+','/'
    $parts = $p.Split('/', [System.StringSplitOptions]::RemoveEmptyEntries)

    # deepest -> parents -> root
    $paths = New-Object System.Collections.Generic.List[string]
    for ($i = $parts.Length; $i -ge 1; $i--) {
        $paths.Add( ($parts[0..($i-1)] -join '/') )
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
        if ($ace.EntityId -ne $ObjectId) { continue }

        $acePerm = $ace.Permissions.ToString()
        if (Perm-Ok -acePerm $acePerm -permType $PermType) { return $true }
    }
    return $false
}

# ---------------- Graph token + identity lookup ----------------
function Get-GraphToken {
    param([string]$TenantId,[string]$ClientId,[string]$ClientSecret)
    $body = @{
        client_id     = $ClientId
        client_secret = $ClientSecret
        grant_type    = 'client_credentials'
        scope         = 'https://graph.microsoft.com/.default'
    }
    $resp = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Body $body -ContentType 'application/x-www-form-urlencoded'
    return $resp.access_token
}

function Invoke-GraphGet {
    param([string]$Token,[string]$Uri)
    $headers = @{ Authorization = "Bearer $Token" }
    return Invoke-RestMethod -Method Get -Uri $Uri -Headers $headers
}

# Safe exact match on displayName; no guessing if multiple
function Resolve-IdentityViaGraph-Exact {
    param([string]$Token,[string]$Name)

    # Escape single quotes for OData: ' -> ''
    $n = $Name.Replace("'", "''")

    # SP by displayName
    $spUri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=displayName eq '$n'&`$select=id,displayName,appId"
    try {
        $sp = Invoke-GraphGet -Token $Token -Uri $spUri
        if ($sp.value.Count -eq 1) { return @{ id = $sp.value[0].id; kind='sp' } }
    } catch { }

    # Group by displayName
    $gUri = "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$n'&`$select=id,displayName"
    try {
        $g = Invoke-GraphGet -Token $Token -Uri $gUri
        if ($g.value.Count -eq 1) { return @{ id = $g.value[0].id; kind='group' } }
    } catch { }

    return $null
}

function Resolve-SpObjectIdByAppIdViaGraph {
    param([string]$Token,[string]$AppIdGuid)

    $spUri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$AppIdGuid'&`$select=id,appId,displayName"
    try {
        $sp = Invoke-GraphGet -Token $Token -Uri $spUri
        if ($sp.value.Count -eq 1) { return $sp.value[0].id }
    } catch { }
    return $null
}

# ---------------- Normalize inputs ----------------
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

# ---------------- Connect Azure ----------------
Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
Write-Host "Authenticated to Azure." -ForegroundColor Green

# ---------------- Graph token (preferred for identity resolution) ----------------
$graphToken = $null
try {
    $graphToken = Get-GraphToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
    Write-Host "Graph token acquired (identity resolution via Graph enabled)." -ForegroundColor Green
} catch {
    Write-Warning "Could not acquire Graph token. Will try AzAD resolution; if SPN lacks directory read, identities may remain unresolved. Error: $($_.Exception.Message)"
}

# ---------------- Custodian placeholders ----------------
$BaseCustodian = $adh_group
$BaseCustLower = $adh_group.ToLower() -replace '_',''
$CustIdentity  = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) { $adh_group } else { "${adh_group}_${adh_sub_group}" }

# ---------------- Identity cache + resolver ----------------
$script:IdentityCache = @{}

function Resolve-IdentityObjectId {
    param([Parameter(Mandatory)][string]$IdentityName)

    if ($script:IdentityCache.ContainsKey($IdentityName)) {
        return $script:IdentityCache[$IdentityName]
    }

    $resolved = $null
    $guidRef  = [ref]([Guid]::Empty)

    # If GUID provided:
    # - treat as objectId by default
    # - if Graph available, ALSO try to interpret as SP appId to objectId
    if ([Guid]::TryParse($IdentityName, $guidRef)) {

        if ($graphToken) {
            $byAppId = Resolve-SpObjectIdByAppIdViaGraph -Token $graphToken -AppIdGuid $IdentityName
            if ($byAppId) {
                $script:IdentityCache[$IdentityName] = $byAppId
                return $byAppId
            }
        }

        # fall back: assume objectId
        $script:IdentityCache[$IdentityName] = $IdentityName
        return $IdentityName
    }

    # Prefer Graph exact displayName (safe; no guessing)
    if ($graphToken) {
        $g = Resolve-IdentityViaGraph-Exact -Token $graphToken -Name $IdentityName
        if ($g -and $g.id) {
            $script:IdentityCache[$IdentityName] = $g.id
            return $g.id
        }
    }

    # Fallback to AzAD (may fail if no Directory Readers)
    $matches = @()
    try { $matches += Get-AzADGroup -DisplayName $IdentityName -ErrorAction SilentlyContinue } catch { }
    try { $matches += Get-AzADServicePrincipal -DisplayName $IdentityName -ErrorAction SilentlyContinue } catch { }

    if (-not $matches -or $matches.Count -eq 0) {
        try { $matches += Get-AzADGroup -SearchString $IdentityName -ErrorAction SilentlyContinue } catch { }
        try { $matches += Get-AzADServicePrincipal -SearchString $IdentityName -ErrorAction SilentlyContinue } catch { }
    }

    $matches = $matches | Sort-Object DisplayName -Unique
    if ($matches.Count -eq 1) { $resolved = $matches[0].Id }

    $script:IdentityCache[$IdentityName] = $resolved
    return $resolved
}

# ---------------- Load CSV ----------------
$rows = Import-Csv -LiteralPath $InputCsvPath
Write-Host ("DEBUG: CSV rows loaded: {0}" -f $rows.Count)
if ($rows.Count -gt 0) {
    Write-Host ("DEBUG: CSV headers     : " + ($rows[0].psobject.Properties.Name -join ', '))
}

# ---------------- Subscriptions ----------------
# If Common.psm1 provides Resolve-ScSubscriptions, use it; else fallback.
$subs = $null
try {
    if (Get-Command Resolve-ScSubscriptions -ErrorAction SilentlyContinue) {
        $subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
    }
} catch { }

if (-not $subs) {
    $subs = Resolve-Subscriptions -adh_group $adh_group -adh_subscription_type $adh_subscription_type
}
if ($subs -isnot [System.Collections.IEnumerable]) { $subs = ,$subs }
if (-not $subs -or $subs.Count -eq 0) { throw "No subscriptions found/accessible for this SPN." }

Write-Host "DEBUG: Subscriptions = $($subs.Name -join ', ')" -ForegroundColor DarkCyan

$out = @()

foreach ($sub in $subs) {
    Set-ScContext -Subscription $sub
    Write-Host ""
    Write-Host "=== Subscription: $($sub.Name) ===" -ForegroundColor Cyan

    foreach ($r in $rows) {

        # -------- Placeholder substitution --------
        $rgName = ($r.ResourceGroupName -replace '<Custodian>', $BaseCustodian).Trim()

        $saName = ($r.StorageAccountName -replace '<Custodian>', $BaseCustodian)
        $saName = ($saName -replace '<Cust>', $BaseCustLower).Trim()

        $cont = ($r.ContainerName -replace '<Custodian>', $BaseCustodian)
        $cont = ($cont -replace '<Cust>', $BaseCustLower).Trim()

        # Identity may be comma-separated
        $identities = @()
        if ($r.Identity) {
            $identities = $r.Identity.Split(',') |
                ForEach-Object { ($_ -replace '<Custodian>', $CustIdentity).Trim() } |
                Where-Object { $_ }
        }

        # -------- env filter (optional naming convention) --------
        if ($adh_subscription_type -eq 'prd') {
            if ($saName -match 'adlsnonprd$') { continue }
        } else {
            if ($saName -match 'adlsprd$') { continue }
        }

        # -------- AccessPath normalization --------
        $accessPath = ($r.AccessPath -replace '<Custodian>', $BaseCustodian)
        $accessPath = ($accessPath -replace '<Cust>', $BaseCustLower).Trim()

        # Special rewrite for '/catalog*'
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

        if ([string]::IsNullOrWhiteSpace($rgName) -or [string]::IsNullOrWhiteSpace($saName) -or [string]::IsNullOrWhiteSpace($cont)) {
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
                    Notes            = 'After placeholder replacement RG/Storage/Container is empty.'
                }
            }
            continue
        }

        # -------- Resolve storage + container --------
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

        # -------- ACL validation --------
        $permType = $r.PermissionType
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
                    Notes            = "Cannot resolve '$iden' to Entra objectId (Graph/AzAD lookup failed). Best fix: put objectId GUID in CSV Identity."
                }
                continue
            }

            $matchedAt = $null
            try {
                foreach ($p in $pathsToCheck) {
                    $entries = Read-AclEntries -FileSystem $cont -Context $ctx -Path $p

                    if ($DebugAcls) {
                        $disp = if ($p -and $p.Trim() -ne '') { "/$p" } else { "/" }
                        Write-Host "DEBUG ACLs for '$disp':" -ForegroundColor DarkGray
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

# Safety
if (-not $out -or $out.Count -eq 0) {
    $out += [pscustomobject]@{
        SubscriptionName=''; ResourceGroup=''; Storage=''; Container=''; Folder=''
        Identity=''; Permission=''; Status='NO_RESULTS'; Notes='Nothing matched in scan'
    }
}

$groupForFile = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) { $adh_group } else { "${adh_group}-${adh_sub_group}" }
$stamp  = Get-Date -Format 'yyyyMMdd'
$csvOut = Join-Path $OutputDir ("adls_acl_{0}_{1}_{2}.csv" -f $groupForFile, $adh_subscription_type, $stamp)

Write-CsvSafe -Rows $out -Path $csvOut
Write-Host "ADLS validation completed." -ForegroundColor Green
Write-Host "CSV : $csvOut"

exit 0
