<#
Scan-ADLS-Acls.ps1
ADLS Gen2 ACL validator (works in ADO pipeline)

Fixes included:
- ✅ BranchName param is OPTIONAL (prevents "parameter cannot be found BranchName" error)
- ✅ Subscription filtering is STRICT:
     adh_subscription_type=prd    -> only subscriptions starting with "prd_" or "prd-"
     adh_subscription_type=nonprd -> only subscriptions starting with "dev_" or "dev-"
- ✅ Identity resolution does NOT require Directory Readers if Graph app-perms exist:
     Uses Microsoft Graph client_credentials token (https://graph.microsoft.com/.default)
     Then resolves Group/SPN displayName -> objectId
     Accepts GUIDs directly (objectId OR appId -> converts appId->objectId using Graph)
- ✅ Checks ACLs on folder + parents + container root
- ✅ Supports comma-separated Identity list in CSV
- ✅ Writes CSV output always (adds NO_RESULTS row if nothing)

CSV columns expected (minimum):
ResourceGroupName, StorageAccountName, ContainerName, AccessPath, Identity, PermissionType
#>

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

    # Keep OPTIONAL to avoid pipeline error
    [string]$BranchName = '',

    # Optional: force exact sub(s) if you ever need it (comma-separated subscriptionIds)
    [string]$SubscriptionIds = '',

    [switch]$DebugAcls
)

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

# STRICT subscription selection by prefix (your requirement)
function Resolve-Subscriptions {
    param(
        [ValidateSet('nonprd','prd')]$adh_subscription_type,
        [string]$SubscriptionIds = ''
    )

    $all = Get-AzSubscription -ErrorAction Stop

    if (-not [string]::IsNullOrWhiteSpace($SubscriptionIds)) {
        $wanted = $SubscriptionIds.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
        $subs = $all | Where-Object { $wanted -contains $_.Id }
        if (-not $subs -or $subs.Count -eq 0) { throw "No matching subscriptions found for SubscriptionIds: $SubscriptionIds" }
        return $subs
    }

    if ($adh_subscription_type -eq 'prd') {
        $subs = $all | Where-Object { $_.Name -match '^(?i)prd[_-]' }
        if (-not $subs -or $subs.Count -eq 0) {
            throw "No subscriptions found with prefix 'prd_' or 'prd-' for adh_subscription_type=prd"
        }
        return $subs
    } else {
        $subs = $all | Where-Object { $_.Name -match '^(?i)dev[_-]' }
        if (-not $subs -or $subs.Count -eq 0) {
            throw "No subscriptions found with prefix 'dev_' or 'dev-' for adh_subscription_type=nonprd"
        }
        return $subs
    }
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

    # '' means root (container)
    if ([string]::IsNullOrWhiteSpace($NormalizedPath) -or $NormalizedPath -eq '/') {
        return @('')  # root only
    }

    $p = $NormalizedPath.Trim().TrimStart('/') -replace '//+','/'
    $parts = $p.Split('/', [System.StringSplitOptions]::RemoveEmptyEntries)

    # Build path list from deepest -> parents -> root
    $paths = New-Object System.Collections.Generic.List[string]
    for ($i = $parts.Length; $i -ge 1; $i--) {
        $paths.Add( ($parts[0..($i-1)] -join '/') )
    }
    $paths.Add('') # root at end
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

    return ,@($entries)  # ensure array
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

        # Main match: EntityId == objectId
        if ($ace.EntityId -and ($ace.EntityId -eq $ObjectId)) {
            return $true
        }
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
    # OData filter strings need single quotes doubled.
    return ($s -replace "'", "''")
}

# Returns objectId string or $null
function Resolve-IdentityViaGraph {
    param([string]$Token,[string]$Name)

    $n = Escape-ODataString $Name

    # 1) SPN exact displayName
    try {
        $u = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=displayName eq '$n'&`$select=id,displayName"
        $r = Invoke-GraphGet -Token $Token -Uri $u
        if ($r.value.Count -eq 1) { return $r.value[0].id }
    } catch {}

    # 2) Group exact displayName
    try {
        $u = "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$n'&`$select=id,displayName"
        $r = Invoke-GraphGet -Token $Token -Uri $u
        if ($r.value.Count -eq 1) { return $r.value[0].id }
    } catch {}

    # 3) StartsWith fallback (helps when names have suffix/prefix)
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

# Converts appId -> SP objectId (if GUID in CSV is appId)
function Resolve-ServicePrincipalObjectIdFromAppId {
    param([string]$Token,[string]$AppIdGuid)

    try {
        $u = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$AppIdGuid'&`$select=id,appId"
        $r = Invoke-GraphGet -Token $Token -Uri $u
        if ($r.value.Count -eq 1) { return $r.value[0].id }
    } catch {}
    return $null
}

# ---------------- Normalize inputs ----------------
if ($null -ne $adh_sub_group) { $adh_sub_group = $adh_sub_group.Trim() }
if ([string]::IsNullOrWhiteSpace($adh_sub_group)) { $adh_sub_group = '' }

Ensure-Dir -Path $OutputDir | Out-Null
if (-not (Test-Path -LiteralPath $InputCsvPath)) { throw "Input CSV not found: $InputCsvPath" }

Write-Host "DEBUG: BranchName = '$BranchName'" -ForegroundColor DarkGray

# ---------------- Connect Azure ----------------
Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
Write-Host "Authenticated to Azure." -ForegroundColor Green

# ---------------- Graph token (for identity resolution) ----------------
$graphToken = $null
try {
    $graphToken = Get-GraphToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
    Write-Host "Graph token acquired." -ForegroundColor Green
} catch {
    Write-Warning "Could not acquire Graph token. Identity name resolution may fail. Error: $($_.Exception.Message)"
}

# ---------------- Custodian placeholders ----------------
$BaseCustodian = $adh_group
$BaseCustLower = $adh_group.ToLower() -replace '_',''
$CustIdentity  = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) { $adh_group } else { "${adh_group}_${adh_sub_group}" }

# ---------------- Identity cache ----------------
$script:IdentityCache = @{}

function Resolve-IdentityObjectId {
    param([Parameter(Mandatory)][string]$IdentityName)

    if ($script:IdentityCache.ContainsKey($IdentityName)) { return $script:IdentityCache[$IdentityName] }

    $IdentityName = $IdentityName.Trim()
    $id = $null

    # GUID? could be objectId OR appId
    $guidRef = [ref]([Guid]::Empty)
    if ([Guid]::TryParse($IdentityName, $guidRef)) {
        # If Graph is available, try to treat this GUID as appId and map to objectId
        if ($graphToken) {
            $maybeObjId = Resolve-ServicePrincipalObjectIdFromAppId -Token $graphToken -AppIdGuid $IdentityName
            if ($maybeObjId) {
                $script:IdentityCache[$IdentityName] = $maybeObjId
                return $maybeObjId
            }
        }
        # Otherwise accept GUID as objectId
        $script:IdentityCache[$IdentityName] = $IdentityName
        return $IdentityName
    }

    # Prefer Graph resolution (doesn't need Directory Readers role if app perms exist)
    if ($graphToken) {
        $id = Resolve-IdentityViaGraph -Token $graphToken -Name $IdentityName
        if ($id) {
            $script:IdentityCache[$IdentityName] = $id
            return $id
        }
    }

    # Fallback AzAD (may fail without Entra read permissions)
    try { $g = Get-AzADGroup -DisplayName $IdentityName -ErrorAction Stop; if ($g.Id) { $id = $g.Id } } catch {}
    if (-not $id) {
        try { $sp = Get-AzADServicePrincipal -DisplayName $IdentityName -ErrorAction Stop; if ($sp.Id) { $id = $sp.Id } } catch {}
    }
    if (-not $id) {
        try {
            $sp2 = Get-AzADServicePrincipal -SearchString $IdentityName -ErrorAction Stop
            if ($sp2 -and $sp2.Count -ge 1) { $id = $sp2[0].Id }
        } catch {}
    }

    $script:IdentityCache[$IdentityName] = $id
    return $id
}

# ---------------- Load CSV ----------------
$rows = Import-Csv -LiteralPath $InputCsvPath
Write-Host ("DEBUG: CSV rows loaded: {0}" -f $rows.Count) -ForegroundColor DarkGray
if ($rows.Count -gt 0) {
    Write-Host ("DEBUG: CSV headers: " + ($rows[0].psobject.Properties.Name -join ', ')) -ForegroundColor DarkGray
}

# ---------------- Subscriptions (STRICT) ----------------
$subs = Resolve-Subscriptions -adh_subscription_type $adh_subscription_type -SubscriptionIds $SubscriptionIds
Write-Host "DEBUG: Subscriptions selected = $($subs.Name -join ', ')" -ForegroundColor Cyan

$out = @()

foreach ($sub in $subs) {
    Set-ScContext -Subscription $sub
    Write-Host ""
    Write-Host "=== Subscription: $($sub.Name) ===" -ForegroundColor Cyan

    foreach ($r in $rows) {

        # Placeholders
        $rgName = ($r.ResourceGroupName -replace '<Custodian>', $BaseCustodian).Trim()

        $saName = ($r.StorageAccountName -replace '<Custodian>', $BaseCustodian)
        $saName = ($saName -replace '<Cust>', $BaseCustLower).Trim()

        $cont = ($r.ContainerName -replace '<Custodian>', $BaseCustodian)
        $cont = ($cont -replace '<Cust>', $BaseCustLower).Trim()

        # AccessPath normalize
        $accessPath = ($r.AccessPath -replace '<Custodian>', $BaseCustodian)
        $accessPath = ($accessPath -replace '<Cust>', $BaseCustLower).Trim()

        # If CSV uses /catalog... rewrite to /adh_<group>...
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

        # Identity list: support comma-separated identities in one row
        $identities = @()
        if ($r.Identity) {
            $identities = $r.Identity.Split(',') |
                ForEach-Object { ($_ -replace '<Custodian>', $CustIdentity).Trim() } |
                Where-Object { $_ }
        }

        if (-not $identities -or $identities.Count -eq 0) {
            $out += [pscustomobject]@{
                SubscriptionName=$sub.Name; ResourceGroup=$rgName; Storage=$saName; Container=$cont; Folder=$folderForReport
                Identity=''; Permission=$r.PermissionType; Status='ERROR'
                Notes="Identity column empty in CSV row."
            }
            continue
        }

        if ([string]::IsNullOrWhiteSpace($rgName) -or [string]::IsNullOrWhiteSpace($saName)) {
            foreach ($iden in $identities) {
                $out += [pscustomobject]@{
                    SubscriptionName=$sub.Name; ResourceGroup=$rgName; Storage=$saName; Container=$cont; Folder=$folderForReport
                    Identity=$iden; Permission=$r.PermissionType; Status='ERROR'
                    Notes="After placeholder replacement, RG or Storage is empty."
                }
            }
            continue
        }

        # Resolve storage + container
        $ctx = $null
        try {
            $sa  = Get-AzStorageAccount -ResourceGroupName $rgName -Name $saName -ErrorAction Stop
            $ctx = $sa.Context
        } catch {
            foreach ($iden in $identities) {
                $out += [pscustomobject]@{
                    SubscriptionName=$sub.Name; ResourceGroup=$rgName; Storage=$saName; Container=$cont; Folder=$folderForReport
                    Identity=$iden; Permission=$r.PermissionType; Status='ERROR'
                    Notes="Storage account error: $($_.Exception.Message)"
                }
            }
            continue
        }

        try {
            $null = Get-AzStorageContainer -Name $cont -Context $ctx -ErrorAction Stop
        } catch {
            foreach ($iden in $identities) {
                $out += [pscustomobject]@{
                    SubscriptionName=$sub.Name; ResourceGroup=$rgName; Storage=$saName; Container=$cont; Folder=$folderForReport
                    Identity=$iden; Permission=$r.PermissionType; Status='ERROR'
                    Notes="Container fetch error: $($_.Exception.Message)"
                }
            }
            continue
        }

        # ACL validation per identity
        $permType = $r.PermissionType
        $pathsToCheck = Get-PathsToCheck -NormalizedPath $normalizedPath

        foreach ($iden in $identities) {

            $objectId = Resolve-IdentityObjectId -IdentityName $iden

            if (-not $objectId) {
                $out += [pscustomobject]@{
                    SubscriptionName=$sub.Name; ResourceGroup=$rgName; Storage=$saName; Container=$cont; Folder=$folderForReport
                    Identity=$iden; Permission=$permType
                    Status='UNRESOLVED_IDENTITY'
                    Notes="Cannot resolve '$iden' to Entra objectId. (Graph/AzAD lookup failed). Prefer using GUID objectId/appId in CSV."
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
                    $notes  = "ACL matched at '$matchedAt' (folder/parents/root checked)"
                } else {
                    $status = 'MISSING'
                    $notes  = "No matching ACE for objectId '$objectId' with perm '$permType' on folder/parents/root"
                }
            } catch {
                $status = 'ERROR'
                $notes  = "ACL read error: $($_.Exception.Message)"
            }

            $out += [pscustomobject]@{
                SubscriptionName=$sub.Name
                ResourceGroup=$rgName
                Storage=$saName
                Container=$cont
                Folder=$folderForReport
                Identity=$iden
                Permission=$permType
                Status=$status
                Notes=$notes
            }
        }
    }
}

# Safety: always output something
if (-not $out -or $out.Count -eq 0) {
    $out += [pscustomobject]@{
        SubscriptionName=''; ResourceGroup=''; Storage=''; Container=''; Folder=''
        Identity=''; Permission=''; Status='NO_RESULTS'; Notes='Nothing matched in scan'
    }
}

# Export
$groupForFile = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) { $adh_group } else { "${adh_group}-${adh_sub_group}" }
$stamp  = Get-Date -Format 'yyyyMMdd'
$csvOut = Join-Path $OutputDir ("adls_acl_{0}_{1}_{2}.csv" -f $groupForFile, $adh_subscription_type, $stamp)

Write-CsvSafe -Rows $out -Path $csvOut
Write-Host "ADLS validation completed." -ForegroundColor Green
Write-Host "CSV : $csvOut"
exit 0
