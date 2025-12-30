# Scan-ADLS-Acls.ps1
# ADLS Gen2 ACL validator (Volvo naming strict)
# - Scans ONLY subscriptions matching: <dev|prd>_azure_<digits>_ADH<adh_group>
# - Resolves identities via Microsoft Graph (preferred) + AzAD fallback
# - Accepts GUIDs directly (objectId OR appId -> resolves to SP objectId when possible)
# - Checks folder + parents + container root ACLs
# - Supports comma-separated Identity values
# - CSV output

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

    # Keep BranchName ONLY if your pipeline passes it.
    # If your pipeline passes -BranchName and the script doesn't have it, it will FAIL.
    [string]$BranchName = '',

    [switch]$DebugAcls
)

# ---------------- Modules ----------------
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
        return $true
    } catch {
        Write-Error "Connect-AzAccount failed: $($_.Exception.Message)"
        return $false
    }
}

function Set-ScContext {
    param([Parameter(Mandatory)]$Subscription)
    Set-AzContext -SubscriptionId $Subscription.Id -ErrorAction Stop | Out-Null
}

# ---------------- Subscription resolver (STRICT) ----------------
function Resolve-SubscriptionsStrict {
    param(
        [Parameter(Mandatory)][string]$adh_group,
        [ValidateSet('nonprd','prd')][string]$adh_subscription_type
    )

    $prefix = if ($adh_subscription_type -eq 'prd') { 'prd_azure_' } else { 'dev_azure_' }

    # Pattern: <prefix><digits>_ADH<adh_group>
    # Example: dev_azure_20481_ADHCIT
    $regex = '^(?i)' + [regex]::Escape($prefix) + '\d+_ADH' + [regex]::Escape($adh_group) + '$'

    $all = Get-AzSubscription -ErrorAction Stop
    $picked = $all | Where-Object { $_.Name -match $regex }
    return $picked
}

# ---------------- ACL logic helpers ----------------
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
        return @('')  # container root only
    }

    $p = $NormalizedPath.Trim().TrimStart('/') -replace '//+','/'
    $parts = $p.Split('/', [System.StringSplitOptions]::RemoveEmptyEntries)

    $paths = New-Object System.Collections.Generic.List[string]
    for ($i = $parts.Length; $i -ge 1; $i--) {
        $paths.Add(($parts[0..($i-1)] -join '/'))
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

    $resp = Invoke-RestMethod -Method Post `
        -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
        -Body $body -ContentType 'application/x-www-form-urlencoded'

    return $resp.access_token
}

function Invoke-GraphGet {
    param([string]$Token,[string]$Uri)

    $headers = @{ Authorization = "Bearer $Token" }
    return Invoke-RestMethod -Method Get -Uri $Uri -Headers $headers
}

function Escape-ODataString {
    param([string]$s)
    if ($null -eq $s) { return '' }
    return $s.Replace("'", "''")
}

# Returns: @{ id=<objectId>; type='sp'|'group' } or $null
function Resolve-IdentityViaGraph {
    param([string]$Token,[string]$Name)

    $n = Escape-ODataString $Name

    # Exact match SP
    $spUri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=displayName eq '$n'&`$select=id,displayName"
    try {
        $sp = Invoke-GraphGet -Token $Token -Uri $spUri
        if ($sp.value.Count -eq 1) { return @{ id = $sp.value[0].id; type='sp' } }
    } catch { }

    # Exact match Group
    $gUri = "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$n'&`$select=id,displayName"
    try {
        $g = Invoke-GraphGet -Token $Token -Uri $gUri
        if ($g.value.Count -eq 1) { return @{ id = $g.value[0].id; type='group' } }
    } catch { }

    # Fallback: startswith filter (no $search header required)
    # This avoids $search ConsistencyLevel header issues in some tenants.
    $spStart = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=startswith(displayName,'$n')&`$select=id,displayName&`$top=5"
    try {
        $sp2 = Invoke-GraphGet -Token $Token -Uri $spStart
        if ($sp2.value.Count -eq 1) { return @{ id = $sp2.value[0].id; type='sp' } }
    } catch { }

    $gStart = "https://graph.microsoft.com/v1.0/groups?`$filter=startswith(displayName,'$n')&`$select=id,displayName&`$top=5"
    try {
        $g2 = Invoke-GraphGet -Token $Token -Uri $gStart
        if ($g2.value.Count -eq 1) { return @{ id = $g2.value[0].id; type='group' } }
    } catch { }

    return $null
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
Write-Host "DEBUG: BranchName    = $BranchName"

# ---------------- Connect Azure ----------------
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure connection failed."
}

# ---------------- Graph token ----------------
$graphToken = $null
try {
    $graphToken = Get-GraphToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
    Write-Host "Graph token acquired." -ForegroundColor Green
} catch {
    Write-Warning "Graph token NOT acquired. Identity name resolution may fail. Error: $($_.Exception.Message)"
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

function Resolve-IdentityObjectId {
    param([Parameter(Mandatory)][string]$IdentityName)

    if ($script:IdentityCache.ContainsKey($IdentityName)) { return $script:IdentityCache[$IdentityName] }

    $guidRef = [ref]([Guid]::Empty)

    # If GUID provided: treat as objectId, BUT try to map appId->objectId for SPs
    if ([Guid]::TryParse($IdentityName, $guidRef)) {
        if ($graphToken) {
            try {
                # If it's actually an appId, resolve to SP objectId
                $spByAppIdUri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$IdentityName'&`$select=id,appId"
                $sp = Invoke-GraphGet -Token $graphToken -Uri $spByAppIdUri
                if ($sp.value.Count -eq 1) {
                    $script:IdentityCache[$IdentityName] = $sp.value[0].id
                    return $sp.value[0].id
                }
            } catch { }
        }
        $script:IdentityCache[$IdentityName] = $IdentityName
        return $IdentityName
    }

    # Preferred: Graph name resolution
    if ($graphToken) {
        $r = Resolve-IdentityViaGraph -Token $graphToken -Name $IdentityName
        if ($r -and $r.id) {
            $script:IdentityCache[$IdentityName] = $r.id
            return $r.id
        }
    }

    # Fallback: AzAD (may fail in locked tenants)
    $matches = @()
    try { $matches += Get-AzADGroup -DisplayName $IdentityName -ErrorAction SilentlyContinue } catch { }
    try { $matches += Get-AzADServicePrincipal -DisplayName $IdentityName -ErrorAction SilentlyContinue } catch { }

    if (-not $matches -or $matches.Count -eq 0) {
        try { $matches += Get-AzADGroup -SearchString $IdentityName -ErrorAction SilentlyContinue } catch { }
        try { $matches += Get-AzADServicePrincipal -SearchString $IdentityName -ErrorAction SilentlyContinue } catch { }
    }

    $matches = $matches | Sort-Object DisplayName -Unique
    $id = $null
    if ($matches.Count -eq 1) { $id = $matches[0].Id }

    $script:IdentityCache[$IdentityName] = $id
    return $id
}

# ---------------- Load CSV ----------------
$rows = Import-Csv -LiteralPath $InputCsvPath
Write-Host ("DEBUG: CSV rows loaded: {0}" -f $rows.Count)
if ($rows.Count -gt 0) {
    Write-Host ("DEBUG: CSV headers     : " + ($rows[0].psobject.Properties.Name -join ', '))
}

# ---------------- Subscriptions (STRICT to your naming) ----------------
$subs = Resolve-SubscriptionsStrict -adh_group $adh_group -adh_subscription_type $adh_subscription_type
if ($subs -isnot [System.Collections.IEnumerable]) { $subs = ,$subs }

if (-not $subs -or $subs.Count -eq 0) {
    $wantedPrefix = if ($adh_subscription_type -eq 'prd') { 'prd_azure_' } else { 'dev_azure_' }
    throw "No subscriptions matched: ${wantedPrefix}<digits>_ADH$adh_group"
}

Write-Host "DEBUG: Subscriptions selected = $($subs.Name -join ', ')" -ForegroundColor Cyan

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

        # Comma-separated identities supported
        $identities = @()
        if ($r.Identity) {
            $identities = $r.Identity.Split(',') |
                ForEach-Object { ($_ -replace '<Custodian>', $CustIdentity).Trim() } |
                Where-Object { $_ }
        } else {
            $identities = @('')
        }

        # --- env filter for storage naming conventions (keep if you need it) ---
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

        # Normalize for API: '' = root, 'a/b' = path
        $normalizedPath = $accessPath.Trim()
        if ($normalizedPath -eq '/') { $normalizedPath = '' }
        $normalizedPath = $normalizedPath.TrimStart('/')
        $normalizedPath = $normalizedPath -replace '//+','/'

        $folderForReport = if ([string]::IsNullOrWhiteSpace($normalizedPath)) { '/' } else { "/$normalizedPath" }

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

        # --- Resolve storage + container ---
        $ctx = $null
        try {
            $sa  = Get-AzStorageAccount -ResourceGroupName $rgName -Name $saName -ErrorAction Stop
            $ctx = $sa.Context
        } catch {
            foreach ($iden in $identities) {
                $out += [pscustomobject]@{
                    SubscriptionName = $sub.Name; ResourceGroup=$rgName; Storage=$saName; Container=$cont; Folder=$folderForReport
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
                    SubscriptionName = $sub.Name; ResourceGroup=$rgName; Storage=$saName; Container=$cont; Folder=$folderForReport
                    Identity=$iden; Permission=$r.PermissionType; Status='ERROR'
                    Notes="Container fetch error: $($_.Exception.Message)"
                }
            }
            continue
        }

        # --- ACL validation per identity ---
        $permType = $r.PermissionType
        $pathsToCheck = Get-PathsToCheck -NormalizedPath ("/$normalizedPath")

        foreach ($iden in $identities) {

            # IMPORTANT: ACL EntityId matches Entra objectId (NOT display name).
            $objectId = Resolve-IdentityObjectId -IdentityName $iden

            if (-not $objectId) {
                $out += [pscustomobject]@{
                    SubscriptionName=$sub.Name; ResourceGroup=$rgName; Storage=$saName; Container=$cont; Folder=$folderForReport
                    Identity=$iden; Permission=$permType
                    Status='UNRESOLVED_IDENTITY'
                    Notes="Cannot resolve '$iden' to an Entra objectId. Provide GUID objectId/appId, or ensure Graph permissions + admin consent."
                }
                continue
            }

            $matchedAt = $null
            try {
                foreach ($p in $pathsToCheck) {
                    # p is '' for root OR 'a/b'
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

$groupForFile = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) { $adh_group } else { "${adh_group}-${adh_sub_group}" }
$stamp  = Get-Date -Format 'yyyyMMdd'
$csvOut = Join-Path $OutputDir ("adls_acl_{0}_{1}_{2}.csv" -f $groupForFile, $adh_subscription_type, $stamp)

Write-CsvSafe -Rows $out -Path $csvOut

Write-Host "ADLS validation completed." -ForegroundColor Green
Write-Host "CSV : $csvOut"
exit 0
