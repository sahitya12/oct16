# Scan-ADLS-Acls.ps1
# ADLS Gen2 ACL validator
# - Subscription selection strictly by naming: <dev|prd>_azure_*_ADH<adh_group>
# - Graph-based identity resolution (app perms) + AzAD fallback
# - Checks folder + parents + container root ACLs
# - CSV output (always)

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

    # ✅ Option 1: keep pipeline unchanged (pipeline passes -BranchName)
    [string]$BranchName = '',

    [switch]$DebugAcls
)

# ---------------- Modules ----------------
Import-Module Az.Accounts, Az.Resources, Az.Storage -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

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

function Set-ScContext {
    param([Parameter(Mandatory)]$Subscription)
    Set-AzContext -SubscriptionId $Subscription.Id -ErrorAction Stop | Out-Null
}

# ---------------- Subscription resolver (STRICT) ----------------
function Resolve-SubscriptionsStrict {
    param(
        [Parameter(Mandatory)][string]$adh_group,
        [Parameter(Mandatory)][ValidateSet('nonprd','prd')]$adh_subscription_type
    )

    # nonprd => dev_azure_####_ADH<group>
    # prd    => prd_azure_####_ADH<group>
    $prefix = if ($adh_subscription_type -eq 'prd') { 'prd' } else { 'dev' }

    # Example expected: dev_azure_20481_ADHCIT
    # NOTE: adh_group may be "CIT" and subscription name has "ADHCIT" (no underscore)
    $groupToken = ("ADH{0}" -f ($adh_group -replace '_','')).ToUpper()

    $regex = "^(?i){0}_azure_\d+_{1}$" -f $prefix, [regex]::Escape($groupToken)

    $all = Get-AzSubscription -ErrorAction Stop
    $matched = $all | Where-Object { $_.Name -match $regex }

    Write-Host "DEBUG: Subscription name regex = $regex" -ForegroundColor DarkGray
    if ($matched) {
        Write-Host "DEBUG: Matched subscriptions   = $($matched.Name -join ', ')" -ForegroundColor Green
    } else {
        Write-Warning "No subscriptions matched regex. Check adh_group/adh_subscription_type or naming convention."
    }

    return $matched
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

# ---------------- Graph identity resolution ----------------
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

function Resolve-IdentityViaGraph {
    param([string]$Token,[string]$Name)

    $safe = $Name.Replace("'", "''")

    # servicePrincipals by exact displayName
    $spUri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=displayName eq '$safe'&`$select=id,displayName"
    try {
        $sp = Invoke-GraphGet -Token $Token -Uri $spUri
        if ($sp.value.Count -eq 1) { return $sp.value[0].id }
    } catch { }

    # groups by exact displayName
    $gUri = "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$safe'&`$select=id,displayName"
    try {
        $g = Invoke-GraphGet -Token $Token -Uri $gUri
        if ($g.value.Count -eq 1) { return $g.value[0].id }
    } catch { }

    return $null
}

# ---------------- Normalize inputs ----------------
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

# ---------------- Login (Common.psm1 style) ----------------
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure connection failed."
}

# ---------------- Graph token ----------------
$graphToken = $null
try {
    $graphToken = Get-GraphToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
    Write-Host "Graph token acquired." -ForegroundColor Green
} catch {
    Write-Warning "Graph token NOT acquired. Identity resolution may fail by name. Error: $($_.Exception.Message)"
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

    $guidRef = [ref]([Guid]::Empty)

    # If GUID provided, accept as objectId (or try appId->sp objectId)
    if ([Guid]::TryParse($IdentityName, $guidRef)) {
        if ($graphToken) {
            try {
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

    # Graph by name (exact)
    if ($graphToken) {
        $id = Resolve-IdentityViaGraph -Token $graphToken -Name $IdentityName
        if ($id) {
            $script:IdentityCache[$IdentityName] = $id
            return $id
        }
    }

    # AzAD fallback
    $matches = @()
    try { $matches += Get-AzADGroup -SearchString $IdentityName -ErrorAction SilentlyContinue } catch { }
    try { $matches += Get-AzADServicePrincipal -SearchString $IdentityName -ErrorAction SilentlyContinue } catch { }

    $matches = $matches | Sort-Object DisplayName -Unique
    $id2 = $null
    if ($matches.Count -eq 1) { $id2 = $matches[0].Id }

    $script:IdentityCache[$IdentityName] = $id2
    return $id2
}

# ---------------- Load CSV ----------------
$rows = Import-Csv -LiteralPath $InputCsvPath
Write-Host ("DEBUG: CSV rows loaded: {0}" -f $rows.Count)

# ---------------- Subscriptions (STRICT) ----------------
$subs = Resolve-SubscriptionsStrict -adh_group $adh_group -adh_subscription_type $adh_subscription_type
if (-not $subs -or $subs.Count -eq 0) {
    throw "No subscriptions matched for adh_group='$adh_group' and adh_subscription_type='$adh_subscription_type'."
}

$out = @()

foreach ($sub in $subs) {
    Set-ScContext -Subscription $sub
    Write-Host ""
    Write-Host "=== Subscription: $($sub.Name) ===" -ForegroundColor Cyan

    foreach ($r in $rows) {

        # ---- placeholder substitution ----
        $rgName = ($r.ResourceGroupName -replace '<Custodian>', $BaseCustodian).Trim()

        $saName = ($r.StorageAccountName -replace '<Custodian>', $BaseCustodian)
        $saName = ($saName -replace '<Cust>', $BaseCustLower).Trim()

        $cont = ($r.ContainerName -replace '<Custodian>', $BaseCustodian)
        $cont = ($cont -replace '<Cust>', $BaseCustLower).Trim()

        $iden = ($r.Identity -replace '<Custodian>', $CustIdentity).Trim()

        $accessPath = ($r.AccessPath -replace '<Custodian>', $BaseCustodian)
        $accessPath = ($accessPath -replace '<Cust>', $BaseCustLower).Trim()

        # /catalog -> /adh_<group>
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

        # ---- Resolve storage + container ----
        $ctx = $null
        try {
            $sa  = Get-AzStorageAccount -ResourceGroupName $rgName -Name $saName -ErrorAction Stop
            $ctx = $sa.Context
        } catch {
            $out += [pscustomobject]@{
                SubscriptionName=$sub.Name; ResourceGroup=$rgName; Storage=$saName; Container=$cont; Folder=$folderForReport
                Identity=$iden; Permission=$r.PermissionType; Status='ERROR'
                Notes="Storage account error: $($_.Exception.Message)"
            }
            continue
        }

        try {
            $null = Get-AzStorageContainer -Name $cont -Context $ctx -ErrorAction Stop
        } catch {
            $out += [pscustomobject]@{
                SubscriptionName=$sub.Name; ResourceGroup=$rgName; Storage=$saName; Container=$cont; Folder=$folderForReport
                Identity=$iden; Permission=$r.PermissionType; Status='ERROR'
                Notes="Container fetch error: $($_.Exception.Message)"
            }
            continue
        }

        # ---- Resolve identity ----
        $objectId = Resolve-IdentityObjectId -IdentityName $iden
        if (-not $objectId) {
            $out += [pscustomobject]@{
                SubscriptionName=$sub.Name; ResourceGroup=$rgName; Storage=$saName; Container=$cont; Folder=$folderForReport
                Identity=$iden; Permission=$r.PermissionType; Status='UNRESOLVED_IDENTITY'
                Notes="Cannot resolve '$iden' to objectId. Use GUID objectId/appId or ensure Graph consent."
            }
            continue
        }

        # ---- ACL validation (folder + parents + root) ----
        $permType = $r.PermissionType
        $pathsToCheck = Get-PathsToCheck -NormalizedPath $normalizedPath

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

# ---- Always output something ----
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
