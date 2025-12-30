# Scan-ADLS-Acls.ps1
# ADLS Gen2 ACL validator (matches your RG script subscription selection style)
# - Scans ONLY subscriptions resolved by Resolve-ScSubscriptions (adh_group + env)
# - Additionally enforces env prefix in subscription name: dev_* for nonprd, prd_* for prd
# - Identity resolution via Microsoft Graph (no Directory Readers required)
# - Accepts GUIDs directly (objectId OR appId)
# - Checks folder + parents + container root ACLs
# - Supports comma-separated Identity values
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

    [string]$BranchName = '',

    [switch]$DebugAcls
)

Import-Module Az.Accounts, Az.Resources, Az.Storage -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

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
    for ($i = $parts.Length; $i -ge 1; $i--) { $paths.Add(($parts[0..($i-1)] -join '/')) }
    $paths.Add('') # root
    return $paths.ToArray()
}

function Read-AclEntries {
    param([string]$FileSystem,$Context,[string]$Path)

    $p = @{ FileSystem = $FileSystem; Context = $Context; ErrorAction = 'Stop' }
    if ($Path -and $Path.Trim() -ne '') { $p['Path'] = $Path }

    $item = Get-AzDataLakeGen2Item @p

    $entries = @()
    if ($item.Acl)        { $entries += $item.Acl }
    if ($item.DefaultAcl) { $entries += $item.DefaultAcl }
    return $entries
}

function Has-MatchingAce {
    param([object[]]$Entries,[string]$ObjectId,[string]$PermType)
    foreach ($ace in $Entries) {
        if ($ace.AccessControlType -notin @('user','group')) { continue }
        if (-not $ace.EntityId) { continue }
        if ($ace.EntityId -ne $ObjectId) { continue }
        if (Perm-Ok -acePerm $ace.Permissions.ToString() -permType $PermType) { return $true }
    }
    return $false
}

# ---------------- Graph token + identity resolution ----------------
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

# Cache
$script:IdentityCache = @{}

function Resolve-IdentityObjectId {
    param([Parameter(Mandatory)][string]$IdentityName,[string]$GraphToken)

    if ($script:IdentityCache.ContainsKey($IdentityName)) { return $script:IdentityCache[$IdentityName] }

    $guidRef = [ref]([Guid]::Empty)

    # GUID: treat as objectId unless it matches an SP appId -> resolve to SP objectId
    if ([Guid]::TryParse($IdentityName, $guidRef)) {
        if ($GraphToken) {
            try {
                $spByAppIdUri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$IdentityName'&`$select=id,appId"
                $sp = Invoke-GraphGet -Token $GraphToken -Uri $spByAppIdUri
                if ($sp.value.Count -eq 1) {
                    $script:IdentityCache[$IdentityName] = $sp.value[0].id
                    return $sp.value[0].id
                }
            } catch {}
        }
        $script:IdentityCache[$IdentityName] = $IdentityName
        return $IdentityName
    }

    if (-not $GraphToken) {
        $script:IdentityCache[$IdentityName] = $null
        return $null
    }

    # exact service principal by displayName
    try {
        $safe = $IdentityName.Replace("'", "''")
        $spUri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=displayName eq '$safe'&`$select=id,displayName"
        $sp = Invoke-GraphGet -Token $GraphToken -Uri $spUri
        if ($sp.value.Count -eq 1) {
            $script:IdentityCache[$IdentityName] = $sp.value[0].id
            return $sp.value[0].id
        }
    } catch {}

    # exact group by displayName
    try {
        $safe = $IdentityName.Replace("'", "''")
        $gUri = "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$safe'&`$select=id,displayName"
        $g = Invoke-GraphGet -Token $GraphToken -Uri $gUri
        if ($g.value.Count -eq 1) {
            $script:IdentityCache[$IdentityName] = $g.value[0].id
            return $g.value[0].id
        }
    } catch {}

    $script:IdentityCache[$IdentityName] = $null
    return $null
}

# ---------------- Start ----------------
Ensure-Dir -Path $OutputDir | Out-Null

# Normalize adh_sub_group EXACTLY like your RG code
$adh_sub_group = $adh_sub_group.Trim()
if ([string]::IsNullOrWhiteSpace($adh_sub_group)) { $adh_sub_group = "" }
Write-Host "Normalized adh_sub_group = '$adh_sub_group'"

if (-not (Test-Path -LiteralPath $InputCsvPath)) { throw "Input CSV not found: $InputCsvPath" }

Write-Host "DEBUG: TenantId      = $TenantId"
Write-Host "DEBUG: ClientId      = $ClientId"
Write-Host "DEBUG: adh_group     = $adh_group"
Write-Host "DEBUG: adh_sub_group = '$adh_sub_group'"
Write-Host "DEBUG: subscription  = $adh_subscription_type"
Write-Host "DEBUG: InputCsvPath  = $InputCsvPath"
Write-Host "DEBUG: OutputDir     = $OutputDir"
Write-Host "DEBUG: BranchName    = $BranchName"

# Connect to Azure (use your Common.psm1 function)
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure connection failed."
}

# Build EXACT custodian (like your RG script)
$Custodian = if ($adh_sub_group -eq "") { $adh_group } else { "${adh_group}_${adh_sub_group}" }
Write-Host "Scanning ONLY custodian: $Custodian"

# Custodian placeholders for naming
$BaseCustodian = $adh_group
$BaseCustLower = $adh_group.ToLower() -replace '_',''
$CustIdentity  = $Custodian

# Graph token
$graphToken = $null
try {
    $graphToken = Get-GraphToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
    Write-Host "Graph token acquired." -ForegroundColor Green
} catch {
    Write-Warning "Graph token NOT acquired; identity name resolution may fail. Error: $($_.Exception.Message)"
}

# Load CSV
$rows = Import-Csv -LiteralPath $InputCsvPath
Write-Host ("DEBUG: CSV rows loaded: {0}" -f $rows.Count)

# =============================================================
# SUBSCRIPTIONS (FIXED): Resolve-ScSubscriptions + prefix gate
# =============================================================
$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
if ($subs -isnot [System.Collections.IEnumerable]) { $subs = ,$subs }

# Enforce your “env prefix in subscription name”
$envPrefixRegex = if ($adh_subscription_type -eq 'prd') { '^prd_' } else { '^dev_' }

$subs = $subs | Where-Object {
    $_.Name -match $envPrefixRegex -and $_.Name -match [regex]::Escape($adh_group)
}

if (-not $subs -or $subs.Count -eq 0) {
    throw "No subscriptions matched BOTH env prefix ($envPrefixRegex) and adh_group ($adh_group)."
}

Write-Host "DEBUG: Subscriptions selected = $($subs.Name -join ', ')" -ForegroundColor Cyan

$out = @()

foreach ($sub in $subs) {

    Set-ScContext -Subscription $sub
    Write-Host ""
    Write-Host "=== Subscription: $($sub.Name) ===" -ForegroundColor Cyan

    foreach ($r in $rows) {

        # Placeholder substitution
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
        }

        # AccessPath
        $accessPath = ($r.AccessPath -replace '<Custodian>', $BaseCustodian)
        $accessPath = ($accessPath -replace '<Cust>', $BaseCustLower).Trim()

        # Optional /catalog rewrite
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

        # ACL validation per identity (folder + parents + root)
        $permType = $r.PermissionType
        $pathsToCheck = Get-PathsToCheck -NormalizedPath $normalizedPath

        foreach ($iden in $identities) {

            $objectId = Resolve-IdentityObjectId -IdentityName $iden -GraphToken $graphToken

            if (-not $objectId) {
                $out += [pscustomobject]@{
                    SubscriptionName=$sub.Name; ResourceGroup=$rgName; Storage=$saName; Container=$cont; Folder=$folderForReport
                    Identity=$iden; Permission=$permType
                    Status='UNRESOLVED_IDENTITY'
                    Notes="Cannot resolve '$iden' to objectId via Graph. Use GUID objectId/appId or ensure Graph consent."
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
                    $notes  = "ACL satisfied (matched at '$matchedAt')"
                } else {
                    $status = 'MISSING'
                    $notes  = "No matching ACL entry found on folder, parents, or container root"
                }
            } catch {
                $status = 'ERROR'
                $notes  = "ACL read error: $($_.Exception.Message)"
            }

            $out += [pscustomobject]@{
                SubscriptionName=$sub.Name; ResourceGroup=$rgName; Storage=$saName; Container=$cont; Folder=$folderForReport
                Identity=$iden; Permission=$permType; Status=$status; Notes=$notes
            }
        }
    }
}

if (-not $out -or $out.Count -eq 0) {
    $out += [pscustomobject]@{
        SubscriptionName=''; ResourceGroup=''; Storage=''; Container=''; Folder=''
        Identity=''; Permission=''; Status='NO_RESULTS'; Notes='Nothing matched in scan'
    }
}

# Output file naming same pattern as your scripts
$groupForFile = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) { $adh_group } else { "${adh_group}_${adh_sub_group}" }
$stamp  = Get-Date -Format 'yyyyMMdd'
$csvOut = Join-Path $OutputDir ("adls_acl_{0}_{1}_{2}.csv" -f $groupForFile, $adh_subscription_type, $stamp)

Write-CsvSafe -Rows $out -Path $csvOut
Write-Host "ADLS validation completed." -ForegroundColor Green
Write-Host "CSV : $csvOut"
exit 0
