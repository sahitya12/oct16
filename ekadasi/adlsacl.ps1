# Scan-ADLS-Acls.ps1
# ADLS Gen2 ACL validator (WORKING + robust)
# Fixes:
#  - Works even when root ACL read needs Path "/"
#  - Resolves identities reliably via Microsoft Graph (no Directory Readers role needed)
#  - Accepts Identity as: DisplayName OR ObjectId GUID OR AppId(ClientId) GUID
#  - Supports comma-separated identities in CSV
#  - Checks: folder -> parents -> container root
#  - Optional: restrict subscriptions via -SubscriptionIds (recommended)

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

    # OPTIONAL: Comma-separated subscription IDs to scan (best way to avoid “first subscription selected” issues)
    [string]$SubscriptionIds = '',

    # OPTIONAL: kept for pipeline compatibility; not required for logic
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

function Perm-Ok {
    param([string]$acePerm, [string]$permType)
    switch ($permType) {
        'r-x' { return ($acePerm -eq 'r-x' -or $acePerm -eq 'rwx') }
        'rwx' { return ($acePerm -eq 'rwx') }
        'r--' { return ($acePerm.Length -ge 1 -and $acePerm[0] -eq 'r') }
        default { return ($acePerm -eq $permType) }
    }
}

function Normalize-PathForGen2([string]$p) {
    if ([string]::IsNullOrWhiteSpace($p) -or $p -eq '/') { return '' }
    $p = $p.Trim()
    $p = $p -replace '\\','/'         # backslash -> slash
    $p = $p.TrimStart('/')            # Gen2 expects no leading /
    $p = $p -replace '//+','/'        # collapse //
    return $p
}

function Get-PathsToCheck {
    param([string]$NormalizedPath) # '' => root
    if ([string]::IsNullOrWhiteSpace($NormalizedPath)) { return @('') }

    $p = Normalize-PathForGen2 $NormalizedPath
    if ($p -eq '') { return @('') }

    $parts = $p.Split('/', [System.StringSplitOptions]::RemoveEmptyEntries)
    $paths = New-Object System.Collections.Generic.List[string]

    for ($i = $parts.Length; $i -ge 1; $i--) {
        $paths.Add( ($parts[0..($i-1)] -join '/') )
    }
    $paths.Add('')  # root last
    return $paths.ToArray()
}

# ---------------- Microsoft Graph token + GET ----------------
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

function Escape-OData([string]$s) {
    # OData string literal escape: single quote doubled
    return $s.Replace("'", "''")
}

# ---------------- Identity resolver ----------------
$script:IdentityCache = @{}
$script:GraphToken = $null

function Resolve-IdentityObjectId {
    param([Parameter(Mandatory)][string]$Identity)

    $Identity = $Identity.Trim()
    if ([string]::IsNullOrWhiteSpace($Identity)) { return $null }

    if ($script:IdentityCache.ContainsKey($Identity)) { return $script:IdentityCache[$Identity] }

    $guidRef = [ref]([Guid]::Empty)

    # If GUID provided: could be ObjectId OR AppId.
    if ([Guid]::TryParse($Identity, $guidRef)) {

        # 1) If Graph available, try treat GUID as appId -> get SP objectId
        if ($script:GraphToken) {
            try {
                $uri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$Identity'&`$select=id,appId"
                $sp = Invoke-GraphGet -Token $script:GraphToken -Uri $uri
                if ($sp.value.Count -eq 1) {
                    $script:IdentityCache[$Identity] = $sp.value[0].id
                    return $sp.value[0].id
                }
            } catch { }
        }

        # 2) Otherwise assume it is already objectId (this matches ADLS EntityId format)
        $script:IdentityCache[$Identity] = $Identity
        return $Identity
    }

    # Name resolution via Graph (preferred)
    if ($script:GraphToken) {

        # Exact displayName match - Service Principals
        try {
            $nameEsc = Escape-OData $Identity
            $uri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=displayName eq '$nameEsc'&`$select=id,displayName"
            $sp = Invoke-GraphGet -Token $script:GraphToken -Uri $uri
            if ($sp.value.Count -eq 1) {
                $script:IdentityCache[$Identity] = $sp.value[0].id
                return $sp.value[0].id
            }
        } catch { }

        # Exact displayName match - Groups
        try {
            $nameEsc = Escape-OData $Identity
            $uri = "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$nameEsc'&`$select=id,displayName"
            $g = Invoke-GraphGet -Token $script:GraphToken -Uri $uri
            if ($g.value.Count -eq 1) {
                $script:IdentityCache[$Identity] = $g.value[0].id
                return $g.value[0].id
            }
        } catch { }

        # Fallback: startswith (works without $search headers/consistencyLevel)
        try {
            $nameEsc = Escape-OData $Identity
            $uri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=startsWith(displayName,'$nameEsc')&`$select=id,displayName"
            $sp2 = Invoke-GraphGet -Token $script:GraphToken -Uri $uri
            if ($sp2.value.Count -eq 1) {
                $script:IdentityCache[$Identity] = $sp2.value[0].id
                return $sp2.value[0].id
            }
        } catch { }

        try {
            $nameEsc = Escape-OData $Identity
            $uri = "https://graph.microsoft.com/v1.0/groups?`$filter=startsWith(displayName,'$nameEsc')&`$select=id,displayName"
            $g2 = Invoke-GraphGet -Token $script:GraphToken -Uri $uri
            if ($g2.value.Count -eq 1) {
                $script:IdentityCache[$Identity] = $g2.value[0].id
                return $g2.value[0].id
            }
        } catch { }
    }

    # Fallback to AzAD (may fail if Entra read is blocked in your tenant)
    $matches = @()
    try { $matches += Get-AzADServicePrincipal -SearchString $Identity -ErrorAction SilentlyContinue } catch { }
    try { $matches += Get-AzADGroup -SearchString $Identity -ErrorAction SilentlyContinue } catch { }

    $matches = $matches | Sort-Object DisplayName -Unique
    if ($matches.Count -eq 1) {
        $script:IdentityCache[$Identity] = $matches[0].Id
        return $matches[0].Id
    }

    $script:IdentityCache[$Identity] = $null
    return $null
}

# ---------------- ACL reader (ROOT FIX) ----------------
function Read-AclEntries {
    param(
        [Parameter(Mandatory)][string]$FileSystem,
        [Parameter(Mandatory)]$Context,
        [string]$Path
    )

    $entries = @()

    # IMPORTANT:
    # Root ACL retrieval is inconsistent across Az.Storage versions.
    # We try both: -Path '/' and “no -Path”, and also ''.
    $pathNorm = Normalize-PathForGen2 $Path

    $tryList = @()
    if ($pathNorm -eq '') {
        $tryList += '/'   # explicit root
        $tryList += ''    # empty path
        $tryList += $null # no Path parameter
    } else {
        $tryList += $pathNorm
    }

    $lastErr = $null

    foreach ($pTry in $tryList) {
        try {
            $params = @{ FileSystem = $FileSystem; Context = $Context; ErrorAction = 'Stop' }
            if ($null -ne $pTry) { $params['Path'] = $pTry }

            $item = Get-AzDataLakeGen2Item @params

            if ($item.Acl)        { $entries += $item.Acl }
            if ($item.DefaultAcl) { $entries += $item.DefaultAcl }

            return $entries
        } catch {
            $lastErr = $_
            continue
        }
    }

    throw $lastErr
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
        if (Perm-Ok -acePerm $ace.Permissions.ToString() -permType $PermType) { return $true }
    }
    return $false
}

# ---------------- Normalize + validate inputs ----------------
if ($null -ne $adh_sub_group) { $adh_sub_group = $adh_sub_group.Trim() }
if ([string]::IsNullOrWhiteSpace($adh_sub_group)) { $adh_sub_group = '' }

Ensure-Dir -Path $OutputDir | Out-Null
if (-not (Test-Path -LiteralPath $InputCsvPath)) { throw "Input CSV not found: $InputCsvPath" }

Write-Host "DEBUG: BranchName          = $BranchName"
Write-Host "DEBUG: SubscriptionIds     = $SubscriptionIds"
Write-Host "DEBUG: TenantId            = $TenantId"
Write-Host "DEBUG: ClientId            = $ClientId"
Write-Host "DEBUG: adh_group           = $adh_group"
Write-Host "DEBUG: adh_sub_group       = '$adh_sub_group'"
Write-Host "DEBUG: adh_subscription_type = $adh_subscription_type"
Write-Host "DEBUG: InputCsvPath        = $InputCsvPath"
Write-Host "DEBUG: OutputDir           = $OutputDir"

# ---------------- Connect Azure ----------------
Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
Write-Host "Authenticated to Azure." -ForegroundColor Green

# ---------------- Graph token ----------------
try {
    $script:GraphToken = Get-GraphToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
    Write-Host "Graph token acquired." -ForegroundColor Green
} catch {
    Write-Warning "Graph token NOT acquired. Identity resolution by name may fail. Error: $($_.Exception.Message)"
    $script:GraphToken = $null
}

# ---------------- Custodian placeholder helpers ----------------
$BaseCustodian = $adh_group
$BaseCustLower = $adh_group.ToLower() -replace '_',''
$CustIdentity  = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) { $adh_group } else { "${adh_group}_${adh_sub_group}" }

# ---------------- Load CSV ----------------
$rows = Import-Csv -LiteralPath $InputCsvPath
Write-Host ("DEBUG: CSV rows loaded: {0}" -f $rows.Count)

# ---------------- Subscriptions ----------------
$subs = @()

if (-not [string]::IsNullOrWhiteSpace($SubscriptionIds)) {
    $wanted = $SubscriptionIds.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    $all = Get-AzSubscription -ErrorAction Stop
    $subs = $all | Where-Object { $wanted -contains $_.Id }
    if (-not $subs -or $subs.Count -eq 0) { throw "No matching subscriptions found for SubscriptionIds: $SubscriptionIds" }
} else {
    # Best-effort selection
    $all = Get-AzSubscription -ErrorAction Stop
    $byGroup = $all | Where-Object { $_.Name -match [regex]::Escape($adh_group) }
    $subs = if ($byGroup) { $byGroup } else { $all }

    if ($adh_subscription_type -eq 'prd') {
        $envFiltered = $subs | Where-Object { $_.Name -match '(?i)\b(prd|prod|production)\b' }
    } else {
        $envFiltered = $subs | Where-Object { $_.Name -match '(?i)\b(nonprd|non-prd|dev|tst|test|qa|uat)\b' }
    }
    if ($envFiltered) { $subs = $envFiltered }
}

Write-Host "DEBUG: Subscriptions selected = $($subs.Name -join ', ')"

# ---------------- Main ----------------
$out = @()

foreach ($sub in $subs) {
    Set-ScContext -Subscription $sub
    Write-Host ""
    Write-Host "=== Subscription: $($sub.Name) ($($sub.Id)) ===" -ForegroundColor Cyan

    foreach ($r in $rows) {

        # ---- placeholders ----
        $rgName = ($r.ResourceGroupName -replace '<Custodian>', $BaseCustodian).Trim()

        $saName = ($r.StorageAccountName -replace '<Custodian>', $BaseCustodian)
        $saName = ($saName -replace '<Cust>', $BaseCustLower).Trim()

        $cont  = ($r.ContainerName -replace '<Custodian>', $BaseCustodian)
        $cont  = ($cont -replace '<Cust>', $BaseCustLower).Trim()

        # Identity: allow comma-separated
        $identities = @()
        if ($r.Identity) {
            $identities = $r.Identity.Split(',') |
                ForEach-Object { ($_ -replace '<Custodian>', $CustIdentity).Trim() } |
                Where-Object { $_ }
        }

        # env filter (optional naming convention)
        if ($adh_subscription_type -eq 'prd') {
            if ($saName -match 'adlsnonprd$') { continue }
        } else {
            if ($saName -match 'adlsprd$') { continue }
        }

        # ---- AccessPath normalization + catalog rewrite ----
        $accessPath = ($r.AccessPath -replace '<Custodian>', $BaseCustodian)
        $accessPath = ($accessPath -replace '<Cust>', $BaseCustLower).Trim()

        if ($accessPath -like '/catalog*') {
            $suffix = $accessPath.Substring('/catalog'.Length)
            $gLower = $adh_group.ToLower()
            if ([string]::IsNullOrWhiteSpace($adh_sub_group)) {
                $accessPath = "/adh_${gLower}${suffix}"
            } else {
                $accessPath = "/adh_${gLower}_$($adh_sub_group.ToLower())${suffix}"
            }
        }

        $normalizedPath = $accessPath
        if ($normalizedPath -eq '/') { $normalizedPath = '' }
        $folderForReport = if ([string]::IsNullOrWhiteSpace($normalizedPath)) { '/' } else { $normalizedPath }

        # Validate basics
        if ([string]::IsNullOrWhiteSpace($rgName) -or [string]::IsNullOrWhiteSpace($saName) -or [string]::IsNullOrWhiteSpace($cont)) {
            foreach ($iden in ($identities | ForEach-Object { $_ } )) {
                $out += [pscustomobject]@{
                    SubscriptionName=$sub.Name; ResourceGroup=$rgName; Storage=$saName; Container=$cont; Folder=$folderForReport
                    Identity=$iden; Permission=$r.PermissionType; Status='ERROR'
                    Notes='Missing RG/Storage/Container after placeholder replacement.'
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

        $permType = $r.PermissionType
        $pathsToCheck = Get-PathsToCheck -NormalizedPath $normalizedPath

        foreach ($iden in $identities) {

            $objectId = Resolve-IdentityObjectId -Identity $iden

            if (-not $objectId) {
                $out += [pscustomobject]@{
                    SubscriptionName=$sub.Name; ResourceGroup=$rgName; Storage=$saName; Container=$cont; Folder=$folderForReport
                    Identity=$iden; Permission=$permType; Status='UNRESOLVED_IDENTITY'
                    Notes="Cannot resolve '$iden' to Entra objectId. Put GUID objectId/appId in CSV, or fix Graph app-permissions + admin consent."
                }
                continue
            }

            $matchedAt = $null
            try {
                foreach ($p in $pathsToCheck) {
                    $entries = Read-AclEntries -FileSystem $cont -Context $ctx -Path $p

                    if ($DebugAcls) {
                        $disp = if ([string]::IsNullOrWhiteSpace($p)) { "/" } else { "/$p" }
                        Write-Host "DEBUG ACLs for '$disp': entries=$($entries.Count)" -ForegroundColor DarkGray
                        foreach ($ace in $entries) {
                            Write-Host ("ACE => Type={0} EntityId={1} Perm={2}" -f $ace.AccessControlType, $ace.EntityId, $ace.Permissions) -ForegroundColor DarkGray
                        }
                    }

                    if (Has-MatchingAce -Entries $entries -ObjectId $objectId -PermType $permType) {
                        $matchedAt = if ([string]::IsNullOrWhiteSpace($p)) { "/" } else { "/$p" }
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
}

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
