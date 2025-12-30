# =====================================================================
# Scan-ADLS-Acls.ps1  (FIXED)
# ADLS Gen2 ACL validator
# - Works in ADO (BranchName supported)
# - Identity resolution via Microsoft Graph (app permissions)
# - Checks ACL on folder + parents + container root
# - Never produces empty CSV: writes ERROR rows instead of silent continue
# =====================================================================

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$ClientId,
    [Parameter(Mandatory)][string]$ClientSecret,

    [Parameter(Mandatory)][string]$adh_group,
    [string]$adh_sub_group = '',

    [ValidateSet('nonprd','prd')]
    [string]$adh_subscription_type = 'nonprd',

    [Parameter(Mandatory)][string]$InputCsvPath,
    [Parameter(Mandatory)][string]$OutputDir,

    # Pipeline passes it; not required for logic
    [string]$BranchName = '',

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
    $Rows | Export-Csv -NoTypeInformation -Encoding UTF8 -Force -Path $Path
}

function Connect-Azure {
    $sec  = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
    $cred = New-Object pscredential($ClientId,$sec)
    Connect-AzAccount -ServicePrincipal -Tenant $TenantId -Credential $cred -ErrorAction Stop | Out-Null
}

function Get-GraphToken {
    $body = @{
        client_id     = $ClientId
        client_secret = $ClientSecret
        grant_type    = 'client_credentials'
        scope         = 'https://graph.microsoft.com/.default'
    }
    (Invoke-RestMethod -Method Post `
        -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
        -Body $body `
        -ContentType 'application/x-www-form-urlencoded').access_token
}

function Graph-Get([string]$Uri) {
    Invoke-RestMethod -Method Get -Uri $Uri -Headers @{ Authorization = "Bearer $script:GraphToken" }
}

function Resolve-IdentityObjectId {
    param([Parameter(Mandatory)][string]$Name)

    # Cache
    if ($script:IdentityCache.ContainsKey($Name)) { return $script:IdentityCache[$Name] }

    # GUID provided: use directly (objectId or appId; we try appId->sp objectId)
    $g=[ref]([guid]::Empty)
    if ([guid]::TryParse($Name,$g)) {
        # Try map GUID as appId to servicePrincipal id
        if ($script:GraphToken) {
            try {
                $u="https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$Name'&`$select=id,appId"
                $r=Graph-Get $u
                if ($r.value.Count -eq 1) {
                    $script:IdentityCache[$Name] = $r.value[0].id
                    return $r.value[0].id
                }
            } catch {}
        }
        $script:IdentityCache[$Name] = $Name
        return $Name
    }

    if (-not $script:GraphToken) {
        $script:IdentityCache[$Name] = $null
        return $null
    }

    # Exact displayName match: SP
    try {
        $u="https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=displayName eq '$Name'&`$select=id,displayName"
        $r=Graph-Get $u
        if ($r.value.Count -eq 1) { $script:IdentityCache[$Name]=$r.value[0].id; return $r.value[0].id }
    } catch {}

    # Exact displayName match: Group
    try {
        $u="https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$Name'&`$select=id,displayName"
        $r=Graph-Get $u
        if ($r.value.Count -eq 1) { $script:IdentityCache[$Name]=$r.value[0].id; return $r.value[0].id }
    } catch {}

    $script:IdentityCache[$Name] = $null
    return $null
}

function Perm-Ok([string]$acePerm,[string]$want) {
    switch ($want) {
        'r-x' { return ($acePerm -eq 'r-x' -or $acePerm -eq 'rwx') }
        'rwx' { return ($acePerm -eq 'rwx') }
        'r--' { return ($acePerm.Length -ge 1 -and $acePerm[0] -eq 'r') }
        default { return ($acePerm -eq $want) }
    }
}

function Get-PathsToCheck([string]$NormalizedPath) {
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

function Read-AclEntries([string]$FileSystem,$Context,[string]$Path) {
    $p = @{ FileSystem = $FileSystem; Context = $Context; ErrorAction = 'Stop' }
    if ($Path -and $Path.Trim() -ne '') { $p['Path'] = $Path }
    $item = Get-AzDataLakeGen2Item @p
    $entries = @()
    if ($item.Acl)        { $entries += $item.Acl }
    if ($item.DefaultAcl) { $entries += $item.DefaultAcl }
    return $entries
}

function Has-MatchingAce([object[]]$Entries,[string]$ObjectId,[string]$PermType) {
    foreach ($ace in $Entries) {
        if ($ace.AccessControlType -notin @('user','group')) { continue }
        if (-not $ace.EntityId) { continue }
        if ($ace.EntityId -ne $ObjectId) { continue }
        if (Perm-Ok -acePerm $ace.Permissions.ToString() -want $PermType) { return $true }
    }
    return $false
}

# ---------------- Start ----------------
Write-Host "DEBUG: BranchName = $BranchName"
Ensure-Dir -Path $OutputDir
if (-not (Test-Path -LiteralPath $InputCsvPath)) { throw "Input CSV not found: $InputCsvPath" }

# Normalize
if ($null -ne $adh_sub_group) { $adh_sub_group = $adh_sub_group.Trim() }
if ([string]::IsNullOrWhiteSpace($adh_sub_group)) { $adh_sub_group = '' }

$BaseCustodian = $adh_group
$BaseCustLower = $adh_group.ToLower() -replace '_',''
$CustIdentity  = if ($adh_sub_group) { "${adh_group}_${adh_sub_group}" } else { $adh_group }

# Login
Connect-Azure
$script:GraphToken = $null
try {
    $script:GraphToken = Get-GraphToken
    Write-Host "Graph token acquired." -ForegroundColor Green
} catch {
    Write-Warning "Graph token failed. Identity resolution will fail unless CSV uses GUIDs. $($_.Exception.Message)"
}
$script:IdentityCache = @{}

# Load rows
$rows = Import-Csv -LiteralPath $InputCsvPath
$out  = @()

# Subscriptions (use what SPN can see)
$subs = Get-AzSubscription -ErrorAction Stop

foreach ($sub in $subs) {
    Set-AzContext -SubscriptionId $sub.Id -ErrorAction Stop | Out-Null

    foreach ($r in $rows) {

        # placeholders
        $rgName = ($r.ResourceGroupName -replace '<Custodian>', $BaseCustodian).Trim()

        $saName = ($r.StorageAccountName -replace '<Custodian>', $BaseCustodian)
        $saName = ($saName -replace '<Cust>', $BaseCustLower).Trim()

        $cont   = ($r.ContainerName -replace '<Custodian>', $BaseCustodian)
        $cont   = ($cont -replace '<Cust>', $BaseCustLower).Trim()

        # env filter
        if ($adh_subscription_type -eq 'prd') {
            if ($saName -match 'adlsnonprd$') { continue }
        } else {
            if ($saName -match 'adlsprd$') { continue }
        }

        # access path
        $accessPath = ($r.AccessPath -replace '<Custodian>', $BaseCustodian)
        $accessPath = ($accessPath -replace '<Cust>', $BaseCustLower).Trim()

        if ($accessPath -like '/catalog*') {
            $suffix = $accessPath.Substring('/catalog'.Length)
            $gl = $adh_group.ToLower()
            if ($adh_sub_group) { $accessPath = "/adh_${gl}_$($adh_sub_group.ToLower())${suffix}" }
            else                { $accessPath = "/adh_${gl}${suffix}" }
        }

        $normalizedPath = $accessPath
        if ($normalizedPath -eq '/') { $normalizedPath = '' }
        $folderForReport = if ($normalizedPath) { $normalizedPath } else { '/' }

        $permType = $r.PermissionType

        # identities (comma-separated supported)
        $identities = @()
        if ($r.Identity) {
            $identities = $r.Identity.Split(',') |
                ForEach-Object { ($_ -replace '<Custodian>', $CustIdentity).Trim() } |
                Where-Object { $_ }
        }

        if (-not $identities -or $identities.Count -eq 0) {
            $out += [pscustomobject]@{
                SubscriptionName=$sub.Name; ResourceGroup=$rgName; Storage=$saName; Container=$cont; Folder=$folderForReport
                Identity=''; Permission=$permType; Status='ERROR'; Notes='Identity column empty'
            }
            continue
        }

        # Resolve storage + container (FIXED PARAMS HERE)
        $ctx = $null
        try {
            $saObj = Get-AzStorageAccount -ResourceGroupName $rgName -Name $saName -ErrorAction Stop
            $ctx   = $saObj.Context
        } catch {
            foreach ($iden in $identities) {
                $out += [pscustomobject]@{
                    SubscriptionName=$sub.Name; ResourceGroup=$rgName; Storage=$saName; Container=$cont; Folder=$folderForReport
                    Identity=$iden; Permission=$permType; Status='ERROR'
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
                    Identity=$iden; Permission=$permType; Status='ERROR'
                    Notes="Container error: $($_.Exception.Message)"
                }
            }
            continue
        }

        # Validate ACLs
        $pathsToCheck = Get-PathsToCheck -NormalizedPath $normalizedPath

        foreach ($iden in $identities) {

            $objectId = Resolve-IdentityObjectId -Name $iden
            if (-not $objectId) {
                $out += [pscustomobject]@{
                    SubscriptionName=$sub.Name; ResourceGroup=$rgName; Storage=$saName; Container=$cont; Folder=$folderForReport
                    Identity=$iden; Permission=$permType
                    Status='UNRESOLVED_IDENTITY'
                    Notes="Cannot resolve '$iden' to objectId. If Graph token failed, use GUID objectId/appId in CSV."
                }
                continue
            }

            $matchedAt = $null
            try {
                foreach ($p in $pathsToCheck) {
                    $entries = Read-AclEntries -FileSystem $cont -Context $ctx -Path $p

                    if ($DebugAcls) {
                        $disp = if ($p) { "/$p" } else { "/" }
                        Write-Host "DEBUG ACLs for '$disp':" -ForegroundColor DarkGray
                        foreach ($ace in $entries) {
                            Write-Host ("ACE => Type={0} EntityId={1} Perm={2}" -f $ace.AccessControlType, $ace.EntityId, $ace.Permissions) -ForegroundColor DarkGray
                        }
                    }

                    if (Has-MatchingAce -Entries $entries -ObjectId $objectId -PermType $permType) {
                        $matchedAt = if ($p) { "/$p" } else { "/" }
                        break
                    }
                }

                if ($matchedAt) {
                    $status='OK'; $notes="ACL satisfied (matched at '$matchedAt')"
                } else {
                    $status='MISSING'; $notes="No matching ACL entry found on folder, parents, or container root"
                }
            } catch {
                $status='ERROR'; $notes="ACL read error: $($_.Exception.Message)"
            }

            $out += [pscustomobject]@{
                SubscriptionName=$sub.Name; ResourceGroup=$rgName; Storage=$saName; Container=$cont; Folder=$folderForReport
                Identity=$iden; Permission=$permType; Status=$status; Notes=$notes
            }
        }
    }
}

# Safety: never empty
if (-not $out -or $out.Count -eq 0) {
    $out += [pscustomobject]@{
        SubscriptionName=''; ResourceGroup=''; Storage=''; Container=''; Folder=''
        Identity=''; Permission=''; Status='NO_RESULTS'; Notes='Nothing scanned (no subs/rows matched).'
    }
}

$stamp  = Get-Date -Format 'yyyyMMdd'
$groupForFile = if ($adh_sub_group) { "${adh_group}-${adh_sub_group}" } else { $adh_group }
$csvOut = Join-Path $OutputDir ("adls_acl_{0}_{1}_{2}.csv" -f $groupForFile, $adh_subscription_type, $stamp)

Write-CsvSafe -Rows $out -Path $csvOut
Write-Host "ADLS validation completed." -ForegroundColor Green
Write-Host "CSV : $csvOut"
exit 0
