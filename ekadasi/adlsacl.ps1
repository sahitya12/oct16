# Scan-ADLS-Acls.ps1 (fixed)
# Fixes:
# 1) Detect missing Entra read and mark identities as UNRESOLVED_IDENTITY instead of ERROR
# 2) Identity resolution uses DisplayName first (like your apply script), then SearchString fallback
# 3) Supports comma-separated identities in CSV cell
# 4) Still checks folder + parents + container root ACLs

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

function Resolve-Subscriptions {
    param([string]$adh_group,[ValidateSet('nonprd','prd')]$adh_subscription_type)

    $all = Get-AzSubscription -ErrorAction Stop
    $byGroup = $all | Where-Object { $_.Name -match [regex]::Escape($adh_group) }
    $subs = if ($byGroup) { $byGroup } else { $all }

    if ($adh_subscription_type -eq 'prd') {
        $envFiltered = $subs | Where-Object { $_.Name -match '(?i)\b(prd|prod|production)\b' }
    } else {
        $envFiltered = $subs | Where-Object { $_.Name -match '(?i)\b(nonprd|non-prd|dev|tst|test|qa|uat)\b' }
    }

    if ($envFiltered) { return $envFiltered }
    return $subs
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

# ---------------- Normalize adh_sub_group ----------------
if ($null -ne $adh_sub_group) { $adh_sub_group = $adh_sub_group.Trim() }
if ([string]::IsNullOrWhiteSpace($adh_sub_group)) { $adh_sub_group = '' }

Ensure-Dir -Path $OutputDir | Out-Null
if (-not (Test-Path -LiteralPath $InputCsvPath)) { throw "Input CSV not found: $InputCsvPath" }

# ---------------- Connect ----------------
Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
Write-Host "Authenticated to Azure." -ForegroundColor Green

# ---------------- Entra read precheck ----------------
$script:CanResolveEntra = $false
try {
    Get-AzADServicePrincipal -First 1 -ErrorAction Stop | Out-Null
    $script:CanResolveEntra = $true
    Write-Host "Entra read check: OK (can query service principals/groups)" -ForegroundColor Green
} catch {
    Write-Warning "Entra read check: FAILED. Your SPN cannot query Entra objects (missing Directory Readers / Graph read)."
    Write-Warning "Result: identities in CSV that are NAMES will be marked UNRESOLVED_IDENTITY. Use GUIDs or assign Directory Readers."
}

# ---------------- Custodian helpers ----------------
$BaseCustodian = $adh_group
$BaseCustLower = $adh_group.ToLower() -replace '_',''
$CustIdentity  = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) { $adh_group } else { "${adh_group}_${adh_sub_group}" }

# ---------------- Identity cache + resolver ----------------
$script:IdentityCache = @{}

function Resolve-IdentityObjectId {
    param([Parameter(Mandatory)][string]$IdentityName)

    if ($script:IdentityCache.ContainsKey($IdentityName)) { return $script:IdentityCache[$IdentityName] }

    # If we cannot query Entra, only accept GUIDs (objectId)
    if (-not $script:CanResolveEntra) {
        $guidRef = [ref]([Guid]::Empty)
        if ([Guid]::TryParse($IdentityName, $guidRef)) {
            $script:IdentityCache[$IdentityName] = $IdentityName
            return $IdentityName
        }
        $script:IdentityCache[$IdentityName] = $null
        return $null
    }

    $id = $null
    $guidRef = [ref]([Guid]::Empty)

    # GUID path: could be SP ObjectId OR AppId
    if ([Guid]::TryParse($IdentityName, $guidRef)) {
        try {
            $spObj = Get-AzADServicePrincipal -ObjectId $IdentityName -ErrorAction Stop
            if ($spObj?.Id) { $id = $spObj.Id }
        } catch { }

        if (-not $id) {
            try {
                $spApp = Get-AzADServicePrincipal -ApplicationId $IdentityName -ErrorAction Stop
                if ($spApp?.Id) { $id = $spApp.Id }
            } catch { }
        }

        if ($id) {
            $script:IdentityCache[$IdentityName] = $id
            return $id
        }

        # fallback: treat as object id
        $script:IdentityCache[$IdentityName] = $IdentityName
        return $IdentityName
    }

    # Name-based resolution (like your APPLY script): DisplayName first, then SearchString fallback
    $matches = @()

    try { $matches += Get-AzADGroup -DisplayName $IdentityName -ErrorAction SilentlyContinue } catch { }
    try { $matches += Get-AzADServicePrincipal -DisplayName $IdentityName -ErrorAction SilentlyContinue } catch { }

    if (-not $matches -or $matches.Count -eq 0) {
        try { $matches += Get-AzADGroup -SearchString $IdentityName -ErrorAction SilentlyContinue } catch { }
        try { $matches += Get-AzADServicePrincipal -SearchString $IdentityName -ErrorAction SilentlyContinue } catch { }
    }

    $matches = $matches | Sort-Object DisplayName -Unique

    if ($matches.Count -eq 1) {
        $id = $matches[0].Id
    } elseif ($matches.Count -gt 1) {
        Write-Warning "Identity '$IdentityName' ambiguous: $($matches.DisplayName -join ', ')"
    }

    $script:IdentityCache[$IdentityName] = $id
    return $id
}

# ---------------- Load CSV ----------------
$rows = Import-Csv -LiteralPath $InputCsvPath
Write-Host ("CSV rows loaded: {0}" -f $rows.Count)

# ---------------- Subscriptions ----------------
$subs = Resolve-Subscriptions -adh_group $adh_group -adh_subscription_type $adh_subscription_type
if (-not $subs -or $subs.Count -eq 0) { throw "No subscriptions found/accessible for this SPN." }

$out = @()

foreach ($sub in $subs) {
    Set-ScContext -Subscription $sub
    Write-Host ""
    Write-Host "=== Subscription: $($sub.Name) ===" -ForegroundColor Cyan

    foreach ($r in $rows) {

        $rgName = ($r.ResourceGroupName -replace '<Custodian>', $BaseCustodian).Trim()

        $saName = ($r.StorageAccountName -replace '<Custodian>', $BaseCustodian)
        $saName = ($saName -replace '<Cust>', $BaseCustLower).Trim()

        $cont = ($r.ContainerName -replace '<Custodian>', $BaseCustodian)
        $cont = ($cont -replace '<Cust>', $BaseCustLower).Trim()

        # NOTE: support multiple identities separated by comma (like your APPLY script)
        $identities = @()
        if ($r.Identity) {
            $identities = $r.Identity.Split(',') | ForEach-Object { ($_ -replace '<Custodian>', $CustIdentity).Trim() } | Where-Object { $_ }
        }

        if ($adh_subscription_type -eq 'prd') {
            if ($saName -match 'adlsnonprd$') { continue }
        } else {
            if ($saName -match 'adlsprd$') { continue }
        }

        $accessPath = ($r.AccessPath -replace '<Custodian>', $BaseCustodian)
        $accessPath = ($accessPath -replace '<Cust>', $BaseCustLower).Trim()

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

        # Resolve storage
        try {
            $sa  = Get-AzStorageAccount -ResourceGroupName $rgName -Name $saName -ErrorAction Stop
            $ctx = $sa.Context
        } catch {
            foreach ($iden in $identities) {
                $out += [pscustomobject]@{
                    SubscriptionName = $sub.Name; ResourceGroup = $rgName; Storage = $saName; Container = $cont
                    Folder = $folderForReport; Identity = $iden; Permission = $r.PermissionType
                    Status = 'ERROR'; Notes = "Storage account error: $($_.Exception.Message)"
                }
            }
            continue
        }

        # container exists
        try {
            $null = Get-AzStorageContainer -Name $cont -Context $ctx -ErrorAction Stop
        } catch {
            foreach ($iden in $identities) {
                $out += [pscustomobject]@{
                    SubscriptionName = $sub.Name; ResourceGroup = $rgName; Storage = $saName; Container = $cont
                    Folder = $folderForReport; Identity = $iden; Permission = $r.PermissionType
                    Status = 'ERROR'; Notes = "Container fetch error: $($_.Exception.Message)"
                }
            }
            continue
        }

        $permType = $r.PermissionType
        $pathsToCheck = Get-PathsToCheck -NormalizedPath $normalizedPath

        foreach ($iden in $identities) {

            $objectId = Resolve-IdentityObjectId -IdentityName $iden
            if (-not $objectId) {
                $out += [pscustomobject]@{
                    SubscriptionName = $sub.Name; ResourceGroup = $rgName; Storage = $saName; Container = $cont
                    Folder = $folderForReport; Identity = $iden; Permission = $permType
                    Status = 'UNRESOLVED_IDENTITY'
                    Notes  = "Cannot resolve '$iden' (missing Directory Readers/Graph read OR not a GUID)."
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
            } catch {
                $status = 'ERROR'
                $notes  = "ACL read error: $($_.Exception.Message)"
            }

            $out += [pscustomobject]@{
                SubscriptionName = $sub.Name; ResourceGroup = $rgName; Storage = $saName; Container = $cont
                Folder = $folderForReport; Identity = $iden; Permission = $permType
                Status = $status; Notes = $notes
            }
        }
    }
}

if (-not $out -or $out.Count -eq 0) {
    $out += [pscustomobject]@{ SubscriptionName=''; ResourceGroup=''; Storage=''; Container=''; Folder=''; Identity=''; Permission=''; Status='NO_RESULTS'; Notes='Nothing matched in scan' }
}

$groupForFile = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) { $adh_group } else { "${adh_group}-${adh_sub_group}" }
$stamp  = Get-Date -Format 'yyyyMMdd'
$csvOut = Join-Path $OutputDir ("adls_acl_{0}_{1}_{2}.csv" -f $groupForFile, $adh_subscription_type, $stamp)

Write-CsvSafe -Rows $out -Path $csvOut
Write-Host "ADLS validation completed." -ForegroundColor Green
Write-Host "CSV : $csvOut"
exit 0
