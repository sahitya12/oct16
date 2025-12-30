# Scan-ADLS-Acls.ps1
# Standalone ADLS Gen2 ACL validator with:
# - Robust Entra ID identity resolution (name search + GUID AppId/ObjectId)
# - Parent-path ACL checking (folder + parents + container root)
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
    [string]$BranchName = '',

    [switch]$DebugAcls
)

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
        $sec = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential($ClientId, $sec)
        Connect-AzAccount -ServicePrincipal -Tenant $TenantId -Credential $cred -ErrorAction Stop | Out-Null
        return $true
    } catch {
        Write-Error "Connect-AzAccount failed: $($_.Exception.Message)"
        return $false
    }
}

function Resolve-Subscriptions {
    param(
        [string]$adh_group,
        [ValidateSet('nonprd','prd')]$adh_subscription_type
    )

    $all = Get-AzSubscription -ErrorAction Stop

    # Try to filter by group name (best-effort)
    $byGroup = $all | Where-Object { $_.Name -match [regex]::Escape($adh_group) }

    $subs = if ($byGroup) { $byGroup } else { $all }

    # Then try to filter by env (best-effort)
    if ($adh_subscription_type -eq 'prd') {
        $envFiltered = $subs | Where-Object { $_.Name -match '(?i)\b(prd|prod|production)\b' }
    } else {
        $envFiltered = $subs | Where-Object { $_.Name -match '(?i)\b(nonprd|non-prd|dev|tst|test|qa|uat)\b' }
    }

    if ($envFiltered) { return $envFiltered }
    return $subs
}

function Set-ScContext {
    param($Subscription)
    Set-AzContext -SubscriptionId $Subscription.Id -ErrorAction Stop | Out-Null
}

# ---------------- Modules ----------------
Import-Module Az.Accounts, Az.Resources, Az.Storage -ErrorAction Stop

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

# ---------------- Custodian helpers ----------------
$BaseCustodian = $adh_group
$BaseCustLower = $adh_group.ToLower() -replace '_',''

$CustIdentity = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) { $adh_group } else { "${adh_group}_${adh_sub_group}" }

Write-Host "DEBUG: BaseCustodian (RG/SA/Cont)  = $BaseCustodian"
Write-Host "DEBUG: <Cust> (lower, no _)        = $BaseCustLower"
Write-Host "DEBUG: CustIdentity (for Identity) = $CustIdentity"

# ---------------- Identity cache + resolver ----------------
$script:IdentityCache = @{}

function Resolve-IdentityObjectId {
    param([Parameter(Mandatory = $true)][string]$IdentityName)

    if ($script:IdentityCache.ContainsKey($IdentityName)) {
        return $script:IdentityCache[$IdentityName]
    }

    $id = $null
    $guidRef = [ref]([Guid]::Empty)

    # GUID path: could be SP ObjectId OR AppId (ClientId)
    if ([Guid]::TryParse($IdentityName, $guidRef)) {

        # Try as Service Principal ObjectId
        try {
            $spObj = Get-AzADServicePrincipal -ObjectId $IdentityName -ErrorAction Stop
            if ($spObj?.Id) { $id = $spObj.Id }
        } catch { }

        # Try as ApplicationId (ClientId)
        if (-not $id) {
            try {
                $spApp = Get-AzADServicePrincipal -ApplicationId $IdentityName -ErrorAction Stop
                if ($spApp?.Id) { $id = $spApp.Id }
            } catch { }
        }

        if ($id) {
            Write-Host "DEBUG: Identity GUID '$IdentityName' resolved to SP objectId '$id'" -ForegroundColor DarkCyan
            $script:IdentityCache[$IdentityName] = $id
            return $id
        }

        # If we can't query Entra, fall back (still allows ACL checks if caller gave objectId)
        Write-Warning "GUID '$IdentityName' could not be resolved as SP objectId or AppId (maybe missing Entra read perms). Using as-is."
        $script:IdentityCache[$IdentityName] = $IdentityName
        return $IdentityName
    }

    # Name-based search (robust: use SearchString for BOTH group and SP)
    $matches = @()

    try { $matches += Get-AzADGroup -SearchString $IdentityName -ErrorAction SilentlyContinue } catch { }
    try { $matches += Get-AzADServicePrincipal -SearchString $IdentityName -ErrorAction SilentlyContinue } catch { }

    $matches = $matches | Sort-Object DisplayName -Unique

    if ($matches.Count -eq 1) {
        $id = $matches[0].Id
    }
    elseif ($matches.Count -gt 1) {
        Write-Warning "Identity '$IdentityName' ambiguous in Entra ID: $($matches.DisplayName -join ', ')"
    }

    Write-Host "DEBUG: Identity '$IdentityName' resolved to objectId '$id'" -ForegroundColor DarkCyan
    $script:IdentityCache[$IdentityName] = $id
    return $id
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

    $p = $NormalizedPath.Trim()
    $p = $p.TrimStart('/')
    $p = $p -replace '//+','/'

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
        if (Perm-Ok -acePerm $acePerm -permType $PermType) {
            return $true
        }
    }
    return $false
}

# ---------------- Load CSV ----------------
$rows = Import-Csv -LiteralPath $InputCsvPath
Write-Host ("DEBUG: CSV rows loaded: {0}" -f $rows.Count)
if ($rows.Count -gt 0) { Write-Host ("DEBUG: CSV headers     : " + ($rows[0].psobject.Properties.Name -join ', ')) }

# ---------------- Subscriptions ----------------
$subs = Resolve-Subscriptions -adh_group $adh_group -adh_subscription_type $adh_subscription_type
if (-not $subs -or $subs.Count -eq 0) { throw "No subscriptions found/accessible for this SPN." }
Write-Host "DEBUG: Subscriptions = $($subs.Name -join ', ')"

$out = @()

foreach ($sub in $subs) {
    Set-ScContext -Subscription $sub
    Write-Host ""
    Write-Host "=== Subscription: $($sub.Name) ===" -ForegroundColor Cyan

    foreach ($r in $rows) {

        # --- Placeholder substitution (same logic as your script) ---
        $rgName = ($r.ResourceGroupName -replace '<Custodian>', $BaseCustodian).Trim()

        $saName = ($r.StorageAccountName -replace '<Custodian>', $BaseCustodian)
        $saName = ($saName -replace '<Cust>', $BaseCustLower).Trim()

        $cont = ($r.ContainerName -replace '<Custodian>', $BaseCustodian)
        $cont = ($cont -replace '<Cust>', $BaseCustLower).Trim()

        $iden = ($r.Identity -replace '<Custodian>', $CustIdentity).Trim()

        # --- env filter for storage naming conventions ---
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
            continue
        }

        # --- Resolve storage + container ---
        try {
            $sa  = Get-AzStorageAccount -ResourceGroupName $rgName -Name $saName -ErrorAction Stop
            $ctx = $sa.Context
        } catch {
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
            continue
        }

        try {
            $null = Get-AzStorageContainer -Name $cont -Context $ctx -ErrorAction Stop
        } catch {
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
            continue
        }

        # --- Resolve identity objectId ---
        $objectId = Resolve-IdentityObjectId -IdentityName $iden
        if (-not $objectId) {
            $out += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $rgName
                Storage          = $saName
                Container        = $cont
                Folder           = $folderForReport
                Identity         = $iden
                Permission       = $r.PermissionType
                Status           = 'ERROR'
                Notes            = "Identity '$iden' not found OR ambiguous in Entra ID. (Tip: use GUID AppId/ObjectId in CSV)"
            }
            continue
        }

        # --- ACL validation (folder + parents + root) ---
        $permType  = $r.PermissionType
        $pathsToCheck = Get-PathsToCheck -NormalizedPath $normalizedPath

        $matchedAt = $null
        $debugDump = $false

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
