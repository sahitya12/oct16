# Scan-ADLS-Acls.ps1
# ADLS Gen2 ACL validator (robust)
# - Works even when root ACL reading is flaky (tries '' and '/')
# - Handles Az ACL entry property differences (EntityId/Id/ObjectId)
# - Auto-resolves correct env storage account name (e.g., adhcitadls -> adhcitadlsnonprd)
# - Checks folder + parents + container root
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
    param(
        [Parameter(Mandatory)][object[]]$Rows,
        [Parameter(Mandatory)][string]$Path
    )
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

function Set-ScContext {
    param($Subscription)
    Set-AzContext -SubscriptionId $Subscription.Id -ErrorAction Stop | Out-Null
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

    if ([string]::IsNullOrWhiteSpace($NormalizedPath) -or $NormalizedPath -eq '/') {
        # root only (we will try '' and '/' later)
        return @('')
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

function Get-AceEntityId {
    param($ace)
    # Different Az versions expose different property names
    if ($null -ne $ace.EntityId -and $ace.EntityId.ToString().Trim() -ne '') { return $ace.EntityId.ToString() }
    if ($null -ne $ace.Id       -and $ace.Id.ToString().Trim()       -ne '') { return $ace.Id.ToString() }
    if ($null -ne $ace.ObjectId -and $ace.ObjectId.ToString().Trim() -ne '') { return $ace.ObjectId.ToString() }
    return $null
}

function Read-AclEntries {
    param(
        [Parameter(Mandatory)][string]$FileSystem,
        [Parameter(Mandatory)]$Context,
        [string]$Path
    )

    # Root handling: try '' and '/' because some Az builds behave differently
    $pathsToTry = @()
    if ([string]::IsNullOrWhiteSpace($Path)) {
        $pathsToTry = @($null, '', '/')
    } else {
        $pathsToTry = @($Path)
    }

    $lastErr = $null
    foreach ($pTry in $pathsToTry) {
        try {
            $p = @{ FileSystem = $FileSystem; Context = $Context; ErrorAction = 'Stop' }
            if ($pTry -ne $null -and $pTry.ToString().Trim() -ne '') {
                # Gen2 expects path WITHOUT leading slash typically
                $clean = $pTry.ToString().Trim()
                $clean = $clean.TrimStart('/')
                $p['Path'] = $clean
            } elseif ($pTry -eq '/') {
                # Explicit root variant
                $p['Path'] = ''
            }

            $item = Get-AzDataLakeGen2Item @p

            $entries = @()
            if ($item.Acl)        { $entries += $item.Acl }
            if ($item.DefaultAcl) { $entries += $item.DefaultAcl }
            return $entries
        }
        catch {
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
        $act = $ace.AccessControlType.ToString()
        if ($act -notin @('user','group','User','Group')) { continue }

        $eid = Get-AceEntityId -ace $ace
        if (-not $eid) { continue }
        if ($eid -ne $ObjectId) { continue }

        $perm = $ace.Permissions.ToString()
        if (Perm-Ok -acePerm $perm -permType $PermType) {
            return $true
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
Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
Write-Host "Authenticated to Azure." -ForegroundColor Green

# ---------------- Custodian helpers ----------------
$BaseCustodian = $adh_group
$BaseCustLower = $adh_group.ToLower() -replace '_',''
$CustIdentity  = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) { $adh_group } else { "${adh_group}_${adh_sub_group}" }

# ---------------- Identity resolver ----------------
# NOTE: If your SPN cannot query Entra, you MUST use GUIDs (objectId) in CSV.
# Your screenshot shows objectId in parentheses -> that is the best value to use.
$script:IdentityCache = @{}

function Resolve-IdentityObjectId {
    param([Parameter(Mandatory)][string]$IdentityName)

    if ($script:IdentityCache.ContainsKey($IdentityName)) { return $script:IdentityCache[$IdentityName] }

    # Accept GUID as-is (objectId)
    $guidRef = [ref]([Guid]::Empty)
    if ([Guid]::TryParse($IdentityName, $guidRef)) {
        $script:IdentityCache[$IdentityName] = $IdentityName
        return $IdentityName
    }

    # Try AzAD lookups (requires Entra read rights)
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

# ---------------- Storage account resolver (ENV-safe) ----------------
function Resolve-StorageAccountByEnv {
    param(
        [Parameter(Mandatory)][string]$ResourceGroupName,
        [Parameter(Mandatory)][string]$StorageAccountName,
        [ValidateSet('nonprd','prd')][string]$Env
    )

    # Try candidates. If user passes adhcitadls but actual is adhcitadlsnonprd, this fixes it.
    $candidates = New-Object System.Collections.Generic.List[string]
    $candidates.Add($StorageAccountName)

    if ($Env -eq 'nonprd') {
        if ($StorageAccountName -notmatch '(?i)nonprd$') { $candidates.Add($StorageAccountName + 'nonprd') }
    } else {
        if ($StorageAccountName -notmatch '(?i)prd$') { $candidates.Add($StorageAccountName + 'prd') }
    }

    # Also try both suffixes if naming is inconsistent
    if ($StorageAccountName -notmatch '(?i)nonprd$') { $candidates.Add($StorageAccountName + 'nonprd') }
    if ($StorageAccountName -notmatch '(?i)prd$')    { $candidates.Add($StorageAccountName + 'prd') }

    foreach ($name in ($candidates | Select-Object -Unique)) {
        try {
            $sa = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $name -ErrorAction Stop
            return $sa
        } catch { }
    }

    # If none worked, throw the last attempt from original name
    return (Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction Stop)
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

        # Placeholder substitution
        $rgName = ($r.ResourceGroupName -replace '<Custodian>', $BaseCustodian).Trim()

        $saName = ($r.StorageAccountName -replace '<Custodian>', $BaseCustodian)
        $saName = ($saName -replace '<Cust>', $BaseCustLower).Trim()

        $cont = ($r.ContainerName -replace '<Custodian>', $BaseCustodian)
        $cont = ($cont -replace '<Cust>', $BaseCustLower).Trim()

        # identities (supports CSV "a,b,c")
        $identities = @()
        if ($r.Identity) {
            $identities = $r.Identity.Split(',') |
                ForEach-Object { ($_ -replace '<Custodian>', $CustIdentity).Trim() } |
                Where-Object { $_ }
        }

        # AccessPath normalization
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

        # Resolve storage + container (ENV-safe SA resolver)
        $ctx = $null
        $resolvedSaName = $saName
        try {
            $sa = Resolve-StorageAccountByEnv -ResourceGroupName $rgName -StorageAccountName $saName -Env $adh_subscription_type
            $ctx = $sa.Context
            $resolvedSaName = $sa.StorageAccountName
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
                    SubscriptionName=$sub.Name; ResourceGroup=$rgName; Storage=$resolvedSaName; Container=$cont; Folder=$folderForReport
                    Identity=$iden; Permission=$r.PermissionType; Status='ERROR'
                    Notes="Container fetch error: $($_.Exception.Message)"
                }
            }
            continue
        }

        # ACL validation
        $permType = $r.PermissionType
        $pathsToCheck = Get-PathsToCheck -NormalizedPath $normalizedPath

        foreach ($iden in $identities) {

            $objectId = Resolve-IdentityObjectId -IdentityName $iden

            if (-not $objectId) {
                $out += [pscustomobject]@{
                    SubscriptionName=$sub.Name; ResourceGroup=$rgName; Storage=$resolvedSaName; Container=$cont; Folder=$folderForReport
                    Identity=$iden; Permission=$permType
                    Status='UNRESOLVED_IDENTITY'
                    Notes="Cannot resolve '$iden' to Entra objectId using AzAD. Best fix: put the OBJECT ID GUID in CSV (the GUID shown in portal parentheses)."
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
                            $eid = Get-AceEntityId -ace $ace
                            Write-Host ("ACE => Type={0} EntityId={1} Perm={2}" -f $ace.AccessControlType, $eid, $ace.Permissions) -ForegroundColor DarkGray
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
                Storage=$resolvedSaName
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
