# Scan-ADLS-Acls.ps1
# ADLS Gen2 ACL validator (subscription strictly filtered by naming convention)
# Subscription naming rule:
#   <dev|prd>_azure_*_ADH<adh_group>
# Example:
#   dev_azure_20481_ADHCIT  (nonprd)
#   prd_azure_20481_ADHCIT  (prd)

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

    # keep it for ADO pipeline even if unused
    [string]$BranchName = '',

    # optional verbose ACL dump
    [switch]$DebugAcls
)

Import-Module Az.Accounts, Az.Resources, Az.Storage -ErrorAction Stop

# ---------------- Small helpers (same spirit as your RG-perm script) ----------------
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
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$ClientSecret
    )

    try {
        $sec  = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential($ClientId, $sec)

        # IMPORTANT: tenant-only login (do not force any default subscription)
        Connect-AzAccount -ServicePrincipal -TenantId $TenantId -Credential $cred -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        Write-Warning "Connect-ScAz failed: $($_.Exception.Message)"
        return $false
    }
}

function Set-ScContext {
    param([Parameter(Mandatory)]$Subscription)
    Set-AzContext -SubscriptionId $Subscription.Id -ErrorAction Stop | Out-Null
}

# strict subscription filter by naming rule:
#   <dev|prd>_azure_*_ADH<adh_group>
function Resolve-OnlyAdhSubscription {
    param(
        [Parameter(Mandatory)][string]$adh_group,
        [Parameter(Mandatory)][ValidateSet('nonprd','prd')]$adh_subscription_type
    )

    $envPrefix = if ($adh_subscription_type -eq 'prd') { 'prd_azure_' } else { 'dev_azure_' }
    $adhToken  = "ADH$($adh_group.ToUpper())"
    $rx        = "(?i)^$([regex]::Escape($envPrefix)).*_$([regex]::Escape($adhToken))(\b|$)"

    $all = Get-AzSubscription -ErrorAction Stop
    $subs = $all | Where-Object { $_.Name -match $rx }

    return @($subs)
}

function Get-FieldValue {
    param(
        [Parameter(Mandatory)]$Row,
        [Parameter(Mandatory)][string[]]$Candidates
    )
    foreach ($c in $Candidates) {
        if ($Row.PSObject.Properties.Name -contains $c) {
            $v = $Row.$c
            if ($null -ne $v) { return [string]$v }
        }
    }
    return $null
}

function Perm-Ok {
    param([string]$AcePerm, [string]$Required)
    switch ($Required) {
        'r-x' { return ($AcePerm -eq 'r-x' -or $AcePerm -eq 'rwx') }
        'rwx' { return ($AcePerm -eq 'rwx') }
        'r--' { return ($AcePerm.Length -ge 1 -and $AcePerm[0] -eq 'r') }
        default { return ($AcePerm -eq $Required) }
    }
}

function Get-PathsToCheck {
    param([string]$NormalizedPath)
    # returns list: folder, parents..., root("")
    if ([string]::IsNullOrWhiteSpace($NormalizedPath) -or $NormalizedPath -eq '/' ) { return @('') }

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
    param([string]$FileSystem,$Context,[string]$Path)

    $p = @{ FileSystem = $FileSystem; Context = $Context; ErrorAction = 'Stop' }
    if ($Path -and $Path.Trim() -ne '') { $p['Path'] = $Path }

    $item = Get-AzDataLakeGen2Item @p

    # include Access ACL; (DefaultAcl optional but useful)
    $entries = @()
    if ($item.Acl)        { $entries += $item.Acl }
    if ($item.DefaultAcl) { $entries += $item.DefaultAcl }
    return ,$entries
}

function Has-MatchingAce {
    param([object[]]$Entries,[string]$ObjectId,[string]$PermType)

    foreach ($ace in $Entries) {
        if ($ace.AccessControlType -notin @('user','group')) { continue }
        if (-not $ace.EntityId) { continue }
        if ($ace.EntityId -ne $ObjectId) { continue }

        $acePerm = $ace.Permissions.ToString()
        if (Perm-Ok -AcePerm $acePerm -Required $PermType) { return $true }
    }
    return $false
}

# ---------------- Microsoft Graph identity resolver ----------------
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

function Graph-Get {
    param([string]$Token,[string]$Uri)

    $headers = @{ Authorization = "Bearer $Token" }
    Invoke-RestMethod -Method Get -Headers $headers -Uri $Uri
}

# returns objectId or $null
function Resolve-IdentityObjectId {
    param(
        [Parameter(Mandatory)][string]$Token,
        [Parameter(Mandatory)][string]$IdentityName
    )

    # GUID in CSV? accept as objectId
    $g = [ref]([Guid]::Empty)
    if ([Guid]::TryParse($IdentityName, $g)) {
        return $IdentityName
    }

    # escape single quotes for OData
    $safe = $IdentityName.Replace("'", "''")

    # service principal by displayName
    try {
        $uri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=displayName eq '$safe'&`$select=id,displayName"
        $r = Graph-Get -Token $Token -Uri $uri
        if ($r.value.Count -ge 1) { return $r.value[0].id }
    } catch {}

    # group by displayName
    try {
        $uri = "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$safe'&`$select=id,displayName"
        $r = Graph-Get -Token $Token -Uri $uri
        if ($r.value.Count -ge 1) { return $r.value[0].id }
    } catch {}

    return $null
}

# ---------------- START ----------------
$adh_sub_group = ($adh_sub_group ?? '').Trim()
if ([string]::IsNullOrWhiteSpace($adh_sub_group)) { $adh_sub_group = '' }

Write-Host "DEBUG: TenantId      = $TenantId"
Write-Host "DEBUG: ClientId      = $ClientId"
Write-Host "DEBUG: adh_group     = $adh_group"
Write-Host "DEBUG: adh_sub_group = '$adh_sub_group'"
Write-Host "DEBUG: subscription  = $adh_subscription_type"
Write-Host "DEBUG: InputCsvPath  = $InputCsvPath"
Write-Host "DEBUG: OutputDir     = $OutputDir"
Write-Host "DEBUG: BranchName    = $BranchName"

Ensure-Dir -Path $OutputDir | Out-Null
if (-not (Test-Path -LiteralPath $InputCsvPath)) { throw "Input CSV not found: $InputCsvPath" }

# connect (same as RG-perm approach)
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure connection failed."
}

# graph token
$graphToken = Get-GraphToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
Write-Host "Graph token acquired." -ForegroundColor Green

# load CSV
$rows = Import-Csv -LiteralPath $InputCsvPath
if (-not $rows -or $rows.Count -eq 0) { throw "CSV has no rows: $InputCsvPath" }

Write-Host ("DEBUG: CSV rows loaded: {0}" -f $rows.Count)
Write-Host ("DEBUG: CSV headers: " + ($rows[0].PSObject.Properties.Name -join ', '))

# validate required columns (accept a few variants)
$need = @{
    ResourceGroup = @('ResourceGroupName','resource_group_name','ResourceGroup')
    Storage       = @('StorageAccountName','storage_account_name','Storage','StorageAccount')
    Container     = @('ContainerName','container_name','Container','FileSystem')
    AccessPath    = @('AccessPath','access_path','Folder','Path')
    Identity      = @('Identity','identity','Principal','principal')
    Permission    = @('PermissionType','permission_type','Permission','permission')
}

foreach ($k in $need.Keys) {
    $v = Get-FieldValue -Row $rows[0] -Candidates $need[$k]
    if ($null -eq $v) {
        throw "CSV missing required column for '$k'. Expected one of: $($need[$k] -join ', ')"
    }
}

# choose custodian tokens for replacements
$BaseCustodian = $adh_group
$BaseCustLower = $adh_group.ToLower() -replace '_',''
$CustIdentity  = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) { $adh_group } else { "${adh_group}_${adh_sub_group}" }

# resolve ONLY the subscriptions we want
$subs = Resolve-OnlyAdhSubscription -adh_group $adh_group -adh_subscription_type $adh_subscription_type
if (-not $subs -or $subs.Count -eq 0) {
    throw "No subscriptions matched naming rule for adh_group=$adh_group env=$adh_subscription_type. Expected: <dev|prd>_azure_*_ADH$($adh_group.ToUpper())"
}

Write-Host "Scanning ONLY subscriptions:" -ForegroundColor Cyan
$subs | ForEach-Object { Write-Host "  - $($_.Name) ($($_.Id))" }

$out = @()

foreach ($sub in $subs) {
    Set-ScContext -Subscription $sub
    Write-Host ""
    Write-Host "=== Subscription: $($sub.Name) ===" -ForegroundColor Cyan

    foreach ($r in $rows) {

        # read row values with flexible headers
        $rgRaw   = Get-FieldValue -Row $r -Candidates $need.ResourceGroup
        $saRaw   = Get-FieldValue -Row $r -Candidates $need.Storage
        $ctRaw   = Get-FieldValue -Row $r -Candidates $need.Container
        $pathRaw = Get-FieldValue -Row $r -Candidates $need.AccessPath
        $idRaw   = Get-FieldValue -Row $r -Candidates $need.Identity
        $permRaw = Get-FieldValue -Row $r -Candidates $need.Permission

        # substitute placeholders
        $rgName = ($rgRaw -replace '<Custodian>', $BaseCustodian).Trim()

        $saName = ($saRaw -replace '<Custodian>', $BaseCustodian)
        $saName = ($saName -replace '<Cust>', $BaseCustLower).Trim()

        $cont = ($ctRaw -replace '<Custodian>', $BaseCustodian)
        $cont = ($cont -replace '<Cust>', $BaseCustLower).Trim()

        $accessPath = ($pathRaw -replace '<Custodian>', $BaseCustodian)
        $accessPath = ($accessPath -replace '<Cust>', $BaseCustLower).Trim()

        # normalize to '' for root
        $normalizedPath = $accessPath
        if ($normalizedPath -eq '/' -or [string]::IsNullOrWhiteSpace($normalizedPath)) { $normalizedPath = '' }

        $folderForReport = if ([string]::IsNullOrWhiteSpace($normalizedPath)) { '/' } else { "/$($normalizedPath.TrimStart('/'))" }

        # identities can be comma-separated
        $identities = @()
        if ($idRaw) {
            $identities = $idRaw.Split(',') |
                ForEach-Object { ($_ -replace '<Custodian>', $CustIdentity).Trim() } |
                Where-Object { $_ }
        }

        if (-not $identities -or $identities.Count -eq 0) {
            $out += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $rgName
                Storage          = $saName
                Container        = $cont
                Folder           = $folderForReport
                Identity         = ''
                Permission       = $permRaw
                Status           = 'ERROR'
                Notes            = 'Identity column empty after parsing'
            }
            continue
        }

        # resolve storage
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
                    Permission       = $permRaw
                    Status           = 'ERROR'
                    Notes            = "Storage account error: $($_.Exception.Message)"
                }
            }
            continue
        }

        # ensure container exists
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
                    Permission       = $permRaw
                    Status           = 'ERROR'
                    Notes            = "Container fetch error: $($_.Exception.Message)"
                }
            }
            continue
        }

        $permType = $permRaw.Trim()
        $pathsToCheck = Get-PathsToCheck -NormalizedPath $normalizedPath

        foreach ($iden in $identities) {

            $objectId = Resolve-IdentityObjectId -Token $graphToken -IdentityName $iden

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
                    Notes            = "Cannot resolve '$iden' to Entra objectId via Graph. Use GUID or fix Graph permissions/consent."
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
}

# always write something
if (-not $out -or $out.Count -eq 0) {
    $out = @([pscustomobject]@{
        SubscriptionName=''; ResourceGroup=''; Storage=''; Container=''; Folder=''
        Identity=''; Permission=''; Status='NO_RESULTS'; Notes='Nothing matched in scan'
    })
}

$groupForFile = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) { $adh_group } else { "${adh_group}_${adh_sub_group}" }
$stamp  = Get-Date -Format 'yyyyMMdd'
$csvOut = Join-Path $OutputDir ("adls_acl_{0}_{1}_{2}.csv" -f $groupForFile, $adh_subscription_type, $stamp)

Write-CsvSafe -Rows $out -Path $csvOut
Write-Host "ADLS validation completed." -ForegroundColor Green
Write-Host "CSV : $csvOut"
exit 0
