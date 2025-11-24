param(
    [Parameter(Mandatory = $true)][string]$TenantId,
    [Parameter(Mandatory = $true)][string]$ClientId,
    [Parameter(Mandatory = $true)][string]$ClientSecret,
    [Parameter(Mandatory = $true)][string]$adh_group,
    [ValidateSet('nonprd','prd')][string]$adh_subscription_type = 'nonprd',
    [Parameter(Mandatory = $true)][string]$InputCsvPath,
    [Parameter(Mandatory = $true)][string]$OutputDir,
    [string]$BranchName = ''
)

# ----------------------------------------------------------
# Imports / setup
# ----------------------------------------------------------
Import-Module Az.Accounts, Az.Resources, Az.Storage -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

Write-Host "==== ADLS ACL Validation ===="
Write-Host "TenantId            : $TenantId"
Write-Host "ClientId            : $ClientId"
Write-Host "adh_group           : $adh_group"
Write-Host "adh_subscription_type: $adh_subscription_type"
Write-Host "InputCsvPath        : $InputCsvPath"
Write-Host "OutputDir           : $OutputDir"
Write-Host "BranchName          : $BranchName"

$OutputDir = Ensure-Dir -Path $OutputDir

if (-not (Test-Path -LiteralPath $InputCsvPath)) {
    throw "ADLS CSV not found: $InputCsvPath"
}

$rows = Import-Csv -LiteralPath $InputCsvPath
if (-not $rows -or $rows.Count -eq 0) {
    throw "ADLS CSV '$InputCsvPath' is empty."
}

if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure connection failed."
}

# ----------------------------------------------------------
# Helpers
# ----------------------------------------------------------

# Cache for identity name -> objectId
$script:IdentityCache = @{}

function Resolve-IdentityObjectId {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$IdentityName
    )

    if ([string]::IsNullOrWhiteSpace($IdentityName)) {
        return $null
    }

    if ($script:IdentityCache.ContainsKey($IdentityName)) {
        return $script:IdentityCache[$IdentityName]
    }

    $id = $null

    # 1. Try group by display name
    try {
        $grp = Get-AzADGroup -DisplayName $IdentityName -ErrorAction Stop
        if ($grp -and $grp.Id) { $id = $grp.Id }
    } catch { }

    # 2. Try SPN by display name
    if (-not $id) {
        try {
            $sp = Get-AzADServicePrincipal -DisplayName $IdentityName -ErrorAction Stop
            if ($sp -and $sp.Id) { $id = $sp.Id }
        } catch { }
    }

    # 3. Try SPN search if partial match
    if (-not $id) {
        try {
            $sp2 = Get-AzADServicePrincipal -SearchString $IdentityName -ErrorAction Stop
            if ($sp2 -and $sp2.Count -ge 1) { $id = $sp2[0].Id }
        } catch { }
    }

    # 4. If literal GUID string
    if (-not $id -and $IdentityName -match '^[0-9a-fA-F-]{36}$') {
        $id = $IdentityName
    }

    $script:IdentityCache[$IdentityName] = $id
    return $id
}

function Normalize-AdlsPath {
    param(
        [string]$PathFromCsv
    )
    if ([string]::IsNullOrWhiteSpace($PathFromCsv) -or $PathFromCsv -eq "/") {
        return "/"
    }

    # remove leading slashes, keep inner structure
    $p = $PathFromCsv.Trim()
    $p = $p.TrimStart('/')
    if ([string]::IsNullOrWhiteSpace($p)) { return "/" }
    return $p
}

# ----------------------------------------------------------
# Main logic
# ----------------------------------------------------------

$out = @()

# Get subscriptions for this adh_group
$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
if ($subs -isnot [System.Collections.IEnumerable]) { $subs = ,$subs }

foreach ($sub in $subs) {

    Write-Host "---- Processing subscription: $($sub.Name) ($($sub.Id)) ----"
    Set-ScContext -Subscription $sub

    foreach ($r in $rows) {

        # Expecting CSV columns like:
        # ResourceGroupName, StorageAccountName, ContainerName, AccessPath, Identity, PermissionType
        $rgName       = $r.ResourceGroupName
        $saName       = $r.StorageAccountName
        $container    = $r.ContainerName
        $identityName = $r.Identity
        $permType     = $r.Permission   # e.g. "r-x", "rwx" etc.
        $accessPath   = $r.Folder       # you called it Folder in your screenshots

        # Token replacement (if you still use <Cust> / <Custodian> in template)
        $rgName    = $rgName    -replace '<Custodian>', $adh_group
        $saName    = $saName    -replace '<Cust>', $adh_group.ToLower() -replace '<Custodian>', $adh_group
        $container = $container -replace '<Cust>', $adh_group.ToLower()
        $identityName = $identityName -replace '<Custodian>', $adh_group

        # Normalise folder/path (VERY important for root vs subfolders)
        $normPath = Normalize-AdlsPath -PathFromCsv $accessPath

        # Default values for this row
        $status = 'ERROR'
        $notes  = ''

        # 1. Resolve storage account
        $sa = $null
        try {
            $sa = Get-AzStorageAccount -ResourceGroupName $rgName -Name $saName -ErrorAction Stop
        } catch {
            $notes  = "Storage account error: $($_.Exception.Message)"
            $status = 'ERROR'
            $out += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $rgName
                Storage          = $saName
                Container        = $container
                Folder           = $accessPath
                Identity         = $identityName
                Permission       = $permType
                Status           = $status
                Notes            = $notes
            }
            continue
        }

        $ctx = $sa.Context

        # 2. Resolve identity -> objectId
        $objectId = Resolve-IdentityObjectId -IdentityName $identityName
        if (-not $objectId) {
            $status = 'ERROR'
            $notes  = "Identity '$identityName' not found in Entra ID"
            $out += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $rgName
                Storage          = $saName
                Container        = $container
                Folder           = $accessPath
                Identity         = $identityName
                Permission       = $permType
                Status           = $status
                Notes            = $notes
            }
            continue
        }

        # 3. Read ADLS item + ACL
        try {
            # IMPORTANT: Path is ALWAYS specified. For root we explicitly use "/"
            $pathForCmd = if ($normPath -eq "/") { "/" } else { $normPath }

            $item = Get-AzDataLakeGen2Item `
                        -FileSystem $container `
                        -Path $pathForCmd `
                        -Context $ctx `
                        -ErrorAction Stop

            $aclEntries = $item.Acl

            if (-not $aclEntries -or $aclEntries.Count -eq 0) {
                $status = 'MISSING'
                $notes  = "No ACL entries found at this level"
            }
            else {
                # Entries are strings like: user:objectId:rwx or group:objectId:r-x
                $match = $aclEntries | Where-Object {
                    $_ -match $objectId -and $_ -match $permType
                }

                if ($match) {
                    $status = 'OK'
                    $notes  = "Permissions match"
                } else {
                    $status = 'MISSING'
                    $notes  = "Permissions missing or mismatched"
                }
            }
        }
        catch {
            $status = 'ERROR'
            $notes  = "ACL read error: $($_.Exception.Message)"
        }

        # 4. Emit row
        $out += [pscustomobject]@{
            SubscriptionName = $sub.Name
            ResourceGroup    = $rgName
            Storage          = $saName
            Container        = $container
            Folder           = (if ([string]::IsNullOrWhiteSpace($accessPath)) { '/' } else { $accessPath })
            Identity         = $identityName
            Permission       = $permType
            Status           = $status
            Notes            = $notes
        }
    }
}

# ----------------------------------------------------------
# Output
# ----------------------------------------------------------
if (-not $out -or $out.Count -eq 0) {
    $out = @(
        [pscustomobject]@{
            SubscriptionName = ''
            ResourceGroup    = ''
            Storage          = ''
            Container        = ''
            Folder           = ''
            Identity         = ''
            Permission       = ''
            Status           = 'NO_RESULTS'
            Notes            = 'No rows were produced by the scan'
        }
    )
}

$csvOut = New-StampedPath -BaseDir $OutputDir -Prefix ("adls_validation_{0}_{1}" -f $adh_group, $adh_subscription_type)
Write-CsvSafe -Rows $out -Path $csvOut

$htmlOut = $csvOut -replace '\.csv$', '.html'
Convert-CsvToHtml -CsvPath $csvOut -HtmlPath $htmlOut -Title "ADLS ACL Validation ($adh_group / $adh_subscription_type) $BranchName"

Write-Host "ADLS ACL validation completed." -ForegroundColor Green
Write-Host "CSV  : $csvOut"
Write-Host "HTML : $htmlOut"
