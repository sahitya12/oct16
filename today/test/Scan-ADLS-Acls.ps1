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

Import-Module Az.Accounts, Az.Resources, Az.Storage -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

Write-Host "DEBUG: TenantId=$TenantId"
Write-Host "DEBUG: ClientId=$ClientId"
Write-Host "DEBUG: adh_group=$adh_group"
Write-Host "DEBUG: adh_subscription_type=$adh_subscription_type"
Write-Host "DEBUG: InputCsvPath=$InputCsvPath"
Write-Host "DEBUG: OutputDir=$OutputDir"
Write-Host "DEBUG: BranchName=$BranchName"

Ensure-Dir -Path $OutputDir | Out-Null

if (-not (Test-Path -LiteralPath $InputCsvPath)) {
    throw "ADLS CSV not found: $InputCsvPath"
}

$rows = Import-Csv -LiteralPath $InputCsvPath

if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure connection failed."
}

# --------------------------------------------------------------------
# Identity name -> ObjectId cache + resolver
# --------------------------------------------------------------------
$script:IdentityCache = @{}

function Resolve-IdentityObjectId {
    param([Parameter(Mandatory = $true)][string]$IdentityName)

    if ($script:IdentityCache.ContainsKey($IdentityName)) {
        return $script:IdentityCache[$IdentityName]
    }

    $id = $null

    # Try as Entra group
    try {
        $grp = Get-AzADGroup -DisplayName $IdentityName -ErrorAction Stop
        if ($grp -and $grp.Id) { $id = $grp.Id }
    } catch { }

    # Try as service principal display name
    if (-not $id) {
        try {
            $sp = Get-AzADServicePrincipal -DisplayName $IdentityName -ErrorAction Stop
            if ($sp -and $sp.Id) { $id = $sp.Id }
        } catch { }
    }

    # Fallback search
    if (-not $id) {
        try {
            $sp2 = Get-AzADServicePrincipal -SearchString $IdentityName -ErrorAction Stop
            if ($sp2 -and $sp2.Count -ge 1) { $id = $sp2[0].Id }
        } catch { }
    }

    # If already a GUID, accept it
    if (-not $id) {
        $guidRef = [ref]([Guid]::Empty)
        if ([Guid]::TryParse($IdentityName, $guidRef)) {
            $id = $IdentityName
        }
    }

    $script:IdentityCache[$IdentityName] = $id
    return $id
}

# --------------------------------------------------------------------
# Recursively list all folders (paths) in a filesystem
# --------------------------------------------------------------------
function Get-Gen2FoldersRecursive {
    param(
        [string]$FileSystem,
        [string]$Path,
        $Context
    )

    $all = @()
    $currentPath = $Path

    if ($currentPath -ne "") {
        $all += $currentPath
    }

    $subdirs = @(Get-AzDataLakeGen2ChildItem -FileSystem $FileSystem -Path $Path -Context $Context |
                Where-Object { $_.IsDirectory })

    foreach ($dir in $subdirs) {
        $dirPath = if ($Path) { "$Path/$($dir.Name)" } else { $dir.Name }
        $all += Get-Gen2FoldersRecursive -FileSystem $FileSystem -Path $dirPath -Context $Context
    }

    return $all
}

# --------------------------------------------------------------------
# Main logic
# --------------------------------------------------------------------
$out  = @()
$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
if ($subs -isnot [System.Collections.IEnumerable]) { $subs = ,$subs }

foreach ($sub in $subs) {

    Set-ScContext -Subscription $sub

    foreach ($r in $rows) {

        $rgName       = ($r.ResourceGroupName -replace '<Custodian>', $adh_group)
        $saName       = ($r.StorageAccountName -replace '<Cust>', $adh_group.ToLower()) -replace '<Custodian>', $adh_group
        $cont         = ($r.ContainerName   -replace '<Cust>', $adh_group.ToLower())
        $identityName = ($r.Identity        -replace '<Custodian>', $adh_group)
        $permType     = $r.PermissionType
        $expAccess    = $r.AccessPath
        $ruleType     = $r.Type
        $ruleScope    = $r.Scope

        # -------- Storage account --------
        try {
            $sa = Get-AzStorageAccount -ResourceGroupName $rgName -Name $saName -ErrorAction Stop
        }
        catch {
            $out += [pscustomobject]@{
                SubscriptionName   = $sub.Name
                ResourceGroup      = $rgName
                Storage            = $saName
                Container          = $cont
                Folder             = '/'
                ExpectedAccessPath = $expAccess
                Type               = $ruleType
                Scope              = $ruleScope
                Identity           = $identityName
                PermissionType     = $permType
                Status             = 'ERROR'
                Notes              = "Storage Account error: $($_.Exception.Message)"
            }
            continue
        }

        $ctx = $sa.Context

        # -------- Container --------
        try {
            $container = Get-AzStorageContainer -Name $cont -Context $ctx -ErrorAction Stop
        }
        catch {
            $out += [pscustomobject]@{
                SubscriptionName   = $sub.Name
                ResourceGroup      = $rgName
                Storage            = $saName
                Container          = $cont
                Folder             = '/'
                ExpectedAccessPath = $expAccess
                Type               = $ruleType
                Scope              = $ruleScope
                Identity           = $identityName
                PermissionType     = $permType
                Status             = 'ERROR'
                Notes              = "Container fetch error: $($_.Exception.Message)"
            }
            continue
        }

        if (-not $container) {
            $out += [pscustomobject]@{
                SubscriptionName   = $sub.Name
                ResourceGroup      = $rgName
                Storage            = $saName
                Container          = $cont
                Folder             = '/'
                ExpectedAccessPath = $expAccess
                Type               = $ruleType
                Scope              = $ruleScope
                Identity           = $identityName
                PermissionType     = $permType
                Status             = 'MISSING'
                Notes              = "Container not found"
            }
            continue
        }

        # -------- Get all folder paths (root + subfolders) --------
        $allFolders = @("")
        $allFolders += Get-Gen2FoldersRecursive -FileSystem $cont -Path "" -Context $ctx

        foreach ($folderPath in $allFolders) {

            $objectId = Resolve-IdentityObjectId -IdentityName $identityName
            if (-not $objectId) {
                $out += [pscustomobject]@{
                    SubscriptionName   = $sub.Name
                    ResourceGroup      = $rgName
                    Storage            = $saName
                    Container          = $cont
                    Folder             = '/'
                    ExpectedAccessPath = $expAccess
                    Type               = $ruleType
                    Scope              = $ruleScope
                    Identity           = $identityName
                    PermissionType     = $permType
                    Status             = 'ERROR'
                    Notes              = "Identity '$identityName' not found in Entra ID"
                }
                continue
            }

            try {
                # Always pass a Path – for root use "/"
                $normPath = if ([string]::IsNullOrWhiteSpace($folderPath)) { "/" } else { $folderPath }

                $params = @{
                    FileSystem  = $cont
                    Context     = $ctx
                    Path        = $normPath
                    ErrorAction = 'Stop'
                }

                $item       = Get-AzDataLakeGen2Item @params
                $aclEntries = $item.Acl

                $matchEntry = $aclEntries | Where-Object {
                    ($_ -match [regex]::Escape($objectId)) -and ($_ -match [regex]::Escape($permType))
                }

                $permStatus = if ($matchEntry) { 'OK' } else { 'MISSING' }
                $permNotes  = if ($matchEntry) { 'Permissions match' } else { 'Permissions missing or mismatched' }
            }
            catch {
                $permStatus = 'ERROR'
                $permNotes  = "ACL read error: $($_.Exception.Message)"
            }

            $out += [pscustomobject]@{
                SubscriptionName   = $sub.Name
                ResourceGroup      = $rgName
                Storage            = $saName
                Container          = $cont
                Folder             = $normPath
                ExpectedAccessPath = $expAccess
                Type               = $ruleType
                Scope              = $ruleScope
                Identity           = $identityName
                PermissionType     = $permType
                Status             = $permStatus
                Notes              = $permNotes
            }
        }
    }
}

if (-not $out) {
    $out += [pscustomobject]@{
        SubscriptionName   = ''
        ResourceGroup      = ''
        Storage            = ''
        Container          = ''
        Folder             = ''
        ExpectedAccessPath = ''
        Type               = ''
        Scope              = ''
        Identity           = ''
        PermissionType     = ''
        Status             = 'NO_RESULTS'
        Notes              = 'Nothing matched in scan'
    }
}

$csvOut  = New-StampedPath -BaseDir $OutputDir -Prefix ("adls_validation_{0}_{1}" -f $adh_group, $adh_subscription_type)
Write-CsvSafe -Rows $out -Path $csvOut

$htmlOut = $csvOut -replace '\.csv$','.html'
Convert-CsvToHtml -CsvPath $csvOut -HtmlPath $htmlOut -Title "ADLS Validation ($adh_group / $adh_subscription_type) $BranchName"

Write-Host "ADLS validation completed." -ForegroundColor Green
Write-Host "CSV : $csvOut"
Write-Host "HTML: $htmlOut"
