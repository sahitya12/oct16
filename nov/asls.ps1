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

# --------------------------------------------------------------------
# Imports / Setup
# --------------------------------------------------------------------
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
# Helpers
# --------------------------------------------------------------------
$script:IdentityCache = @{}

function Resolve-IdentityObjectId {
    param([Parameter(Mandatory = $true)][string]$IdentityName)

    if ($script:IdentityCache.ContainsKey($IdentityName)) {
        return $script:IdentityCache[$IdentityName]
    }

    $id = $null

    # Try group
    try {
        $grp = Get-AzADGroup -DisplayName $IdentityName -ErrorAction Stop
        if ($grp -and $grp.Id) { $id = $grp.Id }
    } catch { }

    # Try SPN by display name
    if (-not $id) {
        try {
            $sp = Get-AzADServicePrincipal -DisplayName $IdentityName -ErrorAction Stop
            if ($sp -and $sp.Id) { $id = $sp.Id }
        } catch { }
    }

    # Try SPN search (substring)
    if (-not $id) {
        try {
            $sp2 = Get-AzADServicePrincipal -SearchString $IdentityName -ErrorAction Stop
            if ($sp2 -and $sp2.Count -ge 1) { $id = $sp2[0].Id }
        } catch { }
    }

    # Direct GUID?
    if (-not $id) {
        $outGuid = [ref]([guid]::Empty)
        if ([Guid]::TryParse($IdentityName, $outGuid)) {
            $id = $IdentityName
        }
    }

    $script:IdentityCache[$IdentityName] = $id
    return $id
}

function Get-AclMatchStatus {
    param(
        [string[]]$AclEntries,
        [string]$ObjectId,
        [string]$RequestedPerm   # e.g. "r-x", "rwx"
    )

    if (-not $AclEntries) { return 'MISSING' }

    $hit = $false
    foreach ($entry in $AclEntries) {
        # format is like: user:<guid>:rwx
        $parts = $entry -split ':'
        if ($parts.Length -lt 3) { continue }

        $entryType  = $parts[0]   # user / group / other / mask
        $entryId    = $parts[1]   # guid
        $entryPerms = $parts[2]   # rwx etc.

        if ($entryId -eq $ObjectId) {
            # Exact permission match – simple but good enough for now
            if ($entryPerms -eq $RequestedPerm) {
                return 'OK'
            } else {
                $hit = $true   # identity found but perms differ
            }
        }
    }

    if ($hit) { return 'MISSING' }
    return 'MISSING'
}

# --------------------------------------------------------------------
# RBAC for pipeline SPN – Storage Blob Data Owner
# --------------------------------------------------------------------
$pipelineSp = Get-AzADServicePrincipal -ApplicationId $ClientId -ErrorAction Stop
$pipelineSpObjectId = $pipelineSp.Id
Write-Host "DEBUG: Pipeline SPN ObjectId = $pipelineSpObjectId"

# Keep track of scopes where we successfully added role
$scopesWithRole = @()

# --------------------------------------------------------------------
# Main
# --------------------------------------------------------------------
$out = @()

$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
if ($subs -isnot [System.Collections.IEnumerable]) { $subs = ,$subs }

foreach ($sub in $subs) {
    Set-ScContext -Subscription $sub
    Write-Host "INFO: Subscription = $($sub.Name)"

    foreach ($r in $rows) {
        $rgName       = ($r.ResourceGroup -replace '<Custodian>', $adh_group)
        $saName       = ($r.Storage -replace '<Cust>', $adh_group.ToLower()) -replace '<Custodian>', $adh_group
        $cont         = ($r.Container -replace '<Cust>', $adh_group.ToLower())
        $identityName = ($r.Identity  -replace '<Custodian>', $adh_group)
        $permType     = $r.Permission

        # Build & ensure RBAC scope for this storage account
        $scope = "/subscriptions/$($sub.Id)/resourceGroups/$rgName/providers/Microsoft.Storage/storageAccounts/$saName"
        if ($scopesWithRole -notcontains $scope) {
            try {
                New-AzRoleAssignment -ObjectId $pipelineSpObjectId `
                                     -RoleDefinitionName "Storage Blob Data Owner" `
                                     -Scope $scope -ErrorAction Stop | Out-Null
                Write-Host ("INFO: Assigned 'Storage Blob Data Owner' to pipeline SPN at {0}" -f $scope)
            } catch {
                Write-Warning ("WARN: Failed to assign 'Storage Blob Data Owner' at {0} – {1}" -f $scope, $_.Exception.Message)
            }
            $scopesWithRole += $scope
        }

        # Get storage account
        try {
            $sa = Get-AzStorageAccount -ResourceGroupName $rgName -Name $saName -ErrorAction Stop
        } catch {
            $out += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $rgName
                Storage          = $saName
                Container        = $cont
                Folder           = $r.Folder
                Identity         = $identityName
                Permission       = $permType
                Status           = 'ERROR'
                Notes            = "Storage account error: $($_.Exception.Message)"
            }
            continue
        }

        $ctx = $sa.Context

        # Container
        try {
            $container = Get-AzStorageContainer -Name $cont -Context $ctx -ErrorAction Stop
        } catch {
            $out += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $rgName
                Storage          = $saName
                Container        = $cont
                Folder           = $r.Folder
                Identity         = $identityName
                Permission       = $permType
                Status           = 'ERROR'
                Notes            = "Container fetch error: $($_.Exception.Message)"
            }
            continue
        }

        # Path / folder
        $accessPathRaw = $r.Folder
        $accessPath    = $accessPathRaw -replace '<Custodian>', $adh_group
        $accessPath    = $accessPath    -replace '<Cust>', $adh_group.ToLower()

        if ($accessPath -match '^/?catalog') {
            if ($adh_group -eq 'KTK') {
                $accessPath = $accessPath -replace '^/?catalog', '/adh_ktk'
            } else {
                $accessPath = $accessPath -replace '^/?catalog', "/adh_$($adh_group.ToLower())"
            }
        }
        $accessPath = $accessPath -replace '/+', '/'

        if ([string]::IsNullOrWhiteSpace($accessPath)) {
            $pathsToCheck = @('')
        } else {
            $pathsToCheck = @($accessPath.TrimStart('/'))
        }

        foreach ($folderPath in $pathsToCheck) {
            $objectId = Resolve-IdentityObjectId -IdentityName $identityName
            if (-not $objectId) {
                $out += [pscustomobject]@{
                    SubscriptionName = $sub.Name
                    ResourceGroup    = $rgName
                    Storage          = $saName
                    Container        = $cont
                    Folder           = ($folderPath -eq '' ? '/' : $folderPath)
                    Identity         = $identityName
                    Permission       = $permType
                    Status           = 'ERROR'
                    Notes            = "Identity '$identityName' not found in Entra ID"
                }
                continue
            }

            try {
                $params = @{
                    FileSystem  = $cont
                    Context     = $ctx
                    ErrorAction = 'Stop'
                }
                if (-not [string]::IsNullOrWhiteSpace($folderPath)) {
                    $params['Path'] = $folderPath
                }

                $item      = Get-AzDataLakeGen2Item @params
                $aclStatus = Get-AclMatchStatus -AclEntries $item.Acl -ObjectId $objectId -RequestedPerm $permType
                $notes     = if ($aclStatus -eq 'OK') { 'Permissions match' } else { 'Permissions missing or mismatched' }
            } catch {
                $aclStatus = 'ERROR'
                $notes     = "ACL read error: $($_.Exception.Message)"
            }

            $out += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $rgName
                Storage          = $saName
                Container        = $cont
                Folder           = ($folderPath -eq '' ? '/' : $folderPath)
                Identity         = $identityName
                Permission       = $permType
                Status           = $aclStatus
                Notes            = $notes
            }
        }
    }
}

# --------------------------------------------------------------------
# Remove temporary RBAC assignments
# --------------------------------------------------------------------
foreach ($scope in $scopesWithRole) {
    try {
        $assignments = Get-AzRoleAssignment -ObjectId $pipelineSpObjectId `
                                            -RoleDefinitionName "Storage Blob Data Owner" `
                                            -Scope $scope -ErrorAction SilentlyContinue
        foreach ($a in $assignments) {
            Remove-AzRoleAssignment -RoleAssignmentId $a.Id -ErrorAction Stop
        }
        Write-Host ("INFO: Removed 'Storage Blob Data Owner' from pipeline SPN at {0}" -f $scope)
    } catch {
        Write-Warning ("WARN: Failed to remove 'Storage Blob Data Owner' at {0} – {1}" -f $scope, $_.Exception.Message)
    }
}

# --------------------------------------------------------------------
# Export
# --------------------------------------------------------------------
if (-not $out) {
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

$csvOut  = New-StampedPath -BaseDir $OutputDir -Prefix ("adls_validation_{0}_{1}" -f $adh_group, $adh_subscription_type)
Write-CsvSafe -Rows $out -Path $csvOut

$htmlOut = $csvOut -replace '\.csv$','.html'
Convert-CsvToHtml -CsvPath $csvOut -HtmlPath $htmlOut -Title "ADLS Validation ($adh_group / $adh_subscription_type) $BranchName"

Write-Host "ADLS validation completed." -ForegroundColor Green
Write-Host "CSV : $csvOut"
Write-Host "HTML: $htmlOut"
