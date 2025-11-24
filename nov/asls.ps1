param(
    [Parameter(Mandatory = $true)][string]$TenantId,
    [Parameter(Mandatory = $true)][string]$ClientId,
    [Parameter(Mandatory = $true)][string]$ClientSecret,
    [Parameter(Mandatory = $true)][string]$adh_group,
    [string]$adh_sub_group = '',
    [ValidateSet('nonprd','prd')][string]$adh_subscription_type = 'nonprd',
    [Parameter(Mandatory = $true)][string]$InputCsvPath,
    [Parameter(Mandatory = $true)][string]$OutputDir,
    [string]$BranchName = ''
)

# -------------------------------------------------------
# Imports
# -------------------------------------------------------
Import-Module Az.Accounts, Az.Resources, Az.Storage -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

Write-Host "DEBUG TenantId            : $TenantId"
Write-Host "DEBUG ClientId            : $ClientId"
Write-Host "DEBUG adh_group           : $adh_group"
Write-Host "DEBUG adh_sub_group       : $adh_sub_group"
Write-Host "DEBUG adh_subscription_type: $adh_subscription_type"
Write-Host "DEBUG InputCsvPath        : $InputCsvPath"
Write-Host "DEBUG OutputDir           : $OutputDir"
Write-Host "DEBUG BranchName          : $BranchName"

# -------------------------------------------------------
# Prep
# -------------------------------------------------------
Ensure-Dir -Path $OutputDir | Out-Null

if (-not (Test-Path -LiteralPath $InputCsvPath)) {
    throw "ADLS CSV not found: $InputCsvPath"
}

$rows = Import-Csv -LiteralPath $InputCsvPath

if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure connection failed."
}

# -------------------------------------------------------
# Placeholder logic
# -------------------------------------------------------
# Custodian: used where CSV has <Custodian>
#   - if adh_sub_group empty -> "KTK"
#   - else -> "KTK_PLT"
$Custodian = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) {
    $adh_group
} else {
    "${adh_group}_${adh_sub_group}"
}

# <Cust>: used where CSV has <Cust> (storage account name adh<Cust>adlsnonprd)
#   - if adh_sub_group empty      -> "ktk"
#   - if adh_sub_group NOT empty  -> "ktkplt" (no underscore, all lower)
$CustLower = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) {
    $adh_group.ToLower()
} else {
    ($adh_group + $adh_sub_group).ToLower()
}

Write-Host "DEBUG Resolved Custodian : $Custodian"
Write-Host "DEBUG Resolved <Cust>    : $CustLower"

# -------------------------------------------------------
# Identity lookup cache
# -------------------------------------------------------
$script:IdentityCache = @{}

function Resolve-IdentityObjectId {
    param(
        [Parameter(Mandatory = $true)][string]$IdentityName
    )

    if ($script:IdentityCache.ContainsKey($IdentityName)) {
        return $script:IdentityCache[$IdentityName]
    }

    $id = $null

    # Try Entra ID group
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

    # Try SPN by search string
    if (-not $id) {
        try {
            $sp2 = Get-AzADServicePrincipal -SearchString $IdentityName -ErrorAction Stop
            if ($sp2 -and $sp2.Count -ge 1) { $id = $sp2[0].Id }
        } catch { }
    }

    # If the string itself looks like a GUID, accept it directly
    if (-not $id) {
        if ($IdentityName -match '^[0-9a-fA-F-]{36}$') {
            $id = $IdentityName
        }
    }

    $script:IdentityCache[$IdentityName] = $id
    return $id
}

# -------------------------------------------------------
# Get pipeline SPN objectId (for temporary Blob Data Owner)
# -------------------------------------------------------
$pipelineSp = Get-AzADServicePrincipal -ApplicationId $ClientId -ErrorAction Stop
$pipelineSpObjectId = $pipelineSp.Id
Write-Host "DEBUG Pipeline SPN ObjectId: $pipelineSpObjectId"

# -------------------------------------------------------
# Main scan
# -------------------------------------------------------
$out  = @()
$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
if ($subs -isnot [System.Collections.IEnumerable]) { $subs = ,$subs }

foreach ($sub in $subs) {
    Set-ScContext -Subscription $sub
    Write-Host "INFO: Running ADLS ACL validation in subscription '$($sub.Name)'."

    foreach ($r in $rows) {

        # ----- Resolve placeholders in names -----
        $rgName = ($r.ResourceGroupName  -replace '<Custodian>', $Custodian)

        $saName = $r.StorageAccountName
        $saName = $saName -replace '<Cust>',      $CustLower
        $saName = $saName -replace '<Custodian>', $Custodian

        $containerName = $r.ContainerName
        $containerName = $containerName -replace '<Cust>',      $CustLower
        $containerName = $containerName -replace '<Custodian>', $Custodian

        $identityName = ($r.Identity -replace '<Custodian>', $Custodian)

        $permType = $r.PermissionType   # e.g. r-x / rwx

        if ([string]::IsNullOrWhiteSpace($rgName) -or
            [string]::IsNullOrWhiteSpace($saName) -or
            [string]::IsNullOrWhiteSpace($containerName)) {

            $out += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $rgName
                Storage          = $saName
                Container        = $containerName
                Folder           = ''
                Identity         = $identityName
                Permission       = $permType
                Status           = 'ERROR'
                Notes            = 'Name resolution produced empty ResourceGroup / Storage / Container.'
            }
            continue
        }

        # ----- Resolve storage account -----
        try {
            $sa = Get-AzStorageAccount -ResourceGroupName $rgName -Name $saName -ErrorAction Stop
        } catch {
            $out += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $rgName
                Storage          = $saName
                Container        = $containerName
                Folder           = ''
                Identity         = $identityName
                Permission       = $permType
                Status           = 'ERROR'
                Notes            = "Storage account error: $($_.Exception.Message)"
            }
            continue
        }

        $ctx   = $sa.Context
        $scope = $sa.Id

        # ----- Temporarily assign Storage Blob Data Owner -----
        $roleAssigned = $false
        try {
            New-AzRoleAssignment `
                -ObjectId $pipelineSpObjectId `
                -RoleDefinitionName "Storage Blob Data Owner" `
                -Scope $scope `
                -ErrorAction Stop | Out-Null
            $roleAssigned = $true
            Write-Host "INFO: Blob Data Owner assigned on scope $scope"
        } catch {
            Write-Warning ("Failed to assign Storage Blob Data Owner on scope {0}: {1}" -f $scope, $_.Exception.Message)
        }

        # ----- AccessPath placeholder handling -----
        $accessPathRaw = $r.AccessPath
        $accessPath    = $accessPathRaw -replace '<Custodian>', $Custodian
        $accessPath    = $accessPath    -replace '<Cust>',      $CustLower

        # "catalog" prefix becomes /adh_<lower adh_group>
        if ($accessPath -match '^/?catalog') {
            $prefix = "/adh_$($adh_group.ToLower())"
            $accessPath = $accessPath -replace '^/?catalog', $prefix
        }

        # Normalize slashes
        $accessPath = $accessPath -replace '/+', '/'

        # Determine which path(s) to check
        $pathsToCheck = @()
        if ([string]::IsNullOrWhiteSpace($accessPath)) {
            # Root folder of container
            $pathsToCheck += ""
        } else {
            $pathsToCheck += $accessPath.TrimStart("/")
        }

        # ----- Identity resolution -----
        $objectId = Resolve-IdentityObjectId -IdentityName $identityName
        if (-not $objectId) {
            foreach ($folderPath in $pathsToCheck) {
                $out += [pscustomobject]@{
                    SubscriptionName = $sub.Name
                    ResourceGroup    = $rgName
                    Storage          = $saName
                    Container        = $containerName
                    Folder           = ($folderPath -eq "" ? "/" : $folderPath)
                    Identity         = $identityName
                    Permission       = $permType
                    Status           = 'ERROR'
                    Notes            = "Identity '$identityName' not found in Entra ID"
                }
            }

            # Cleanup role if we managed to assign it
            if ($roleAssigned) {
                try {
                    Remove-AzRoleAssignment `
                        -ObjectId $pipelineSpObjectId `
                        -RoleDefinitionName "Storage Blob Data Owner" `
                        -Scope $scope `
                        -ErrorAction Stop | Out-Null
                    Write-Host "INFO: Blob Data Owner removed on scope $scope"
                } catch {
                    Write-Warning ("Failed to remove Storage Blob Data Owner on scope {0}: {1}" -f $scope, $_.Exception.Message)
                }
            }
            continue
        }

        # ----- Check ACLs for each path -----
        foreach ($folderPath in $pathsToCheck) {

            try {
                $params = @{
                    FileSystem  = $containerName
                    Context     = $ctx
                    ErrorAction = 'Stop'
                }
                if (-not [string]::IsNullOrWhiteSpace($folderPath)) {
                    $params['Path'] = $folderPath
                }

                $item = Get-AzDataLakeGen2Item @params
                $aclEntries = $item.Acl

                # ACL strings look like: "user:objectId:rwx" / "group:objectId:r-x"
                $matchEntry = $aclEntries | Where-Object {
                    ($_ -match [regex]::Escape($objectId)) -and
                    ($_ -match [regex]::Escape($permType))
                }

                if ($matchEntry) {
                    $status = 'OK'
                    $notes  = 'Permissions match'
                } else {
                    $status = 'MISSING'
                    $notes  = 'Permissions missing or mismatched'
                }

            } catch {
                $status = 'ERROR'
                $notes  = "ACL read error: $($_.Exception.Message)"
            }

            $out += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $rgName
                Storage          = $saName
                Container        = $containerName
                Folder           = ($folderPath -eq "" ? "/" : $folderPath)
                Identity         = $identityName
                Permission       = $permType
                Status           = $status
                Notes            = $notes
            }
        }

        # ----- Remove temporary Blob Data Owner -----
        if ($roleAssigned) {
            try {
                Remove-AzRoleAssignment `
                    -ObjectId $pipelineSpObjectId `
                    -RoleDefinitionName "Storage Blob Data Owner" `
                    -Scope $scope `
                    -ErrorAction Stop | Out-Null
                Write-Host "INFO: Blob Data Owner removed on scope $scope"
            } catch {
                Write-Warning ("Failed to remove Storage Blob Data Owner on scope {0}: {1}" -f $scope, $_.Exception.Message)
            }
        }
    } # rows
} # subs

# -------------------------------------------------------
# Output
# -------------------------------------------------------
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
            Notes            = 'Nothing matched in scan'
        }
    )
}

$csvOut  = New-StampedPath -BaseDir $OutputDir -Prefix ("adls_validation_{0}_{1}" -f $adh_group, $adh_subscription_type)
Write-CsvSafe -Rows $out -Path $csvOut

$htmlOut = $csvOut -replace '\.csv$','.html'
Convert-CsvToHtml -CsvPath $csvOut -HtmlPath $htmlOut -Title "ADLS Validation ($adh_group / $adh_subscription_type) $BranchName"

Write-Host "ADLS validation completed." -ForegroundColor Green
Write-Host "CSV  : $csvOut"
Write-Host "HTML : $htmlOut"
