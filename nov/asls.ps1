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

# ----------------------------------------------------------------------
# Get pipeline SPN objectId (used for temporary RBAC on Storage Accounts)
# ----------------------------------------------------------------------
$pipelineSp = Get-AzADServicePrincipal -ApplicationId $ClientId -ErrorAction Stop
$pipelineSpObjectId = $pipelineSp.Id
Write-Host "Pipeline SPN ObjectId: $pipelineSpObjectId"

$script:IdentityCache = @{}

function Resolve-IdentityObjectId {
    param([Parameter(Mandatory = $true)][string]$IdentityName)

    if ($script:IdentityCache.ContainsKey($IdentityName)) {
        return $script:IdentityCache[$IdentityName]
    }

    $id = $null

    try {
        $grp = Get-AzADGroup -DisplayName $IdentityName -ErrorAction Stop
        if ($grp -and $grp.Id) { $id = $grp.Id }
    } catch {}

    if (-not $id) {
        try {
            $sp = Get-AzADServicePrincipal -DisplayName $IdentityName -ErrorAction Stop
            if ($sp -and $sp.Id) { $id = $sp.Id }
        } catch {}
    }

    if (-not $id) {
        try {
            $sp2 = Get-AzADServicePrincipal -SearchString $IdentityName -ErrorAction Stop
            if ($sp2 -and $sp2.Count -ge 1) { $id = $sp2[0].Id }
        } catch {}
    }

    if (-not $id) {
        $guidRef = [ref]([Guid]::Empty)
        if ([Guid]::TryParse($IdentityName, $guidRef)) {
            $id = $IdentityName
        }
    }

    $script:IdentityCache[$IdentityName] = $id
    return $id
}

# Helper: does an actual permission satisfy an expected one?
# e.g. expected r-x is OK with actual rwx (superset)
function Test-PermissionMatch {
    param(
        [Parameter(Mandatory = $true)][string]$Actual,
        [Parameter(Mandatory = $true)][string]$Expected
    )

    if ([string]::IsNullOrWhiteSpace($Actual) -or [string]::IsNullOrWhiteSpace($Expected)) {
        return $false
    }

    if ($Actual.Length -ne 3 -or $Expected.Length -ne 3) {
        return $false
    }

    for ($i = 0; $i -lt 3; $i++) {
        $e = $Expected[$i]
        $a = $Actual[$i]
        if ($e -ne '-' -and $a -ne $e) {
            return $false
        }
    }
    return $true
}

$out = @()
$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
if ($subs -isnot [System.Collections.IEnumerable]) { $subs = ,$subs }

foreach ($sub in $subs) {
    Set-ScContext -Subscription $sub
    Write-Host "Processing subscription: $($sub.Name) [$($sub.Id)]"

    # track which storage accounts we gave temporary role on (per subscription)
    $assignedScopes = @()

    foreach ($r in $rows) {

        $rgName       = ($r.ResourceGroupName  -replace '<Custodian>', $adh_group)
        $saName       = ($r.StorageAccountName -replace '<Cust>', $adh_group.ToLower()) -replace '<Custodian>', $adh_group
        $cont         = ($r.ContainerName      -replace '<Cust>', $adh_group.ToLower())
        $identityName = ($r.Identity           -replace '<Custodian>', $adh_group)
        $permType     = $r.PermissionType

        # ---- storage account ----
        try {
            $sa = Get-AzStorageAccount -ResourceGroupName $rgName -Name $saName -ErrorAction Stop
        } catch {
            $out += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $rgName
                Storage          = $saName
                Container        = $cont
                Folder           = ''
                Identity         = $identityName
                PermissionType   = $permType
                Status           = 'ERROR'
                Notes            = "Storage Account error: $($_.Exception.Message)"
            }
            continue
        }

        # ---- temporary RBAC: Storage Blob Data Owner on that Storage Account ----
        $scope = $sa.Id
        if ($assignedScopes -notcontains $scope) {
            try {
                New-AzRoleAssignment -ObjectId $pipelineSpObjectId `
                                     -RoleDefinitionName 'Storage Blob Data Owner' `
                                     -Scope $scope `
                                     -ErrorAction Stop | Out-Null
                Write-Host "Assigned Storage Blob Data Owner on $scope to pipeline SPN."
            } catch {
                if ($_.Exception.Message -notmatch 'The role assignment already exists') {
                    Write-Warning "Failed to assign Storage Blob Data Owner on $scope: $($_.Exception.Message)"
                }
            }
            $assignedScopes += $scope
        }

        $ctx = $sa.Context

        # ---- container ----
        try {
            $container = Get-AzStorageContainer -Name $cont -Context $ctx -ErrorAction Stop
        } catch {
            $out += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $rgName
                Storage          = $saName
                Container        = $cont
                Folder           = ''
                Identity         = $identityName
                PermissionType   = $permType
                Status           = 'ERROR'
                Notes            = "Container fetch error: $($_.Exception.Message)"
            }
            continue
        }

        # ---- AccessPath / folder handling ----
        $accessPathRaw = $r.AccessPath
        $accessPath = $accessPathRaw -replace '<Custodian>', $adh_group
        $accessPath = $accessPath  -replace '<Cust>', $adh_group.ToLower()

        if ($accessPath -match '^/?catalog') {
            if ($adh_group -eq 'KTK') {
                $accessPath = $accessPath -replace '^/?catalog', '/adh_ktk'
            } else {
                $accessPath = $accessPath -replace '^/?catalog', "/adh_$($adh_group.ToLower())"
            }
        }

        $accessPath = $accessPath -replace '/+', '/'

        $pathsToCheck = @()
        if ([string]::IsNullOrWhiteSpace($accessPath)) {
            $pathsToCheck += ""
        } else {
            $pathsToCheck += $accessPath.TrimStart("/")
        }

        foreach ($folderPath in $pathsToCheck) {

            $objectId = Resolve-IdentityObjectId -IdentityName $identityName
            if (-not $objectId) {
                $out += [pscustomobject]@{
                    SubscriptionName = $sub.Name
                    ResourceGroup    = $rgName
                    Storage          = $saName
                    Container        = $cont
                    Folder           = ($folderPath -eq "" ? "/" : $folderPath)
                    Identity         = $identityName
                    PermissionType   = $permType
                    Status           = 'ERROR'
                    Notes            = "Identity '$identityName' not found in Entra ID"
                }
                continue
            }

            try {
                $params = @{ FileSystem = $cont; Context = $ctx; ErrorAction = 'Stop' }
                if (-not [string]::IsNullOrWhiteSpace($folderPath)) {
                    $params['Path'] = $folderPath
                }

                $item = Get-AzDataLakeGen2Item @params

                # Acl is a string like: "user::rwx,group::r-x,other::---,user:<guid>:r-x,mask::rwx"
                $aclEntries = @()
                if ($item.Acl) {
                    $aclEntries = $item.Acl -split ','
                }

                $parsedAcl = $aclEntries | ForEach-Object {
                    $parts = $_.Split(':')
                    [pscustomobject]@{
                        Type        = $parts[0]              # user / group / other / mask
                        Id          = if ($parts.Count -ge 3) { $parts[1] } else { '' }
                        Permissions = $parts[$parts.Count-1] # rwx/r-x/---
                    }
                }

                $matchEntry = $parsedAcl | Where-Object {
                    $_.Id -eq $objectId -and (Test-PermissionMatch -Actual $_.Permissions -Expected $permType)
                }

                if ($matchEntry) {
                    $permStatus = 'OK'
                    $permNotes  = 'Permissions match (or exceed) expected'
                } else {
                    $permStatus = 'MISSING'
                    $permNotes  = 'Permissions missing or mismatched'
                }

            } catch {
                $permStatus = 'ERROR'
                $permNotes  = "ACL read error: $($_.Exception.Message)"
            }

            $out += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $rgName
                Storage          = $saName
                Container        = $cont
                Folder           = ($folderPath -eq "" ? "/" : $folderPath)
                Identity         = $identityName
                PermissionType   = $permType
                Status           = $permStatus
                Notes            = $permNotes
            }
        }
    }

    # ------------------------------------------------------------------
    # Revoke temporary "Storage Blob Data Owner" assignments for this sub
    # ------------------------------------------------------------------
    foreach ($scope in $assignedScopes | Select-Object -Unique) {
        try {
            Remove-AzRoleAssignment -ObjectId $pipelineSpObjectId `
                                    -RoleDefinitionName 'Storage Blob Data Owner' `
                                    -Scope $scope `
                                    -ErrorAction Stop | Out-Null
            Write-Host "Revoked Storage Blob Data Owner on $scope from pipeline SPN."
        } catch {
            Write-Warning "Failed to remove Storage Blob Data Owner on $scope: $($_.Exception.Message)"
        }
    }
}

if (-not $out) {
    $out += [pscustomobject]@{
        SubscriptionName = ''
        ResourceGroup    = ''
        Storage          = ''
        Container        = ''
        Folder           = ''
        Identity         = ''
        PermissionType   = ''
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
