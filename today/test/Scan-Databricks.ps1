# sanitychecks/scripts/Scan-Databricks.ps1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$ClientId,
    [Parameter(Mandatory)][string]$ClientSecret,
    [Parameter(Mandatory)][string]$adh_group,
    [ValidateSet('nonprd','prd')][string]$adh_subscription_type = 'nonprd',
    [Parameter(Mandatory)][string]$OutputDir,
    [Parameter(Mandatory)][string]$DatabricksPat,   # PAT / token
    [string]$BranchName = ''
)

Import-Module Az.Accounts, Az.Resources, Az.Databricks -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1')           -Force -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'DatabricksHelper.psm1') -Force -ErrorAction Stop

$OutputDir = Ensure-Dir -Path $OutputDir

# -------------------------------------------------------------------
# 1. Connect Azure and resolve subscriptions + envs + workspace names
# -------------------------------------------------------------------
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure connection failed."
}

$subs        = Resolve-DbSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
$envsToCheck = Get-DbEnvsForType       -Environment $adh_subscription_type
$wsNames     = Get-DbWorkspaceNames    -AdhGroup $adh_group -Environment $adh_subscription_type

Write-Host "DEBUG: adh_group        = $adh_group"
Write-Host "DEBUG: subscriptionType = $adh_subscription_type"
Write-Host "DEBUG: envsToCheck      = $($envsToCheck -join ', ')"
Write-Host "DEBUG: expectedWsNames  = $($wsNames -join ', ')"

# -------------------------------------------------------------------
# 2. Result buckets
# -------------------------------------------------------------------
$workspaceResults     = @()
$workspacePermResults = @()
$sqlWhResults         = @()
$sqlWhPermResults     = @()
$catalogListResults   = @()
$catalogPermResults   = @()
$extLocResults        = @()
$extLocPermResults    = @()

# -------------------------------------------------------------------
# 3. Loop subscriptions / envs / workspaces
# -------------------------------------------------------------------
foreach ($sub in $subs) {
    Write-Host "Processing subscription: $($sub.Name)" -ForegroundColor Yellow
    Set-ScContext -Subscription $sub

    $azWorkspaces = Get-AzDatabricksWorkspace -ErrorAction SilentlyContinue

    foreach ($env in $envsToCheck) {

        $expectedWsName = switch ($env) {
            'dev' { "ADH_$($adh_group.ToUpper())_dev" }
            'tst' { "ADH_$($adh_group.ToUpper())_tst" }
            'stg' { "ADH_$($adh_group.ToUpper())_stg" }
            'prd' { "ADH_$($adh_group.ToUpper())_prd" }
        }

        $ws = $azWorkspaces | Where-Object { $_.Name -eq $expectedWsName }

        if (-not $ws) {
            # No workspace for that env in this subscription
            $workspaceResults += [pscustomobject]@{
                SubscriptionName = $sub.Name
                SubscriptionId   = $sub.Id
                Env              = $env
                WorkspaceName    = $expectedWsName
                WorkspaceUrl     = ''
                State            = 'Missing'
                Location         = ''
                adh_group        = $adh_group
                BranchName       = $BranchName
            }
            continue
        }

        $workspaceUrl = $ws.WorkspaceUrl

        # -----------------------------
        # 3.1 Workspace basic inventory
        # -----------------------------
        $workspaceResults += [pscustomobject]@{
            SubscriptionName = $sub.Name
            SubscriptionId   = $sub.Id
            Env              = $env
            WorkspaceName    = $ws.Name
            WorkspaceUrl     = $workspaceUrl
            State            = $ws.ProvisioningState
            Location         = $ws.Location
            adh_group        = $adh_group
            BranchName       = $BranchName
        }

        # ------------------------------------------------
        # 3.2 Workspace permissions (flatten full ACL list)
        # ------------------------------------------------
        try {
            $wsPermsRaw = Get-DbWorkspacePermissions -WorkspaceUrl $workspaceUrl -DatabricksPat $DatabricksPat
            foreach ($ace in $wsPermsRaw.access_control_list) {
                # figure out which field actually has the name
                $principalName = $null
                $principalType = $null

                if ($ace.user_name) {
                    $principalName = $ace.user_name
                    $principalType = 'user'
                } elseif ($ace.group_name) {
                    $principalName = $ace.group_name
                    $principalType = 'group'
                } elseif ($ace.service_principal_name) {
                    $principalName = $ace.service_principal_name
                    $principalType = 'service_principal'
                }

                foreach ($p in $ace.all_permissions) {
                    $workspacePermResults += [pscustomobject]@{
                        SubscriptionName = $sub.Name
                        SubscriptionId   = $sub.Id
                        Env              = $env
                        WorkspaceName    = $ws.Name
                        PrincipalType    = $principalType
                        PrincipalName    = $principalName
                        PermissionLevel  = $p.permission_level
                        Inherited        = $p.inherited
                        adh_group        = $adh_group
                    }
                }
            }
        } catch {
            Write-Warning "Workspace permissions failed for $($ws.Name): $($_.Exception.Message)"
        }

        # --------------------------------------------------------
        # 3.3 SQL Warehouses (list + permissions per warehouse)
        # --------------------------------------------------------
        try {
            $whRaw      = Get-DbWarehouses -WorkspaceUrl $workspaceUrl -DatabricksPat $DatabricksPat
            $warehouses = $whRaw.warehouses

            foreach ($wh in $warehouses) {
                # basic info
                $sqlWhResults += [pscustomobject]@{
                    SubscriptionName = $sub.Name
                    SubscriptionId   = $sub.Id
                    Env              = $env
                    WorkspaceName    = $ws.Name
                    WarehouseId      = $wh.id
                    WarehouseName    = $wh.name
                    ClusterSize      = $wh.cluster_size
                    State            = $wh.state
                    AutoStopMinutes  = $wh.auto_stop_mins
                    Tags             = ($wh.tags | ConvertTo-Json -Compress)
                    adh_group        = $adh_group
                }

                # permissions
                try {
                    $permRaw = Get-DbWarehousePermissions -WorkspaceUrl $workspaceUrl -WarehouseId $wh.id -DatabricksPat $DatabricksPat
                    foreach ($ace in $permRaw.access_control_list) {
                        $principalName = $null
                        $principalType = $null

                        if ($ace.user_name) {
                            $principalName = $ace.user_name
                            $principalType = 'user'
                        } elseif ($ace.group_name) {
                            $principalName = $ace.group_name
                            $principalType = 'group'
                        } elseif ($ace.service_principal_name) {
                            $principalName = $ace.service_principal_name
                            $principalType = 'service_principal'
                        }

                        foreach ($p in $ace.all_permissions) {
                            $sqlWhPermResults += [pscustomobject]@{
                                SubscriptionName = $sub.Name
                                SubscriptionId   = $sub.Id
                                Env              = $env
                                WorkspaceName    = $ws.Name
                                WarehouseId      = $wh.id
                                WarehouseName    = $wh.name
                                PrincipalType    = $principalType
                                PrincipalName    = $principalName
                                PermissionLevel  = $p.permission_level
                                Inherited        = $p.inherited
                                adh_group        = $adh_group
                            }
                        }
                    }
                } catch {
                    Write-Warning "SQL Warehouse permissions failed for $($wh.name): $($_.Exception.Message)"
                }
            }
        } catch {
            Write-Warning "SQL Warehouses listing failed for workspace $($ws.Name): $($_.Exception.Message)"
        }

        # ------------------------------------------------------
        # 3.4 Unity Catalog – list catalogs & catalog privileges
        # ------------------------------------------------------
        try {
            $catRaw  = Get-DbCatalogsList -WorkspaceUrl $workspaceUrl -DatabricksPat $DatabricksPat
            $catalogs = $catRaw.catalogs

            foreach ($cat in $catalogs) {
                $catalogListResults += [pscustomobject]@{
                    SubscriptionName = $sub.Name
                    SubscriptionId   = $sub.Id
                    Env              = $env
                    WorkspaceName    = $ws.Name
                    CatalogName      = $cat.name
                    CatalogType      = $cat.catalog_type
                    Comment          = $cat.comment
                    Properties       = ($cat.properties | ConvertTo-Json -Compress)
                    adh_group        = $adh_group
                }

                # permissions per catalog
                try {
                    $permRaw = Get-DbCatalogPermissions -WorkspaceUrl $workspaceUrl -CatalogName $cat.name -DatabricksPat $DatabricksPat
                    foreach ($entry in $permRaw.privilege_assignments) {
                        $catalogPermResults += [pscustomobject]@{
                            SubscriptionName = $sub.Name
                            SubscriptionId   = $sub.Id
                            Env              = $env
                            WorkspaceName    = $ws.Name
                            CatalogName      = $cat.name
                            PrincipalName    = $entry.principal
                            Privileges       = ($entry.privileges -join ',')
                            adh_group        = $adh_group
                        }
                    }
                } catch {
                    Write-Warning "Catalog permissions failed for $($cat.name): $($_.Exception.Message)"
                }
            }
        } catch {
            Write-Warning "Catalog listing failed for workspace $($ws.Name): $($_.Exception.Message)"
        }

        # ------------------------------------------------------
        # 3.5 External locations + permissions
        # ------------------------------------------------------
        try {
            $extRaw   = Get-DbExternalLocationsList -WorkspaceUrl $workspaceUrl -DatabricksPat $DatabricksPat
            $extLocs  = $extRaw.external_locations

            foreach ($loc in $extLocs) {
                $extLocResults += [pscustomobject]@{
                    SubscriptionName = $sub.Name
                    SubscriptionId   = $sub.Id
                    Env              = $env
                    WorkspaceName    = $ws.Name
                    ExternalLocation = $loc.name
                    Url              = $loc.url
                    CredentialName   = $loc.credential_name
                    Comment          = $loc.comment
                    adh_group        = $adh_group
                }

                # permissions for each external location
                try {
                    $permRaw = Get-DbExternalLocationPermissions -WorkspaceUrl $workspaceUrl -Name $loc.name -DatabricksPat $DatabricksPat
                    foreach ($entry in $permRaw.privilege_assignments) {
                        $extLocPermResults += [pscustomobject]@{
                            SubscriptionName = $sub.Name
                            SubscriptionId   = $sub.Id
                            Env              = $env
                            WorkspaceName    = $ws.Name
                            ExternalLocation = $loc.name
                            PrincipalName    = $entry.principal
                            Privileges       = ($entry.privileges -join ',')
                            adh_group        = $adh_group
                        }
                    }
                } catch {
                    Write-Warning "External location permissions failed for $($loc.name): $($_.Exception.Message)"
                }
            }
        } catch {
            Write-Warning "External locations listing failed for workspace $($ws.Name): $($_.Exception.Message)"
        }
    } # env loop
} # sub loop

# -------------------------------------------------------------------
# 4. Write outputs (CSV + one HTML for workspace overview)
# -------------------------------------------------------------------
$csvWs = New-StampedPath -BaseDir $OutputDir -Prefix ("db_ws_{0}_{1}" -f $adh_group, $adh_subscription_type)
Write-CsvSafe -Rows $workspaceResults -Path $csvWs
Convert-CsvToHtml -CsvPath $csvWs -HtmlPath ($csvWs -replace '\.csv$','.html') `
    -Title "Databricks Workspaces ($adh_group / $adh_subscription_type) $BranchName"

$csvWsPerm = New-StampedPath -BaseDir $OutputDir -Prefix ("db_ws_perms_{0}_{1}" -f $adh_group, $adh_subscription_type)
Write-CsvSafe -Rows $workspacePermResults -Path $csvWsPerm

$csvWh = New-StampedPath -BaseDir $OutputDir -Prefix ("db_sqlwh_{0}_{1}" -f $adh_group, $adh_subscription_type)
Write-CsvSafe -Rows $sqlWhResults -Path $csvWh

$csvWhPerm = New-StampedPath -BaseDir $OutputDir -Prefix ("db_sqlwh_perms_{0}_{1}" -f $adh_group, $adh_subscription_type)
Write-CsvSafe -Rows $sqlWhPermResults -Path $csvWhPerm

$csvCatList = New-StampedPath -BaseDir $OutputDir -Prefix ("db_catalogs_{0}_{1}" -f $adh_group, $adh_subscription_type)
Write-CsvSafe -Rows $catalogListResults -Path $csvCatList

$csvCatPerm = New-StampedPath -BaseDir $OutputDir -Prefix ("db_catalog_perms_{0}_{1}" -f $adh_group, $adh_subscription_type)
Write-CsvSafe -Rows $catalogPermResults -Path $csvCatPerm

$csvExt = New-StampedPath -BaseDir $OutputDir -Prefix ("db_extloc_{0}_{1}" -f $adh_group, $adh_subscription_type)
Write-CsvSafe -Rows $extLocResults -Path $csvExt

$csvExtPerm = New-StampedPath -BaseDir $OutputDir -Prefix ("db_extloc_perms_{0}_{1}" -f $adh_group, $adh_subscription_type)
Write-CsvSafe -Rows $extLocPermResults -Path $csvExtPerm

Write-Host "Databricks inventory scan completed." -ForegroundColor Green
Write-Host "Workspace CSV          : $csvWs"
Write-Host "Workspace perms CSV    : $csvWsPerm"
Write-Host "SQL Warehouses CSV     : $csvWh"
Write-Host "SQL Warehouse perms    : $csvWhPerm"
Write-Host "Catalog list CSV       : $csvCatList"
Write-Host "Catalog perms CSV      : $csvCatPerm"
Write-Host "External locations CSV : $csvExt"
Write-Host "Ext loc perms CSV      : $csvExtPerm"
