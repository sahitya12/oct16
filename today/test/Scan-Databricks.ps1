# sanitychecks/scripts/Scan-Databricks.ps1

param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$ClientId,
    [Parameter(Mandatory)][string]$ClientSecret,
    [Parameter(Mandatory)][string]$adh_group,
    [ValidateSet('nonprd','prd')][string]$adh_subscription_type = 'nonprd',
    [Parameter(Mandatory)][string]$InputConfigPath,   # Excel template
    [Parameter(Mandatory)][string]$OutputDir,
    [Parameter(Mandatory)][string]$DatabricksPat,     # PAT or token
    [string]$BranchName = ''
)

Import-Module Az.Accounts, Az.Resources, Az.Databricks -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1')          -Force -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'DatabricksHelper.psm1')-Force -ErrorAction Stop
Import-Module ImportExcel -ErrorAction Stop

$OutputDir = Ensure-Dir $OutputDir

# 1. Connect Azure and resolve subscriptions
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure connection failed."
}

$subs        = Resolve-DbSubscriptions  -AdhGroup $adh_group -Environment $adh_subscription_type
$envsToCheck = Get-DbEnvsForType        -Environment $adh_subscription_type
$wsNames     = Get-DbWorkspaceNames     -AdhGroup $adh_group  -Environment $adh_subscription_type

Write-Host "Will scan envs: $($envsToCheck -join ', ')" -ForegroundColor Cyan
Write-Host "Expected workspace names: $($wsNames -join ', ')" -ForegroundColor Cyan

# 2. Read Excel config
$workspacePermsCfg        = Import-Excel -Path $InputConfigPath -WorksheetName 'workspace_perms'
$clusterPermsCfg          = Import-Excel -Path $InputConfigPath -WorksheetName 'cluster_perms'
$sqlWarehousePermsCfg     = Import-Excel -Path $InputConfigPath -WorksheetName 'sql_warehouse_perms'
$catalogPermsCfg          = Import-Excel -Path $InputConfigPath -WorksheetName 'catalog_perms'
$externalLocationsCfg     = Import-Excel -Path $InputConfigPath -WorksheetName 'external_locations'
$externalLocationPermsCfg = Import-Excel -Path $InputConfigPath -WorksheetName 'external_location_perms'
$adminSettingsCfg         = Import-Excel -Path $InputConfigPath -WorksheetName 'admin_settings'

# 3. Results buckets
$workspaceResults     = @()
$workspacePermResults = @()
$clusterPermResults   = @()
$sqlWhPermResults     = @()
$catalogPermResults   = @()
$extLocResults        = @()
$extLocPermResults    = @()
$adminResults         = @()

# 4. Per subscription / per env
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
            $workspaceResults += [pscustomobject]@{
                SubscriptionName    = $sub.Name
                SubscriptionId      = $sub.Id
                Env                 = $env
                WorkspaceName       = $expectedWsName
                WorkspaceUrl        = ''
                State               = 'Missing'
                Location            = ''
                adh_group           = $adh_group
                BranchName          = $BranchName
            }
            continue
        }

        $workspaceUrl = $ws.WorkspaceUrl

        $workspaceResults += [pscustomobject]@{
            SubscriptionName    = $sub.Name
            SubscriptionId      = $sub.Id
            Env                 = $env
            WorkspaceName       = $ws.Name
            WorkspaceUrl        = $workspaceUrl
            State               = $ws.ProvisioningState
            Location            = $ws.Location
            adh_group           = $adh_group
            BranchName          = $BranchName
        }

        # -------------------
        # 4.1 Workspace perms
        # -------------------
        $wsPermsRaw = Get-DbWorkspacePermissions -WorkspaceUrl $workspaceUrl -DatabricksPat $DatabricksPat
        $wsAcl      = $wsPermsRaw.access_control_list

        foreach ($cfg in $workspacePermsCfg | Where-Object { $_.env -eq $env -and $_.component_type -eq 'Workspace' }) {
            $principalTemplate = $cfg.principal_template
            $expectedPerm      = $cfg.expected_permission
            $principalName     = $principalTemplate -replace '<<cust>>', $adh_group.ToUpper()

            $actualPerm = $null
            foreach ($ace in $wsAcl) {
                if ($ace.user_name -eq $principalName -or
                    $ace.group_name -eq $principalName -or
                    $ace.service_principal_name -eq $principalName) {

                    $actualPerm = $ace.all_permissions[0].permission_level
                    break
                }
            }

            $status = if (-not $actualPerm) { 'PrincipalMissing' }
                      elseif ($actualPerm -eq $expectedPerm) { 'OK' }
                      else { 'Mismatch' }

            $workspacePermResults += [pscustomobject]@{
                SubscriptionName    = $sub.Name
                SubscriptionId      = $sub.Id
                Env                 = $env
                WorkspaceName       = $ws.Name
                PrincipalName       = $principalName
                ExpectedPermission  = $expectedPerm
                ActualPermission    = $actualPerm
                Status              = $status
                adh_group           = $adh_group
                BranchName          = $BranchName
            }
        }

        # -------------------
        # 4.2 Cluster (APC) perms
        # -------------------
        $clustersRaw = Get-DbClusters -WorkspaceUrl $workspaceUrl -DatabricksPat $DatabricksPat
        $clusters    = $clustersRaw.clusters

        foreach ($cfg in $clusterPermsCfg | Where-Object { $_.env -eq $env }) {
            $pattern   = $cfg.cluster_name_pattern
            $principal = ($cfg.principal_template -replace '<<cust>>', $adh_group.ToUpper())
            $expected  = $cfg.expected_permission

            $matchedClusters = $clusters | Where-Object { $_.cluster_name -like $pattern }

            if (-not $matchedClusters) {
                $clusterPermResults += [pscustomobject]@{
                    SubscriptionName = $sub.Name
                    SubscriptionId   = $sub.Id
                    Env              = $env
                    WorkspaceName    = $ws.Name
                    ClusterName      = $pattern
                    PrincipalName    = $principal
                    ExpectedPerm     = $expected
                    ActualPerm       = ''
                    Status           = 'ClusterMissing'
                    adh_group        = $adh_group
                }
                continue
            }

            foreach ($c in $matchedClusters) {
                $permRaw = Get-DbClusterPermissions -WorkspaceUrl $workspaceUrl -ClusterId $c.cluster_id -DatabricksPat $DatabricksPat
                $acl     = $permRaw.access_control_list

                $actualPerm = $null
                foreach ($ace in $acl) {
                    if ($ace.user_name -eq $principal -or $ace.group_name -eq $principal -or $ace.service_principal_name -eq $principal) {
                        $actualPerm = $ace.all_permissions[0].permission_level
                        break
                    }
                }

                $status = if (-not $actualPerm) { 'PrincipalMissing' }
                          elseif ($actualPerm -eq $expected) { 'OK' }
                          else { 'Mismatch' }

                $clusterPermResults += [pscustomobject]@{
                    SubscriptionName = $sub.Name
                    SubscriptionId   = $sub.Id
                    Env              = $env
                    WorkspaceName    = $ws.Name
                    ClusterName      = $c.cluster_name
                    PrincipalName    = $principal
                    ExpectedPerm     = $expected
                    ActualPerm       = $actualPerm
                    Status           = $status
                    adh_group        = $adh_group
                }
            }
        }

        # -------------------
        # 4.3 SQL Warehouse perms
        # -------------------
        $whRaw      = Get-DbWarehouses -WorkspaceUrl $workspaceUrl -DatabricksPat $DatabricksPat
        $warehouses = $whRaw.warehouses

        foreach ($cfg in $sqlWarehousePermsCfg | Where-Object { $_.env -eq $env }) {
            $pattern   = $cfg.warehouse_name_pattern
            $principal = ($cfg.principal_template -replace '<<cust>>', $adh_group.ToUpper())
            $expected  = $cfg.expected_permission

            $matchedWh = $warehouses | Where-Object { $_.name -like $pattern }

            if (-not $matchedWh) {
                $sqlWhPermResults += [pscustomobject]@{
                    SubscriptionName = $sub.Name
                    SubscriptionId   = $sub.Id
                    Env              = $env
                    WorkspaceName    = $ws.Name
                    WarehouseName    = $pattern
                    PrincipalName    = $principal
                    ExpectedPerm     = $expected
                    ActualPerm       = ''
                    Status           = 'WarehouseMissing'
                    adh_group        = $adh_group
                }
                continue
            }

            foreach ($wh in $matchedWh) {
                $permRaw = Get-DbWarehousePermissions -WorkspaceUrl $workspaceUrl -WarehouseId $wh.id -DatabricksPat $DatabricksPat
                $acl     = $permRaw.access_control_list

                $actualPerm = $null
                foreach ($ace in $acl) {
                    if ($ace.user_name -eq $principal -or $ace.group_name -eq $principal -or $ace.service_principal_name -eq $principal) {
                        $actualPerm = $ace.all_permissions[0].permission_level
                        break
                    }
                }

                $status = if (-not $actualPerm) { 'PrincipalMissing' }
                          elseif ($actualPerm -eq $expected) { 'OK' }
                          else { 'Mismatch' }

                $sqlWhPermResults += [pscustomobject]@{
                    SubscriptionName = $sub.Name
                    SubscriptionId   = $sub.Id
                    Env              = $env
                    WorkspaceName    = $ws.Name
                    WarehouseName    = $wh.name
                    PrincipalName    = $principal
                    ExpectedPerm     = $expected
                    ActualPerm       = $actualPerm
                    Status           = $status
                    adh_group        = $adh_group
                }
            }
        }

        # -------------------
        # 4.4 Catalog perms (bindings)
        # -------------------
        foreach ($cfg in $catalogPermsCfg | Where-Object { $_.env -eq $env }) {
            $catalogName = ($cfg.catalog_name       -replace '<<cust>>', $adh_group.ToLower())
            $principal   = ($cfg.principal_template -replace '<<cust>>', $adh_group.ToUpper())
            $expected    = $cfg.expected_privileges -split ',' | ForEach-Object { $_.Trim() }

            $permRaw = Get-DbCatalogPermissions -WorkspaceUrl $workspaceUrl -CatalogName $catalogName -DatabricksPat $DatabricksPat
            $acl     = $permRaw.privilege_assignments

            $actual  = @()
            foreach ($entry in $acl) {
                if ($entry.principal -eq $principal) {
                    $actual = $entry.privileges
                    break
                }
            }

            $missing = $expected | Where-Object { $_ -notin $actual }
            $extra   = $actual   | Where-Object { $_ -notin $expected }

            $status = if (-not $actual) { 'PrincipalMissing' }
                      elseif (-not $missing -and -not $extra) { 'OK' }
                      else { 'Mismatch' }

            $catalogPermResults += [pscustomobject]@{
                SubscriptionName = $sub.Name
                SubscriptionId   = $sub.Id
                Env              = $env
                WorkspaceName    = $ws.Name
                CatalogName      = $catalogName
                PrincipalName    = $principal
                ExpectedPrivs    = ($expected -join ',')
                ActualPrivs      = ($actual   -join ',')
                MissingPrivs     = ($missing  -join ',')
                ExtraPrivs       = ($extra    -join ',')
                Status           = $status
                adh_group        = $adh_group
            }
        }

        # -------------------
        # 4.5 External locations & perms
        # -------------------
        $extCfg  = $externalLocationsCfg     | Where-Object { $_.env -eq $env }
        $ePermCfg= $externalLocationPermsCfg | Where-Object { $_.env -eq $env }

        foreach ($row in $extCfg) {
            $name  = ($row.external_location_name_template -replace '<<cust>>', $adh_group.ToLower())
            $pathT = ($row.storage_path_template          -replace '<<cust>>', $adh_group.ToLower())
            $cred  = ($row.credential_name_template       -replace '<<cust>>', $adh_group.ToUpper())

            try {
                $locRaw = Get-DbExternalLocation -WorkspaceUrl $workspaceUrl -Name $name -DatabricksPat $DatabricksPat
                $exists = $true
            } catch {
                $locRaw = $null
                $exists = $false
            }

            $extLocResults += [pscustomobject]@{
                SubscriptionName = $sub.Name
                SubscriptionId   = $sub.Id
                Env              = $env
                WorkspaceName    = $ws.Name
                ExternalLocation = $name
                ExpectedPath     = $pathT
                ExpectedCred     = $cred
                ActualPath       = if ($locRaw) { $locRaw.url } else { '' }
                ActualCred       = if ($locRaw) { $locRaw.credential_name } else { '' }
                Exists           = $exists
                adh_group        = $adh_group
            }

            if ($exists) {
                $permRaw = Get-DbExternalLocationPermissions -WorkspaceUrl $workspaceUrl -Name $name -DatabricksPat $DatabricksPat
                $acl     = $permRaw.privilege_assignments

                foreach ($pcfg in $ePermCfg | Where-Object { 
                    ($_.external_location_name_template -replace '<<cust>>', $adh_group.ToLower()) -eq $name 
                }) {
                    $principal = ($pcfg.principal_template -replace '<<cust>>', $adh_group.ToUpper())
                    $expected  = $pcfg.expected_privileges -split ',' | ForEach-Object { $_.Trim() }

                    $actual = @()
                    foreach ($entry in $acl) {
                        if ($entry.principal -eq $principal) {
                            $actual = $entry.privileges
                            break
                        }
                    }

                    $missing = $expected | Where-Object { $_ -notin $actual }
                    $extra   = $actual   | Where-Object { $_ -notin $expected }

                    $status = if (-not $actual) { 'PrincipalMissing' }
                              elseif (-not $missing -and -not $extra) { 'OK' }
                              else { 'Mismatch' }

                    $extLocPermResults += [pscustomobject]@{
                        SubscriptionName = $sub.Name
                        SubscriptionId   = $sub.Id
                        Env              = $env
                        WorkspaceName    = $ws.Name
                        ExternalLocation = $name
                        PrincipalName    = $principal
                        ExpectedPrivs    = ($expected -join ',')
                        ActualPrivs      = ($actual   -join ',')
                        MissingPrivs     = ($missing  -join ',')
                        ExtraPrivs       = ($extra    -join ',')
                        Status           = $status
                        adh_group        = $adh_group
                    }
                }
            }
        }

        # -------------------
        # 4.6 Admin settings
        # -------------------
        if ($adminSettingsCfg) {
            $settingsRaw = Get-DbWorkspaceSettings -WorkspaceUrl $workspaceUrl -DatabricksPat $DatabricksPat

            foreach ($cfg in $adminSettingsCfg) {
                $key         = $cfg.setting_key
                $expectedVal = [string]$cfg.expected_value
                $actualVal   = $null

                if ($settingsRaw -and $settingsRaw.ContainsKey($key)) {
                    $actualVal = [string]$settingsRaw[$key]
                }

                $status = if ($actualVal -eq $expectedVal) { 'OK' } else { 'Mismatch' }

                $adminResults += [pscustomobject]@{
                    SubscriptionName = $sub.Name
                    SubscriptionId   = $sub.Id
                    Env              = $env
                    WorkspaceName    = $ws.Name
                    SettingKey       = $key
                    ExpectedValue    = $expectedVal
                    ActualValue      = $actualVal
                    Status           = $status
                    adh_group        = $adh_group
                }
            }
        }
    }
}

# 5. Outputs (CSV + HTML for key ones)
$csvWs = New-StampedPath -BaseDir $OutputDir -Prefix ("db_ws_{0}_{1}" -f $adh_group, $adh_subscription_type)
Write-CsvSafe -Rows $workspaceResults -Path $csvWs
Convert-CsvToHtml -CsvPath $csvWs -HtmlPath ($csvWs -replace '\.csv$','.html') -Title "Databricks Workspaces ($adh_group / $adh_subscription_type) $BranchName"

$csvWsPerm = New-StampedPath -BaseDir $OutputDir -Prefix ("db_ws_perms_{0}_{1}" -f $adh_group, $adh_subscription_type)
Write-CsvSafe -Rows $workspacePermResults -Path $csvWsPerm

$csvCluster = New-StampedPath -BaseDir $OutputDir -Prefix ("db_cluster_perms_{0}_{1}" -f $adh_group, $adh_subscription_type)
Write-CsvSafe -Rows $clusterPermResults -Path $csvCluster

$csvWh = New-StampedPath -BaseDir $OutputDir -Prefix ("db_sqlwh_perms_{0}_{1}" -f $adh_group, $adh_subscription_type)
Write-CsvSafe -Rows $sqlWhPermResults -Path $csvWh

$csvCat = New-StampedPath -BaseDir $OutputDir -Prefix ("db_catalog_perms_{0}_{1}" -f $adh_group, $adh_subscription_type)
Write-CsvSafe -Rows $catalogPermResults -Path $csvCat

$csvExt = New-StampedPath -BaseDir $OutputDir -Prefix ("db_extloc_{0}_{1}" -f $adh_group, $adh_subscription_type)
Write-CsvSafe -Rows $extLocResults -Path $csvExt

$csvExtPerm = New-StampedPath -BaseDir $OutputDir -Prefix ("db_extloc_perms_{0}_{1}" -f $adh_group, $adh_subscription_type)
Write-CsvSafe -Rows $extLocPermResults -Path $csvExtPerm

$csvAdmin = New-StampedPath -BaseDir $OutputDir -Prefix ("db_admin_settings_{0}_{1}" -f $adh_group, $adh_subscription_type)
Write-CsvSafe -Rows $adminResults -Path $csvAdmin

Write-Host "Databricks sanity scan completed." -ForegroundColor Green
Write-Host "Workspace CSV       : $csvWs"
Write-Host "Workspace perms CSV : $csvWsPerm"
Write-Host "Cluster perms CSV   : $csvCluster"
Write-Host "SQL WH perms CSV    : $csvWh"
Write-Host "Catalog perms CSV   : $csvCat"
Write-Host "Ext loc CSV         : $csvExt"
Write-Host "Ext loc perms CSV   : $csvExtPerm"
Write-Host "Admin settings CSV  : $csvAdmin"
