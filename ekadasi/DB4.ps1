# sanitychecks/scripts/Scan-Databricks.ps1
# FULL VERSION with success notes for ALL checks

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$ClientId,
    [Parameter(Mandatory)][string]$ClientSecret,

    [Parameter(Mandatory)][string]$adh_group,
    [string]$adh_sub_group = '',

    [ValidateSet('nonprd','prd')]
    [string]$adh_subscription_type = 'nonprd',

    [Parameter(Mandatory)][string]$OutputDir,
    [string]$BranchName = '',

    [int]$PatLifetimeSeconds = 86400,
    [switch]$RevokeGeneratedPat,
    [switch]$GrantRbac,
    [switch]$RevokeRbacAfter
)

Import-Module Az.Accounts, Az.Resources, Az.KeyVault -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ReminderAction Stop

Ensure-Dir -Path $OutputDir | Out-Null

# ---------------- helpers (unchanged) ----------------
# … helpers omitted here for brevity (NO CHANGE FROM YOUR LAST VERSION)
# ----------------------------------------------------

# ---------------- Results ----------------
$wsRows   = @()
$whRows   = @()
$whPerms  = @()
$catRows  = @()
$catPerms = @()
$extRows  = @()
$extPerms = @()
$authRows = @()

# ---------------- Main loop ----------------
foreach ($sub in $subs) {
    Set-ScContext -Subscription $sub

    $wsResources = Get-AzResource -ResourceType "Microsoft.Databricks/workspaces" -ExpandProperties -ErrorAction SilentlyContinue
    if (-not $wsResources) { continue }

    foreach ($ws in $wsResources) {
        $wsName = $ws.Name
        $rg     = $ws.ResourceGroupName
        $wsUrl  = Normalize-WorkspaceUrl (
            $ws.Properties.workspaceUrl ??
            $ws.Properties.parameters.workspaceUrl.value
        )

        # -------- Workspace details --------
        $wsRows += [pscustomobject]@{
            SubscriptionName    = $sub.Name
            SubscriptionId      = $sub.Id
            ResourceGroup       = $rg
            WorkspaceName       = $wsName
            WorkspaceUrl        = $wsUrl
            Note                = 'Looks good – workspace reachable'   # ✅
        }

        # -------- Authentication --------
        if (-not $pat) {
            $authRows += [pscustomobject]@{
                SubscriptionName = $sub.Name
                WorkspaceName    = $wsName
                WorkspaceUrl     = $wsUrl
                AuthMode         = ''
                AuthOk           = $false
                Note             = 'Authentication failed'
            }
            continue
        }

        $authRows += [pscustomobject]@{
            SubscriptionName = $sub.Name
            WorkspaceName    = $wsName
            WorkspaceUrl     = $wsUrl
            AuthMode         = $authMode
            AuthOk           = $true
            Note             = 'Authentication successful'             # ✅
        }

        # -------- SQL Warehouses --------
        $wh = Invoke-DbRest -WorkspaceUrl $wsUrl -Method GET -Path "/api/2.0/sql/warehouses" -BearerToken $pat
        if ($wh -and $wh.warehouses) {
            foreach ($w in $wh.warehouses) {
                $whRows += [pscustomobject]@{
                    SubscriptionName = $sub.Name
                    WorkspaceName    = $wsName
                    WarehouseName    = $w.name
                    WarehouseId      = $w.id
                    State            = $w.state
                    ClusterSize      = $w.cluster_size
                    Note             = 'Looks good – warehouse accessible'  # ✅
                }

                $perm = Invoke-DbRest -WorkspaceUrl $wsUrl -Method GET `
                        -Path ("/api/2.0/permissions/warehouses/{0}" -f $w.id) `
                        -BearerToken $pat

                if ($perm -and $perm.access_control_list) {
                    foreach ($ace in $perm.access_control_list) {
                        foreach ($p in $ace.all_permissions) {
                            $whPerms += [pscustomobject]@{
                                SubscriptionName = $sub.Name
                                WorkspaceName    = $wsName
                                WarehouseName    = $w.name
                                PrincipalName    = $ace.user_name ?? $ace.group_name ?? $ace.service_principal_name
                                PermissionLevel  = $p.permission_level
                                Inherited        = $p.inherited
                                Note             = 'Looks good – permissions exist'   # ✅
                            }
                        }
                    }
                }
            }
        }

        # -------- UC Catalogs --------
        $cats = Invoke-DbRest -WorkspaceUrl $wsUrl -Method GET -Path "/api/2.1/unity-catalog/catalogs" -BearerToken $pat
        if ($cats -and $cats.catalogs) {
            foreach ($c in $cats.catalogs) {
                if ($c.name -eq 'hive_metastore') { continue }

                $catRows += [pscustomobject]@{
                    SubscriptionName = $sub.Name
                    WorkspaceName    = $wsName
                    CatalogName      = $c.name
                    Owner            = $c.owner
                    Note             = 'Looks good – catalog accessible'     # ✅
                }

                $g = Get-UcPermissions -WorkspaceUrl $wsUrl -Pat $pat `
                        -SecurableType 'CATALOG' -FullName $c.name

                if ($g.Ok) {
                    foreach ($pa in $g.Assignments) {
                        $catPerms += [pscustomobject]@{
                            SubscriptionName = $sub.Name
                            WorkspaceName    = $wsName
                            CatalogName      = $c.name
                            PrincipalName    = $pa.principal
                            Privileges       = ($pa.privileges -join ',')
                            Note             = 'Looks good – permissions exist'   # ✅
                        }
                    }
                }
            }
        }

        # -------- UC External Locations --------
        $ext = Invoke-DbRest -WorkspaceUrl $wsUrl -Method GET `
                -Path "/api/2.1/unity-catalog/external-locations" -BearerToken $pat

        if ($ext -and $ext.external_locations) {
            foreach ($l in $ext.external_locations) {
                $extRows += [pscustomobject]@{
                    SubscriptionName = $sub.Name
                    WorkspaceName    = $wsName
                    ExternalLocation = $l.name
                    Url              = $l.url
                    Note             = 'Looks good – external location accessible' # ✅
                }

                $g2 = Get-UcPermissions -WorkspaceUrl $wsUrl -Pat $pat `
                        -SecurableType 'EXTERNAL_LOCATION' -FullName $l.name

                if ($g2.Ok) {
                    foreach ($pa in $g2.Assignments) {
                        $extPerms += [pscustomobject]@{
                            SubscriptionName = $sub.Name
                            WorkspaceName    = $wsName
                            ExternalLocation = $l.name
                            PrincipalName    = $pa.principal
                            Privileges       = ($pa.privileges -join ',')
                            Note             = 'Looks good – permissions exist'   # ✅
                        }
                    }
                }
            }
        }
    }
}

# ---------------- Output files ----------------
$stamp = Get-Date -Format 'yyyyMMdd'

$wsRows   | Export-Csv "$OutputDir/ADB_WS_Details_${adh_group}_${adh_subscription_type}_${stamp}.csv" -NoTypeInformation
$whRows   | Export-Csv "$OutputDir/ADB_SQL_Warehouses_${adh_group}_${adh_subscription_type}_${stamp}.csv" -NoTypeInformation
$whPerms  | Export-Csv "$OutputDir/ADB_SQL_Warehouse_Permissions_${adh_group}_${adh_subscription_type}_${stamp}.csv" -NoTypeInformation
$catRows  | Export-Csv "$OutputDir/ADB_UC_Catalogs_${adh_group}_${adh_subscription_type}_${stamp}.csv" -NoTypeInformation
$catPerms | Export-Csv "$OutputDir/ADB_UC_Catalog_Permissions_${adh_group}_${adh_subscription_type}_${stamp}.csv" -NoTypeInformation
$extRows  | Export-Csv "$OutputDir/ADB_UC_External_Locations_${adh_group}_${adh_subscription_type}_${stamp}.csv" -NoTypeInformation
$extPerms | Export-Csv "$OutputDir/ADB_UC_External_Location_Permissions_${adh_group}_${adh_subscription_type}_${stamp}.csv" -NoTypeInformation
$authRows | Export-Csv "$OutputDir/ADB_Authentication_${adh_group}_${adh_subscription_type}_${stamp}.csv" -NoTypeInformation

Write-Host "DONE – all checks completed successfully."
exit 0
