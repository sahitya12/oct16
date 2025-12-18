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

    # Optional explicit subscriptions override
    [string[]]$SubscriptionIds = @(),

    # Optional: grant RBAC like your KV script
    [switch]$GrantRbac
)

Import-Module Az.Accounts, Az.Resources -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

# ---------------- Normalize ----------------
if ($null -ne $adh_sub_group) { $adh_sub_group = $adh_sub_group.Trim() }
if ([string]::IsNullOrWhiteSpace($adh_sub_group)) { $adh_sub_group = '' }

$OutputDir = Ensure-Dir -Path $OutputDir

Write-Host "INFO: OutputDir = $OutputDir" -ForegroundColor Cyan
Write-Host "INFO: adh_group = $adh_group | adh_sub_group = '$adh_sub_group' | type = $adh_subscription_type" -ForegroundColor Cyan
Write-Host "INFO: GrantRbac = $GrantRbac" -ForegroundColor Cyan

# ---------------- Azure auth ----------------
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure connection failed."
}

# ---------------- RBAC helper (KV-style) ----------------
function Ensure-RbacRole {
    param(
        [Parameter(Mandatory)][string]$ObjectId,
        [Parameter(Mandatory)][string]$Scope,
        [Parameter(Mandatory)][string]$RoleName
    )
    try {
        $existing = Get-AzRoleAssignment -ObjectId $ObjectId -RoleDefinitionName $RoleName -Scope $Scope -ErrorAction SilentlyContinue
        if (-not $existing) {
            New-AzRoleAssignment -ObjectId $ObjectId -RoleDefinitionName $RoleName -Scope $Scope -ErrorAction Stop
            Write-Host "RBAC: Assigned '$RoleName' on $Scope" -ForegroundColor Green
            Start-Sleep -Seconds 20
        } else {
            Write-Host "RBAC: Already has '$RoleName' on $Scope" -ForegroundColor DarkGreen
        }
    } catch {
        Write-Warning "RBAC: Failed '$RoleName' on $Scope : $($_.Exception.Message)"
    }
}

# ---------------- Tokens (FIXED) ----------------
function Get-DbTokens {
    # ✅ Correct audience for AAD token to call Databricks REST API
    $dbx = Get-AzAccessToken -ResourceUrl "https://databricks.azure.net/" -ErrorAction Stop
    $arm = Get-AzAccessToken -ResourceUrl "https://management.azure.com/" -ErrorAction Stop

    if (-not $dbx.Token) { throw "Failed to acquire Databricks AAD token." }
    if (-not $arm.Token) { throw "Failed to acquire ARM token." }

    [pscustomobject]@{
        DatabricksToken = $dbx.Token
        ArmToken        = $arm.Token
    }
}

# ---------------- REST caller (FIXED: show real error body) ----------------
function Invoke-DbRest {
    param(
        [Parameter(Mandatory)][string]$WorkspaceUrl,
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$DbxToken,
        [Parameter(Mandatory)][string]$ArmToken,
        [Parameter(Mandatory)][string]$WorkspaceResourceId
    )

    $hostPart = $WorkspaceUrl -replace '^https://',''
    $uri = "https://$hostPart$Path"

    $headers = @{
        Authorization                              = "Bearer $DbxToken"
        "X-Databricks-Azure-SP-Management-Token"   = $ArmToken
        "X-Databricks-Azure-Workspace-Resource-Id" = $WorkspaceResourceId
    }

    try {
        return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers -ErrorAction Stop
    }
    catch {
        $statusCode = $null
        $respBody   = $null

        try {
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
                $stream = $_.Exception.Response.GetResponseStream()
                if ($stream) {
                    $reader = New-Object System.IO.StreamReader($stream)
                    $respBody = $reader.ReadToEnd()
                }
            }
        } catch {}

        Write-Warning ("DBX REST FAILED: {0} {1} :: HTTP={2} :: {3}" -f $Method, $uri, $statusCode, $_.Exception.Message)
        if ($respBody) {
            $oneLine = ($respBody -replace '\s+',' ') 
            Write-Warning ("DBX REST BODY: {0}" -f $oneLine.Substring(0, [Math]::Min(800, $oneLine.Length)))
        }
        return $null
    }
}

# ---------------- Subscriptions ----------------
if ($SubscriptionIds.Count -gt 0) {
    $subs = foreach ($sid in $SubscriptionIds) { Get-AzSubscription -SubscriptionId $sid -ErrorAction Stop }
} else {
    $subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
    if ($subs -isnot [System.Collections.IEnumerable]) { $subs = ,$subs }
}
if (-not $subs -or $subs.Count -eq 0) {
    throw "No subscriptions for adh_group '$adh_group' / env '$adh_subscription_type'."
}
Write-Host "INFO: Subs = $($subs.Name -join ', ')" -ForegroundColor Cyan

$tokens = Get-DbTokens

# ---------------- Result arrays ----------------
$workspaceResults    = @()
$sqlWhResults        = @()
$sqlWhPermResults    = @()
$catalogListResults  = @()
$catalogPermResults  = @()
$extLocResults       = @()

# ---------------- Main scan ----------------
foreach ($sub in $subs) {

    Write-Host "---- Subscription: $($sub.Name) / $($sub.Id)" -ForegroundColor Yellow
    Set-ScContext -Subscription $sub

    # Optional RBAC grant at subscription scope to ensure enumeration works
    if ($GrantRbac) {
        $sp = Get-AzADServicePrincipal -ApplicationId $ClientId -ErrorAction Stop
        $spObjectId = $sp.Id
        $subScope = "/subscriptions/$($sub.Id)"
        Ensure-RbacRole -ObjectId $spObjectId -Scope $subScope -RoleName "Reader"
    }

    $wsResources = Get-AzResource -ResourceType "Microsoft.Databricks/workspaces" -ExpandProperties -ErrorAction SilentlyContinue
    if (-not $wsResources) {
        Write-Warning "No Databricks workspaces in $($sub.Name)"
        continue
    }

    foreach ($ws in $wsResources) {

        $wsName   = $ws.Name
        $rg       = $ws.ResourceGroupName
        $location = $ws.Location
        $wsId     = $ws.ResourceId

        # RBAC on RG (best practice for ARM reads)
        if ($GrantRbac) {
            $rgScope = "/subscriptions/$($sub.Id)/resourceGroups/$rg"
            Ensure-RbacRole -ObjectId $spObjectId -Scope $rgScope -RoleName "Reader"
        }

        $wsUrl = $null
        if ($ws.Properties.workspaceUrl) {
            $wsUrl = $ws.Properties.workspaceUrl
        } elseif ($ws.Properties.parameters.workspaceUrl.value) {
            $wsUrl = $ws.Properties.parameters.workspaceUrl.value
        }

        if (-not $wsUrl) {
            Write-Warning "WorkspaceUrl not found for $wsName ($wsId) – skipping."
            continue
        }

        Write-Host "  Workspace: $wsName | $wsUrl" -ForegroundColor Green

        $workspaceResults += [pscustomobject]@{
            SubscriptionName      = $sub.Name
            SubscriptionId        = $sub.Id
            ResourceGroup         = $rg
            WorkspaceName         = $wsName
            Location              = $location
            WorkspaceUrl          = $wsUrl
            WorkspaceResourceId   = $wsId
            adh_group             = $adh_group
            adh_sub_group         = $adh_sub_group
            adh_subscription_type = $adh_subscription_type
            BranchName            = $BranchName
        }

        # -------- SQL Warehouses + permissions --------
        Write-Host "    Calling SQL warehouses API..." -ForegroundColor Cyan
        $wh = Invoke-DbRest -WorkspaceUrl $wsUrl -Method GET -Path "/api/2.0/sql/warehouses" `
                            -DbxToken $tokens.DatabricksToken -ArmToken $tokens.ArmToken -WorkspaceResourceId $wsId

        if ($wh -and $wh.warehouses) {
            foreach ($w in $wh.warehouses) {

                $sqlWhResults += [pscustomobject]@{
                    SubscriptionName        = $sub.Name
                    SubscriptionId          = $sub.Id
                    ResourceGroup           = $rg
                    WorkspaceName           = $wsName
                    WarehouseId             = $w.id
                    WarehouseName           = $w.name
                    WarehouseState          = $w.state
                    ClusterSize             = $w.cluster_size
                    AutoStopMins            = $w.auto_stop_mins
                    SpotInstancePolicy      = $w.spot_instance_policy
                    EnableServerlessCompute = $w.enable_serverless_compute
                    adh_group               = $adh_group
                    adh_sub_group           = $adh_sub_group
                }

                $whPerm = Invoke-DbRest -WorkspaceUrl $wsUrl -Method GET `
                         -Path ("/api/2.0/permissions/warehouses/{0}" -f $w.id) `
                         -DbxToken $tokens.DatabricksToken -ArmToken $tokens.ArmToken -WorkspaceResourceId $wsId

                if ($whPerm -and $whPerm.access_control_list) {
                    foreach ($ace in $whPerm.access_control_list) {

                        $principalName = $null
                        $principalType = 'unknown'
                        if ($ace.user_name)               { $principalName = $ace.user_name;               $principalType = 'user' }
                        elseif ($ace.group_name)          { $principalName = $ace.group_name;              $principalType = 'group' }
                        elseif ($ace.service_principal_name) { $principalName = $ace.service_principal_name; $principalType = 'service_principal' }

                        foreach ($p in $ace.all_permissions) {
                            $sqlWhPermResults += [pscustomobject]@{
                                SubscriptionName = $sub.Name
                                SubscriptionId   = $sub.Id
                                ResourceGroup    = $rg
                                WorkspaceName    = $wsName
                                WarehouseId      = $w.id
                                WarehouseName    = $w.name
                                PrincipalType    = $principalType
                                PrincipalName    = $principalName
                                PermissionLevel  = $p.permission_level
                                Inherited        = $p.inherited
                                adh_group        = $adh_group
                                adh_sub_group    = $adh_sub_group
                            }
                        }
                    }
                }
            }
        } else {
            Write-Warning "    SQL Warehouses: none OR API failed (see REST warnings above)."
        }

        # -------- Catalogs + permissions --------
        Write-Host "    Calling catalogs API..." -ForegroundColor Cyan
        $cats = Invoke-DbRest -WorkspaceUrl $wsUrl -Method GET -Path "/api/2.1/unity-catalog/catalogs" `
                              -DbxToken $tokens.DatabricksToken -ArmToken $tokens.ArmToken -WorkspaceResourceId $wsId

        if ($cats -and $cats.catalogs) {
            foreach ($c in $cats.catalogs) {

                $catalogListResults += [pscustomobject]@{
                    SubscriptionName = $sub.Name
                    SubscriptionId   = $sub.Id
                    ResourceGroup    = $rg
                    WorkspaceName    = $wsName
                    CatalogName      = $c.name
                    Owner            = $c.owner
                    Comment          = $c.comment
                    CreatedAt        = $c.created_at
                    UpdatedAt        = $c.updated_at
                    adh_group        = $adh_group
                    adh_sub_group    = $adh_sub_group
                }

                $catPerm = Invoke-DbRest -WorkspaceUrl $wsUrl -Method GET `
                          -Path ("/api/2.1/unity-catalog/permissions/catalogs/{0}" -f $c.name) `
                          -DbxToken $tokens.DatabricksToken -ArmToken $tokens.ArmToken -WorkspaceResourceId $wsId

                if ($catPerm -and $catPerm.privilege_assignments) {
                    foreach ($entry in $catPerm.privilege_assignments) {
                        $catalogPermResults += [pscustomobject]@{
                            SubscriptionName = $sub.Name
                            SubscriptionId   = $sub.Id
                            ResourceGroup    = $rg
                            WorkspaceName    = $wsName
                            CatalogName      = $c.name
                            PrincipalName    = $entry.principal
                            Privileges       = ($entry.privileges -join ',')
                            adh_group        = $adh_group
                            adh_sub_group    = $adh_sub_group
                        }
                    }
                }
            }
        } else {
            Write-Warning "    Catalogs: none OR API failed (see REST warnings above)."
        }

        # -------- External locations --------
        Write-Host "    Calling external locations API..." -ForegroundColor Cyan
        $ext = Invoke-DbRest -WorkspaceUrl $wsUrl -Method GET -Path "/api/2.1/unity-catalog/external-locations" `
                             -DbxToken $tokens.DatabricksToken -ArmToken $tokens.ArmToken -WorkspaceResourceId $wsId

        if ($ext -and $ext.external_locations) {
            foreach ($l in $ext.external_locations) {
                $extLocResults += [pscustomobject]@{
                    SubscriptionName = $sub.Name
                    SubscriptionId   = $sub.Id
                    ResourceGroup    = $rg
                    WorkspaceName    = $wsName
                    ExternalLocation = $l.name
                    Url              = $l.url
                    CredentialName   = $l.credential_name
                    Owner            = $l.owner
                    Comment          = $l.comment
                    CreatedAt        = $l.created_at
                    UpdatedAt        = $l.updated_at
                    adh_group        = $adh_group
                    adh_sub_group    = $adh_sub_group
                }
            }
        } else {
            Write-Warning "    External locations: none OR API failed (see REST warnings above)."
        }
    }
}

# ---------------- Export ----------------
$stamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$prefix = "{0}_{1}_{2}" -f $adh_group, $adh_subscription_type, $stamp

$csvWs      = Join-Path $OutputDir "$prefix`_db_workspaces.csv"
$csvWh      = Join-Path $OutputDir "$prefix`_db_sql_warehouses.csv"
$csvWhPerm  = Join-Path $OutputDir "$prefix`_db_sql_warehouse_perms.csv"
$csvCats    = Join-Path $OutputDir "$prefix`_db_catalogs.csv"
$csvCatPerm = Join-Path $OutputDir "$prefix`_db_catalog_perms.csv"
$csvExt     = Join-Path $OutputDir "$prefix`_db_external_locations.csv"

$workspaceResults   | Export-Csv -NoTypeInformation -Path $csvWs      -Encoding UTF8
$sqlWhResults       | Export-Csv -NoTypeInformation -Path $csvWh      -Encoding UTF8
$sqlWhPermResults   | Export-Csv -NoTypeInformation -Path $csvWhPerm  -Encoding UTF8
$catalogListResults | Export-Csv -NoTypeInformation -Path $csvCats    -Encoding UTF8
$catalogPermResults | Export-Csv -NoTypeInformation -Path $csvCatPerm -Encoding UTF8
$extLocResults      | Export-Csv -NoTypeInformation -Path $csvExt     -Encoding UTF8

Write-Host "DONE. CSV outputs:" -ForegroundColor Cyan
Write-Host " - $csvWs"
Write-Host " - $csvWh"
Write-Host " - $csvWhPerm"
Write-Host " - $csvCats"
Write-Host " - $csvCatPerm"
Write-Host " - $csvExt"

if (Get-Module -ListAvailable -Name ImportExcel) {
    Import-Module ImportExcel -ErrorAction SilentlyContinue
    $xlsx = Join-Path $OutputDir "$prefix`_db_inventory.xlsx"
    if (Test-Path $xlsx) { Remove-Item $xlsx -Force }

    # Always write sheets (even if empty arrays)
    $workspaceResults   | Export-Excel -Path $xlsx -WorksheetName "Workspaces"     -AutoSize -FreezeTopRow
    $sqlWhResults       | Export-Excel -Path $xlsx -WorksheetName "SQLWarehouses"  -AutoSize -FreezeTopRow
    $sqlWhPermResults   | Export-Excel -Path $xlsx -WorksheetName "SQLWhPerms"     -AutoSize -FreezeTopRow
    $catalogListResults | Export-Excel -Path $xlsx -WorksheetName "Catalogs"       -AutoSize -FreezeTopRow
    $catalogPermResults | Export-Excel -Path $xlsx -WorksheetName "CatalogPerms"   -AutoSize -FreezeTopRow
    $extLocResults      | Export-Excel -Path $xlsx -WorksheetName "ExternalLocs"   -AutoSize -FreezeTopRow

    Write-Host " - $xlsx" -ForegroundColor Green
}
else {
    Write-Warning "ImportExcel module not found; XLSX skipped."
}

Write-Host "Counts:" -ForegroundColor Yellow
Write-Host " Workspaces          = $($workspaceResults.Count)"
Write-Host " SQL Warehouses      = $($sqlWhResults.Count)"
Write-Host " SQL Wh Permissions  = $($sqlWhPermResults.Count)"
Write-Host " Catalogs            = $($catalogListResults.Count)"
Write-Host " Catalog Permissions = $($catalogPermResults.Count)"
Write-Host " External Locations  = $($extLocResults.Count)"
