# sanitychecks/scripts/Scan-Databricks.ps1
# Full working code:
# - Enumerates Databricks workspaces via ARM
# - Ensures SPN exists in Databricks workspace via SCIM (requires admin)
# - Adds SPN to 'admins' group (workspace admin)
# - Fetches: SQL Warehouses + perms, UC Catalogs + perms, External Locations
# - Outputs CSVs + XLSX (if ImportExcel module exists)
#
# NOTE:
# - Workspace admin is usually enough for /sql/warehouses.
# - Unity Catalog endpoints require UC enabled + metastore attached; otherwise may return empty/403/404.

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

    # Optional override
    [string[]]$SubscriptionIds = @(),

    # Grant Azure RBAC (Reader) at subscription/RG scope to ensure enumeration works
    [switch]$GrantRbac,

    # Ensure SPN exists in Databricks workspace + add to admins group (requires Databricks admin)
    [switch]$EnsureDbxAdmin
)

Import-Module Az.Accounts, Az.Resources -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

# ---------------- Normalize ----------------
if ($null -ne $adh_sub_group) { $adh_sub_group = $adh_sub_group.Trim() }
if ([string]::IsNullOrWhiteSpace($adh_sub_group)) { $adh_sub_group = '' }

Ensure-Dir -Path $OutputDir | Out-Null

Write-Host "INFO: OutputDir             = $OutputDir" -ForegroundColor Cyan
Write-Host "INFO: adh_group             = $adh_group" -ForegroundColor Cyan
Write-Host "INFO: adh_sub_group         = '$adh_sub_group'" -ForegroundColor Cyan
Write-Host "INFO: adh_subscription_type = $adh_subscription_type" -ForegroundColor Cyan
Write-Host "INFO: BranchName            = $BranchName" -ForegroundColor Cyan
Write-Host "INFO: GrantRbac             = $GrantRbac" -ForegroundColor Cyan
Write-Host "INFO: EnsureDbxAdmin        = $EnsureDbxAdmin" -ForegroundColor Cyan

# ---------------- Azure auth ----------------
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure connection failed."
}

# ---------------- Helpers ----------------
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

function Get-DbTokens {
    # ✅ Correct resource for Databricks REST token
    $dbx = Get-AzAccessToken -ResourceUrl "https://databricks.azure.net/" -ErrorAction Stop
    $arm = Get-AzAccessToken -ResourceUrl "https://management.azure.com/" -ErrorAction Stop

    if (-not $dbx.Token) { throw "Failed to acquire Databricks AAD token." }
    if (-not $arm.Token) { throw "Failed to acquire ARM token." }

    [pscustomobject]@{
        DatabricksToken = $dbx.Token
        ArmToken        = $arm.Token
    }
}

function Invoke-DbRest {
    param(
        [Parameter(Mandatory)][string]$WorkspaceUrl,
        [Parameter(Mandatory)][ValidateSet('GET','POST','PUT','PATCH','DELETE')][string]$Method,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$DbxToken,
        [Parameter(Mandatory)][string]$ArmToken,
        [Parameter(Mandatory)][string]$WorkspaceResourceId,
        [string]$Body = $null
    )

    $hostPart = $WorkspaceUrl -replace '^https://',''
    $uri = "https://$hostPart$Path"

    $headers = @{
        Authorization                              = "Bearer $DbxToken"
        "X-Databricks-Azure-SP-Management-Token"   = $ArmToken
        "X-Databricks-Azure-Workspace-Resource-Id" = $WorkspaceResourceId
    }

    try {
        if ($null -ne $Body -and $Body.Trim().Length -gt 0) {
            return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers -Body $Body -ContentType 'application/json' -ErrorAction Stop
        } else {
            return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers -ErrorAction Stop
        }
    }
    catch {
        $statusCode = $null
        $respBody   = $null
        try {
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
                $stream = $_.Exception.Response.GetResponseStream()
                if ($stream) { $respBody = (New-Object System.IO.StreamReader($stream)).ReadToEnd() }
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

function Ensure-DbxServicePrincipal {
    param(
        [Parameter(Mandatory)][string]$WorkspaceUrl,
        [Parameter(Mandatory)][string]$DbxToken,
        [Parameter(Mandatory)][string]$ArmToken,
        [Parameter(Mandatory)][string]$WorkspaceResourceId,
        [Parameter(Mandatory)][string]$ApplicationId,
        [Parameter(Mandatory)][string]$DisplayName
    )

    $filter = [uri]::EscapeDataString("applicationId eq `"$ApplicationId`"")
    $resp = Invoke-DbRest -WorkspaceUrl $WorkspaceUrl -Method GET `
            -Path "/api/2.0/preview/scim/v2/ServicePrincipals?filter=$filter" `
            -DbxToken $DbxToken -ArmToken $ArmToken -WorkspaceResourceId $WorkspaceResourceId

    if ($resp -and $resp.Resources -and $resp.Resources.Count -gt 0) {
        return $resp.Resources[0].id
    }

    $body = @{
        schemas       = @("urn:ietf:params:scim:schemas:core:2.0:ServicePrincipal")
        applicationId = $ApplicationId
        displayName   = $DisplayName
    } | ConvertTo-Json -Depth 10

    $created = Invoke-DbRest -WorkspaceUrl $WorkspaceUrl -Method POST `
              -Path "/api/2.0/preview/scim/v2/ServicePrincipals" `
              -DbxToken $DbxToken -ArmToken $ArmToken -WorkspaceResourceId $WorkspaceResourceId `
              -Body $body

    if (-not $created -or -not $created.id) { throw "Failed to create Service Principal in Databricks workspace." }
    return $created.id
}

function Ensure-DbxAdminsMembership {
    param(
        [Parameter(Mandatory)][string]$WorkspaceUrl,
        [Parameter(Mandatory)][string]$DbxToken,
        [Parameter(Mandatory)][string]$ArmToken,
        [Parameter(Mandatory)][string]$WorkspaceResourceId,
        [Parameter(Mandatory)][string]$ScimSpId
    )

    $filter = [uri]::EscapeDataString('displayName eq "admins"')
    $g = Invoke-DbRest -WorkspaceUrl $WorkspaceUrl -Method GET `
         -Path "/api/2.0/preview/scim/v2/Groups?filter=$filter" `
         -DbxToken $DbxToken -ArmToken $ArmToken -WorkspaceResourceId $WorkspaceResourceId

    if (-not $g -or -not $g.Resources -or $g.Resources.Count -eq 0) {
        throw "Databricks SCIM group 'admins' not found."
    }

    $adminsGroup = $g.Resources[0]
    $adminsId    = $adminsGroup.id

    $already = $false
    foreach ($m in @($adminsGroup.members)) {
        if ($m.value -eq $ScimSpId) { $already = $true; break }
    }

    if ($already) {
        Write-Host "DBX: SPN already in 'admins' group." -ForegroundColor DarkGreen
        return
    }

    $patch = @{
        schemas    = @("urn:ietf:params:scim:api:messages:2.0:PatchOp")
        Operations = @(@{
            op    = "add"
            path  = "members"
            value = @(@{ value = $ScimSpId })
        })
    } | ConvertTo-Json -Depth 10

    $null = Invoke-DbRest -WorkspaceUrl $WorkspaceUrl -Method PATCH `
            -Path "/api/2.0/preview/scim/v2/Groups/$adminsId" `
            -DbxToken $DbxToken -ArmToken $ArmToken -WorkspaceResourceId $WorkspaceResourceId `
            -Body $patch

    Write-Host "DBX: Added SPN to 'admins' group." -ForegroundColor Green
    Start-Sleep -Seconds 10
}

# ---------------- Subscriptions ----------------
if ($SubscriptionIds.Count -gt 0) {
    $subs = foreach ($sid in $SubscriptionIds) { Get-AzSubscription -SubscriptionId $sid -ErrorAction Stop }
} else {
    $subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
    if ($subs -isnot [System.Collections.IEnumerable]) { $subs = ,$subs }
}
if (-not $subs -or $subs.Count -eq 0) {
    throw "No subscriptions resolved for adh_group '$adh_group' / env '$adh_subscription_type'."
}
Write-Host "INFO: Subscriptions = $($subs.Name -join ', ')" -ForegroundColor Cyan

# SPN object id for RBAC
$spObjectId = $null
if ($GrantRbac) {
    $sp = Get-AzADServicePrincipal -ApplicationId $ClientId -ErrorAction Stop
    $spObjectId = $sp.Id
    Write-Host "INFO: SP ObjectId = $spObjectId" -ForegroundColor Cyan
}

# Tokens for Databricks REST
$tokens = Get-DbTokens

# ---------------- Results ----------------
$workspaces        = @()
$sqlWh             = @()
$sqlWhPerms        = @()
$catalogs          = @()
$catalogPerms      = @()
$externalLocations = @()

foreach ($sub in $subs) {

    Set-ScContext -Subscription $sub
    Write-Host "`n=== Subscription: $($sub.Name) ===" -ForegroundColor Yellow

    if ($GrantRbac -and $spObjectId) {
        Ensure-RbacRole -ObjectId $spObjectId -Scope "/subscriptions/$($sub.Id)" -RoleName "Reader"
    }

    $wsResources = Get-AzResource -ResourceType "Microsoft.Databricks/workspaces" -ExpandProperties -ErrorAction SilentlyContinue
    if (-not $wsResources -or @($wsResources).Count -eq 0) {
        Write-Warning "No Databricks workspaces in subscription $($sub.Name)"
        continue
    }

    foreach ($ws in $wsResources) {

        $wsName   = $ws.Name
        $rg       = $ws.ResourceGroupName
        $loc      = $ws.Location
        $wsId     = $ws.ResourceId

        if ($GrantRbac -and $spObjectId) {
            Ensure-RbacRole -ObjectId $spObjectId -Scope "/subscriptions/$($sub.Id)/resourceGroups/$rg" -RoleName "Reader"
        }

        # Workspace URL extraction
        $wsUrl = $null
        if ($ws.Properties.workspaceUrl) { $wsUrl = $ws.Properties.workspaceUrl }
        elseif ($ws.Properties.parameters.workspaceUrl.value) { $wsUrl = $ws.Properties.parameters.workspaceUrl.value }

        if (-not $wsUrl) {
            Write-Warning "WorkspaceUrl not found for $wsName ($wsId) – skipping."
            continue
        }

        Write-Host "Workspace: $wsName | $wsUrl" -ForegroundColor Green

        $workspaces += [pscustomobject]@{
            SubscriptionName    = $sub.Name
            SubscriptionId      = $sub.Id
            ResourceGroup       = $rg
            WorkspaceName       = $wsName
            Location            = $loc
            WorkspaceUrl        = $wsUrl
            WorkspaceResourceId = $wsId
            adh_group           = $adh_group
            adh_sub_group       = $adh_sub_group
            EnvType             = $adh_subscription_type
            BranchName          = $BranchName
        }

        # Ensure SPN inside workspace + admin membership
        if ($EnsureDbxAdmin) {
            try {
                $scimSpId = Ensure-DbxServicePrincipal `
                    -WorkspaceUrl $wsUrl `
                    -DbxToken $tokens.DatabricksToken `
                    -ArmToken $tokens.ArmToken `
                    -WorkspaceResourceId $wsId `
                    -ApplicationId $ClientId `
                    -DisplayName "SPN-$($adh_group)-scan"

                Ensure-DbxAdminsMembership `
                    -WorkspaceUrl $wsUrl `
                    -DbxToken $tokens.DatabricksToken `
                    -ArmToken $tokens.ArmToken `
                    -WorkspaceResourceId $wsId `
                    -ScimSpId $scimSpId
            } catch {
                Write-Warning "DBX: EnsureDbxAdmin failed for $wsName : $($_.Exception.Message)"
            }
        }

        # -------- SQL Warehouses --------
        $wh = Invoke-DbRest -WorkspaceUrl $wsUrl -Method GET -Path "/api/2.0/sql/warehouses" `
              -DbxToken $tokens.DatabricksToken -ArmToken $tokens.ArmToken -WorkspaceResourceId $wsId

        if ($wh -and $wh.warehouses) {
            foreach ($w in $wh.warehouses) {
                $sqlWh += [pscustomobject]@{
                    SubscriptionName   = $sub.Name
                    SubscriptionId     = $sub.Id
                    ResourceGroup      = $rg
                    WorkspaceName      = $wsName
                    WarehouseId        = $w.id
                    WarehouseName      = $w.name
                    State              = $w.state
                    ClusterSize        = $w.cluster_size
                    AutoStopMins       = $w.auto_stop_mins
                    Serverless         = $w.enable_serverless_compute
                    SpotPolicy         = $w.spot_instance_policy
                    adh_group          = $adh_group
                    adh_sub_group      = $adh_sub_group
                }

                $whPerm = Invoke-DbRest -WorkspaceUrl $wsUrl -Method GET `
                    -Path ("/api/2.0/permissions/warehouses/{0}" -f $w.id) `
                    -DbxToken $tokens.DatabricksToken -ArmToken $tokens.ArmToken -WorkspaceResourceId $wsId

                if ($whPerm -and $whPerm.access_control_list) {
                    foreach ($ace in $whPerm.access_control_list) {

                        $principalName = $null
                        $principalType = 'unknown'
                        if ($ace.user_name) { $principalName = $ace.user_name; $principalType = 'user' }
                        elseif ($ace.group_name) { $principalName = $ace.group_name; $principalType = 'group' }
                        elseif ($ace.service_principal_name) { $principalName = $ace.service_principal_name; $principalType = 'service_principal' }

                        foreach ($p in $ace.all_permissions) {
                            $sqlWhPerms += [pscustomobject]@{
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
                            }
                        }
                    }
                }
            }
        } else {
            Write-Warning "SQL Warehouses empty or API blocked for $wsName."
        }

        # -------- Unity Catalog: Catalogs --------
        $catResp = Invoke-DbRest -WorkspaceUrl $wsUrl -Method GET -Path "/api/2.1/unity-catalog/catalogs" `
                    -DbxToken $tokens.DatabricksToken -ArmToken $tokens.ArmToken -WorkspaceResourceId $wsId

        if ($catResp -and $catResp.catalogs) {
            foreach ($c in $catResp.catalogs) {
                $catalogs += [pscustomobject]@{
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
                        $catalogPerms += [pscustomobject]@{
                            SubscriptionName = $sub.Name
                            SubscriptionId   = $sub.Id
                            ResourceGroup    = $rg
                            WorkspaceName    = $wsName
                            CatalogName      = $c.name
                            PrincipalName    = $entry.principal
                            Privileges       = ($entry.privileges -join ',')
                        }
                    }
                }
            }
        } else {
            Write-Warning "Catalogs empty or UC API blocked for $wsName."
        }

        # -------- Unity Catalog: External locations --------
        $extResp = Invoke-DbRest -WorkspaceUrl $wsUrl -Method GET -Path "/api/2.1/unity-catalog/external-locations" `
                   -DbxToken $tokens.DatabricksToken -ArmToken $tokens.ArmToken -WorkspaceResourceId $wsId

        if ($extResp -and $extResp.external_locations) {
            foreach ($l in $extResp.external_locations) {
                $externalLocations += [pscustomobject]@{
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
                }
            }
        } else {
            Write-Warning "External locations empty or UC API blocked for $wsName."
        }
    }
}

# ---------------- Output ----------------
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$base  = "{0}_{1}_{2}" -f $adh_group, $adh_subscription_type, $stamp

$csvWs   = Join-Path $OutputDir "$base`_db_workspaces.csv"
$csvWh   = Join-Path $OutputDir "$base`_db_sql_warehouses.csv"
$csvWhP  = Join-Path $OutputDir "$base`_db_sql_warehouse_perms.csv"
$csvCat  = Join-Path $OutputDir "$base`_db_catalogs.csv"
$csvCatP = Join-Path $OutputDir "$base`_db_catalog_perms.csv"
$csvExt  = Join-Path $OutputDir "$base`_db_external_locations.csv"

$workspaces        | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvWs
$sqlWh             | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvWh
$sqlWhPerms        | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvWhP
$catalogs          | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvCat
$catalogPerms      | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvCatP
$externalLocations | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvExt

Write-Host "`nDONE. CSV outputs:" -ForegroundColor Cyan
Write-Host " - $csvWs"
Write-Host " - $csvWh"
Write-Host " - $csvWhP"
Write-Host " - $csvCat"
Write-Host " - $csvCatP"
Write-Host " - $csvExt"

# XLSX (optional)
if (Get-Module -ListAvailable -Name ImportExcel) {
    Import-Module ImportExcel -ErrorAction SilentlyContinue
    $xlsx = Join-Path $OutputDir "$base`_db_inventory.xlsx"
    if (Test-Path $xlsx) { Remove-Item $xlsx -Force }

    # Always write sheets (even if empty)
    $workspaces        | Export-Excel -Path $xlsx -WorksheetName "Workspaces"     -AutoSize -FreezeTopRow
    $sqlWh             | Export-Excel -Path $xlsx -WorksheetName "SQLWarehouses"  -AutoSize -FreezeTopRow
    $sqlWhPerms        | Export-Excel -Path $xlsx -WorksheetName "SQLWhPerms"     -AutoSize -FreezeTopRow
    $catalogs          | Export-Excel -Path $xlsx -WorksheetName "Catalogs"       -AutoSize -FreezeTopRow
    $catalogPerms      | Export-Excel -Path $xlsx -WorksheetName "CatalogPerms"   -AutoSize -FreezeTopRow
    $externalLocations | Export-Excel -Path $xlsx -WorksheetName "ExternalLocs"   -AutoSize -FreezeTopRow

    Write-Host " - $xlsx" -ForegroundColor Green
} else {
    Write-Warning "ImportExcel module not found; XLSX skipped."
}

Write-Host "`nCounts:" -ForegroundColor Yellow
Write-Host " Workspaces          = $($workspaces.Count)"
Write-Host " SQL Warehouses      = $($sqlWh.Count)"
Write-Host " SQL Wh Perms        = $($sqlWhPerms.Count)"
Write-Host " Catalogs            = $($catalogs.Count)"
Write-Host " Catalog perms       = $($catalogPerms.Count)"
Write-Host " External locations  = $($externalLocations.Count)"
