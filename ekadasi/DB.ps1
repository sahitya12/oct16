# sanitychecks/scripts/Scan-Databricks.ps1
# AAD (client_credentials) -> Create Databricks PAT per workspace -> Scan UC/SQL permissions
# No Key Vault dependency. Works if the SPN used for Azure login is added to each workspace.

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

    # Create a short-lived PAT per workspace (default 1 day)
    [int]$PatLifetimeSeconds = 86400,

    # Revoke the generated PAT after scan (recommended)
    [switch]$RevokeGeneratedPat
)

Import-Module Az.Accounts, Az.Resources -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

Ensure-Dir -Path $OutputDir | Out-Null

# ---------------- Helpers ----------------
function Normalize-Text([string]$s) {
    if ($null -eq $s) { return '' }
    return $s.Trim()
}

function Get-EnvList([string]$subType) {
    if ($subType -eq 'prd') { return @('prd') }
    return @('dev','tst','stg')
}

function Normalize-WorkspaceUrl([string]$u) {
    if ([string]::IsNullOrWhiteSpace($u)) { return '' }
    $u = $u.Trim().TrimEnd('/')
    if ($u -notmatch '^https?://') { $u = "https://$u" }
    return $u
}

# Global last error from DBX REST (so we can write it into CSV)
$script:LastDbxError = ''

function Invoke-DbRest {
    param(
        [Parameter(Mandatory)][string]$WorkspaceUrl,
        [Parameter(Mandatory)][ValidateSet('GET','POST','PUT','PATCH','DELETE')][string]$Method,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$BearerToken,
        [string]$Body = $null,
        [string]$ContentType = $null
    )

    $script:LastDbxError = ''

    $WorkspaceUrl = Normalize-WorkspaceUrl $WorkspaceUrl
    $hostPart = $WorkspaceUrl -replace '^https?://',''
    $uri = "https://$hostPart$Path"
    $headers = @{ Authorization = "Bearer $BearerToken" }

    try {
        if ($Body) {
            if (-not $ContentType) { $ContentType = 'application/json' }
            return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers -ContentType $ContentType -Body $Body -ErrorAction Stop
        } else {
            return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers -ErrorAction Stop
        }
    } catch {
        $statusCode = $null
        $respBody = $null
        try {
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
                $stream = $_.Exception.Response.GetResponseStream()
                if ($stream) { $respBody = (New-Object System.IO.StreamReader($stream)).ReadToEnd() }
            }
        } catch {}

        $msg = "HTTP=$statusCode; $($_.Exception.Message)"
        if ($respBody) {
            $one = ($respBody -replace '\s+',' ')
            if ($one.Length -gt 0) {
                $msg = $msg + " | BODY=" + $one.Substring(0,[Math]::Min(400,$one.Length))
            }
        }
        $script:LastDbxError = $msg
        return $null
    }
}

# Get Entra token for Azure Databricks resource (client_credentials)
function Get-AadDatabricksToken {
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$SpnClientId,
        [Parameter(Mandatory)][string]$SpnClientSecret
    )
    try {
        # Azure Databricks resource App ID
        $scope = "2ff814a6-3304-4ab8-85cb-cd0e6f879c1d/.default"

        $body = @{
            client_id     = $SpnClientId
            client_secret = $SpnClientSecret
            grant_type    = "client_credentials"
            scope         = $scope
        }

        $tok = Invoke-RestMethod -Method POST `
            -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
            -ContentType "application/x-www-form-urlencoded" -Body $body -ErrorAction Stop

        return $tok.access_token
    } catch {
        return $null
    }
}

# Validate whether token is accepted by the workspace (403 means token valid but lacks permission for that endpoint)
function Test-DbxAuth {
    param(
        [Parameter(Mandatory)][string]$WorkspaceUrl,
        [Parameter(Mandatory)][string]$BearerToken
    )

    $me = Invoke-DbRest -WorkspaceUrl $WorkspaceUrl -Method GET -Path "/api/2.0/current-user" -BearerToken $BearerToken
    if ($me) { return $true }
    if ($script:LastDbxError -match 'HTTP=403') { return $true }
    if ($script:LastDbxError -match 'HTTP=401') { return $false }

    # fallback probe
    $c = Invoke-DbRest -WorkspaceUrl $WorkspaceUrl -Method GET -Path "/api/2.0/clusters/list" -BearerToken $BearerToken
    if ($c) { return $true }
    if ($script:LastDbxError -match 'HTTP=403') { return $true }
    if ($script:LastDbxError -match 'HTTP=401') { return $false }

    return $false
}

# Create a PAT using AAD token (Databricks allows this if SPN exists in workspace)
function New-DatabricksPat {
    param(
        [Parameter(Mandatory)][string]$WorkspaceUrl,
        [Parameter(Mandatory)][string]$AadBearerToken,
        [int]$LifetimeSeconds = 86400,
        [string]$Comment = "sanitychecks-auto"
    )

    $bodyObj = @{
        lifetime_seconds = $LifetimeSeconds
        comment          = $Comment
    }
    $json = ($bodyObj | ConvertTo-Json -Depth 5)

    $resp = Invoke-DbRest -WorkspaceUrl $WorkspaceUrl -Method POST -Path "/api/2.0/token/create" `
        -BearerToken $AadBearerToken -Body $json -ContentType "application/json"

    if (-not $resp -or [string]::IsNullOrWhiteSpace($resp.token_value)) {
        return $null
    }
    return $resp.token_value
}

# Optionally revoke created PAT
function Revoke-DatabricksPat {
    param(
        [Parameter(Mandatory)][string]$WorkspaceUrl,
        [Parameter(Mandatory)][string]$AadBearerToken,
        [Parameter(Mandatory)][string]$TokenId
    )
    $json = (@{ token_id = $TokenId } | ConvertTo-Json -Depth 5)
    $null = Invoke-DbRest -WorkspaceUrl $WorkspaceUrl -Method POST -Path "/api/2.0/token/delete" `
        -BearerToken $AadBearerToken -Body $json -ContentType "application/json"
}

# Create token AND remember token_id for revoke
function New-DatabricksPatWithId {
    param(
        [Parameter(Mandatory)][string]$WorkspaceUrl,
        [Parameter(Mandatory)][string]$AadBearerToken,
        [int]$LifetimeSeconds = 86400,
        [string]$Comment = "sanitychecks-auto"
    )

    $bodyObj = @{
        lifetime_seconds = $LifetimeSeconds
        comment          = $Comment
    }
    $json = ($bodyObj | ConvertTo-Json -Depth 5)

    $resp = Invoke-DbRest -WorkspaceUrl $WorkspaceUrl -Method POST -Path "/api/2.0/token/create" `
        -BearerToken $AadBearerToken -Body $json -ContentType "application/json"

    if (-not $resp) { return $null }
    if ([string]::IsNullOrWhiteSpace($resp.token_value)) { return $null }
    # response includes token_value and (usually) token_info with token_id
    $tokenId = $null
    try { $tokenId = $resp.token_info.token_id } catch {}
    return @{ Pat = $resp.token_value; TokenId = $tokenId }
}

function Ensure-AtLeastOneRow([ref]$arr, [hashtable]$row) {
    if (-not $arr.Value -or @($arr.Value).Count -eq 0) {
        $arr.Value = @([pscustomobject]$row)
    }
}

# ---------------- Start ----------------
$adh_sub_group = Normalize-Text $adh_sub_group

Write-Host "INFO: adh_group             = $adh_group"
Write-Host "INFO: adh_sub_group         = '$adh_sub_group'"
Write-Host "INFO: adh_subscription_type = $adh_subscription_type"
Write-Host "INFO: OutputDir             = $OutputDir"
Write-Host "INFO: BranchName            = $BranchName"
Write-Host "INFO: PatLifetimeSeconds    = $PatLifetimeSeconds"
Write-Host "INFO: RevokeGeneratedPat    = $RevokeGeneratedPat"

if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure connection failed."
}

$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
if ($subs -isnot [System.Collections.IEnumerable]) { $subs = ,$subs }
if (-not $subs -or @($subs).Count -eq 0) { throw "No subscriptions resolved." }

Write-Host "INFO: Subscriptions = $(($subs | Select-Object -ExpandProperty Name) -join ', ')"

$envs = Get-EnvList $adh_subscription_type

# Results
$wsRows   = @()
$ucProbe  = @()
$whRows   = @()
$whPerms  = @()
$catRows  = @()
$catPerms = @()
$extRows  = @()
$extPerms = @()
$notes    = @()

foreach ($sub in $subs) {
    Set-ScContext -Subscription $sub
    Write-Host "`n=== Databricks scan: $($sub.Name) ($($sub.Id)) ===" -ForegroundColor Cyan

    $wsResources = Get-AzResource -ResourceType "Microsoft.Databricks/workspaces" -ExpandProperties -ErrorAction SilentlyContinue
    if (-not $wsResources -or @($wsResources).Count -eq 0) {
        Write-Warning "No Databricks workspaces in subscription $($sub.Name)"
        continue
    }

    foreach ($ws in $wsResources) {
        $wsName = $ws.Name
        $rg     = $ws.ResourceGroupName
        $loc    = $ws.Location
        $wsId   = $ws.ResourceId

        $wsUrl = $null
        if ($ws.Properties.workspaceUrl) {
            $wsUrl = $ws.Properties.workspaceUrl
        } elseif ($ws.Properties.parameters.workspaceUrl.value) {
            $wsUrl = $ws.Properties.parameters.workspaceUrl.value
        }
        $wsUrl = Normalize-WorkspaceUrl $wsUrl

        if (-not $wsUrl) {
            $wsRows += [pscustomobject]@{
                SubscriptionName    = $sub.Name
                SubscriptionId      = $sub.Id
                ResourceGroup       = $rg
                WorkspaceName       = $wsName
                Location            = $loc
                WorkspaceUrl        = ''
                WorkspaceResourceId = $wsId
                Note                = 'workspaceUrl missing'
            }
            continue
        }

        $wsRows += [pscustomobject]@{
            SubscriptionName    = $sub.Name
            SubscriptionId      = $sub.Id
            ResourceGroup       = $rg
            WorkspaceName       = $wsName
            Location            = $loc
            WorkspaceUrl        = $wsUrl
            WorkspaceResourceId = $wsId
            Note                = ''
        }

        # -------- Auth bootstrap using AAD --------
        $aadTok = Get-AadDatabricksToken -TenantId $TenantId -SpnClientId $ClientId -SpnClientSecret $ClientSecret
        if (-not $aadTok) {
            $notes += [pscustomobject]@{
                SubscriptionName = $sub.Name
                WorkspaceName    = $wsName
                WorkspaceUrl     = $wsUrl
                AuthMode         = "AAD_CLIENT_CREDENTIALS"
                AuthOk           = $false
                Note             = "AUTH FAILED: could not obtain AAD token for Databricks resource."
            }
            continue
        }

        # Validate AAD token is accepted by this workspace (SPN must exist in that workspace)
        if (-not (Test-DbxAuth -WorkspaceUrl $wsUrl -BearerToken $aadTok)) {
            $notes += [pscustomobject]@{
                SubscriptionName = $sub.Name
                WorkspaceName    = $wsName
                WorkspaceUrl     = $wsUrl
                AuthMode         = "AAD_CLIENT_CREDENTIALS"
                AuthOk           = $false
                Note             = "AUTH FAILED: workspace rejected AAD token. Ensure SPN is added in this workspace (Identity & access > Service principals) and has access. $script:LastDbxError"
            }
            continue
        }

        # -------- Create PAT per workspace (short-lived) --------
        $patObj = New-DatabricksPatWithId -WorkspaceUrl $wsUrl -AadBearerToken $aadTok -LifetimeSeconds $PatLifetimeSeconds -Comment ("sanitychecks-{0}-{1}" -f $adh_group, $adh_subscription_type)
        if (-not $patObj -or [string]::IsNullOrWhiteSpace($patObj.Pat)) {
            $notes += [pscustomobject]@{
                SubscriptionName = $sub.Name
                WorkspaceName    = $wsName
                WorkspaceUrl     = $wsUrl
                AuthMode         = "AAD_TO_PAT"
                AuthOk           = $false
                Note             = "AUTH FAILED: could not create PAT using AAD token. SPN needs permission to create tokens. $script:LastDbxError"
            }
            continue
        }

        $bearer = $patObj.Pat
        $tokenIdForRevoke = $patObj.TokenId

        $notes += [pscustomobject]@{
            SubscriptionName = $sub.Name
            WorkspaceName    = $wsName
            WorkspaceUrl     = $wsUrl
            AuthMode         = "AAD_TO_PAT"
            AuthOk           = $true
            Note             = ("Auth OK. PAT created. TokenId=" + ($tokenIdForRevoke ?? ''))
        }

        # -------- UC probe: metastore attachment --------
        $ms = Invoke-DbRest -WorkspaceUrl $wsUrl -Method GET -Path "/api/2.1/unity-catalog/metastore" -BearerToken $bearer
        if ($ms) {
            $ucProbe += [pscustomobject]@{
                SubscriptionName = $sub.Name
                WorkspaceName    = $wsName
                WorkspaceUrl     = $wsUrl
                Status           = 'OK'
                UcMetastoreId    = $ms.metastore_id
                UcMetastoreName  = $ms.metastore_name
                DefaultCatalog    = $ms.default_catalog_name
                Note             = ''
            }
        } else {
            $ucProbe += [pscustomobject]@{
                SubscriptionName = $sub.Name
                WorkspaceName    = $wsName
                WorkspaceUrl     = $wsUrl
                Status           = 'ERROR'
                UcMetastoreId    = ''
                UcMetastoreName  = ''
                DefaultCatalog    = ''
                Note             = ("UC metastore probe failed. " + $script:LastDbxError)
            }
        }

        # -------- SQL Warehouses --------
        $wh = Invoke-DbRest -WorkspaceUrl $wsUrl -Method GET -Path "/api/2.0/sql/warehouses" -BearerToken $bearer
        if ($wh -and $wh.warehouses) {
            foreach ($w in $wh.warehouses) {
                $whRows += [pscustomobject]@{
                    SubscriptionName = $sub.Name
                    ResourceGroup    = $rg
                    WorkspaceName    = $wsName
                    WarehouseId      = $w.id
                    WarehouseName    = $w.name
                    State            = $w.state
                    ClusterSize      = $w.cluster_size
                    Note             = ''
                }

                $perm = Invoke-DbRest -WorkspaceUrl $wsUrl -Method GET -Path ("/api/2.0/permissions/warehouses/{0}" -f $w.id) -BearerToken $bearer
                if ($perm -and $perm.access_control_list) {
                    foreach ($ace in $perm.access_control_list) {
                        $ptype = 'unknown'
                        $pname = $null
                        if ($ace.user_name) { $ptype='user'; $pname=$ace.user_name }
                        elseif ($ace.group_name) { $ptype='group'; $pname=$ace.group_name }
                        elseif ($ace.service_principal_name) { $ptype='service_principal'; $pname=$ace.service_principal_name }

                        foreach ($p in @($ace.all_permissions)) {
                            $whPerms += [pscustomobject]@{
                                SubscriptionName = $sub.Name
                                WorkspaceName    = $wsName
                                WarehouseName    = $w.name
                                WarehouseId      = $w.id
                                PrincipalType    = $ptype
                                PrincipalName    = $pname
                                PermissionLevel  = $p.permission_level
                                Inherited        = $p.inherited
                                Note             = ''
                            }
                        }
                    }
                } else {
                    $whPerms += [pscustomobject]@{
                        SubscriptionName = $sub.Name
                        WorkspaceName    = $wsName
                        WarehouseName    = $w.name
                        WarehouseId      = $w.id
                        PrincipalType    = ''
                        PrincipalName    = ''
                        PermissionLevel  = ''
                        Inherited        = ''
                        Note             = ("Warehouse permissions blocked. " + $script:LastDbxError)
                    }
                }
            }
        } else {
            $whRows += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $rg
                WorkspaceName    = $wsName
                WarehouseId      = ''
                WarehouseName    = ''
                State            = ''
                ClusterSize      = ''
                Note             = ("No warehouses OR SQL API blocked. " + $script:LastDbxError)
            }
        }

        # -------- Unity Catalog: Catalogs + Permissions --------
        $cats = Invoke-DbRest -WorkspaceUrl $wsUrl -Method GET -Path "/api/2.1/unity-catalog/catalogs" -BearerToken $bearer
        if ($cats -and $cats.catalogs) {
            foreach ($c in $cats.catalogs) {
                $catRows += [pscustomobject]@{
                    SubscriptionName = $sub.Name
                    ResourceGroup    = $rg
                    WorkspaceName    = $wsName
                    CatalogName      = $c.name
                    Owner            = $c.owner
                    Comment          = $c.comment
                    Note             = ''
                }

                $cp = Invoke-DbRest -WorkspaceUrl $wsUrl -Method GET -Path ("/api/2.1/unity-catalog/permissions/catalogs/{0}" -f $c.name) -BearerToken $bearer
                if ($cp -and $cp.privilege_assignments) {
                    foreach ($pa in $cp.privilege_assignments) {
                        $catPerms += [pscustomobject]@{
                            SubscriptionName = $sub.Name
                            WorkspaceName    = $wsName
                            CatalogName      = $c.name
                            PrincipalName    = $pa.principal
                            Privileges       = ($pa.privileges -join ',')
                            Note             = ''
                        }
                    }
                } else {
                    $catPerms += [pscustomobject]@{
                        SubscriptionName = $sub.Name
                        WorkspaceName    = $wsName
                        CatalogName      = $c.name
                        PrincipalName    = ''
                        Privileges       = ''
                        Note             = ("Catalog permission API blocked. " + $script:LastDbxError)
                    }
                }
            }
        } else {
            $catRows += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $rg
                WorkspaceName    = $wsName
                CatalogName      = ''
                Owner            = ''
                Comment          = ''
                Note             = ("No catalogs OR UC API blocked. " + $script:LastDbxError)
            }
        }

        # -------- Unity Catalog: External Locations + Permissions --------
        $ext = Invoke-DbRest -WorkspaceUrl $wsUrl -Method GET -Path "/api/2.1/unity-catalog/external-locations" -BearerToken $bearer
        if ($ext -and $ext.external_locations) {
            foreach ($l in $ext.external_locations) {
                $extRows += [pscustomobject]@{
                    SubscriptionName = $sub.Name
                    ResourceGroup    = $rg
                    WorkspaceName    = $wsName
                    ExternalLocation = $l.name
                    Url              = $l.url
                    Owner            = $l.owner
                    Comment          = $l.comment
                    Note             = ''
                }

                $lp = Invoke-DbRest -WorkspaceUrl $wsUrl -Method GET -Path ("/api/2.1/unity-catalog/permissions/external-locations/{0}" -f $l.name) -BearerToken $bearer
                if ($lp -and $lp.privilege_assignments) {
                    foreach ($pa in $lp.privilege_assignments) {
                        $extPerms += [pscustomobject]@{
                            SubscriptionName = $sub.Name
                            WorkspaceName    = $wsName
                            ExternalLocation = $l.name
                            PrincipalName    = $pa.principal
                            Privileges       = ($pa.privileges -join ',')
                            Note             = ''
                        }
                    }
                } else {
                    $extPerms += [pscustomobject]@{
                        SubscriptionName = $sub.Name
                        WorkspaceName    = $wsName
                        ExternalLocation = $l.name
                        PrincipalName    = ''
                        Privileges       = ''
                        Note             = ("External location permission API blocked. " + $script:LastDbxError)
                    }
                }
            }
        } else {
            $extRows += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $rg
                WorkspaceName    = $wsName
                ExternalLocation = ''
                Url              = ''
                Owner            = ''
                Comment          = ''
                Note             = ("No external locations OR UC API blocked. " + $script:LastDbxError)
            }
        }

        # -------- Revoke PAT if requested --------
        if ($RevokeGeneratedPat -and $tokenIdForRevoke) {
            Write-Host "INFO: Revoking generated PAT for $wsName (token_id=$tokenIdForRevoke)" -ForegroundColor DarkYellow
            Revoke-DatabricksPat -WorkspaceUrl $wsUrl -AadBearerToken $aadTok -TokenId $tokenIdForRevoke
        }
    }
}

# -------- Ensure not-empty outputs --------
Ensure-AtLeastOneRow ([ref]$wsRows)   @{ SubscriptionName=''; SubscriptionId=''; ResourceGroup=''; WorkspaceName=''; Location=''; WorkspaceUrl=''; WorkspaceResourceId=''; Note='' }
Ensure-AtLeastOneRow ([ref]$ucProbe)  @{ SubscriptionName=''; WorkspaceName=''; WorkspaceUrl=''; Status=''; UcMetastoreId=''; UcMetastoreName=''; DefaultCatalog=''; Note='' }
Ensure-AtLeastOneRow ([ref]$whRows)   @{ SubscriptionName=''; ResourceGroup=''; WorkspaceName=''; WarehouseId=''; WarehouseName=''; State=''; ClusterSize=''; Note='' }
Ensure-AtLeastOneRow ([ref]$whPerms)  @{ SubscriptionName=''; WorkspaceName=''; WarehouseName=''; WarehouseId=''; PrincipalType=''; PrincipalName=''; PermissionLevel=''; Inherited=''; Note='' }
Ensure-AtLeastOneRow ([ref]$catRows)  @{ SubscriptionName=''; ResourceGroup=''; WorkspaceName=''; CatalogName=''; Owner=''; Comment=''; Note='' }
Ensure-AtLeastOneRow ([ref]$catPerms) @{ SubscriptionName=''; WorkspaceName=''; CatalogName=''; PrincipalName=''; Privileges=''; Note='' }
Ensure-AtLeastOneRow ([ref]$extRows)  @{ SubscriptionName=''; ResourceGroup=''; WorkspaceName=''; ExternalLocation=''; Url=''; Owner=''; Comment=''; Note='' }
Ensure-AtLeastOneRow ([ref]$extPerms) @{ SubscriptionName=''; WorkspaceName=''; ExternalLocation=''; PrincipalName=''; Privileges=''; Note='' }
Ensure-AtLeastOneRow ([ref]$notes)    @{ SubscriptionName=''; WorkspaceName=''; WorkspaceUrl=''; AuthMode=''; AuthOk=''; Note='' }

# -------- Output files (DB_<group>_<subtype>_<YYYYMMDD>_*.csv) --------
$stamp = Get-Date -Format 'yyyyMMdd'
$base  = "DB_{0}_{1}_{2}" -f $adh_group, $adh_subscription_type, $stamp

$csvWs     = Join-Path $OutputDir "$base`_ws.csv"
$csvUc     = Join-Path $OutputDir "$base`_uc_metastore.csv"
$csvWh     = Join-Path $OutputDir "$base`_wh.csv"
$csvWhP    = Join-Path $OutputDir "$base`_wh_permissions.csv"
$csvCat    = Join-Path $OutputDir "$base`_uc_catalogs.csv"
$csvCatP   = Join-Path $OutputDir "$base`_uc_catalog_permissions.csv"
$csvExt    = Join-Path $OutputDir "$base`_uc_external_locations.csv"
$csvExtP   = Join-Path $OutputDir "$base`_uc_external_location_permissions.csv"
$csvNote   = Join-Path $OutputDir "$base`_note.csv"

$wsRows   | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvWs
$ucProbe  | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvUc
$whRows   | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvWh
$whPerms  | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvWhP
$catRows  | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvCat
$catPerms | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvCatP
$extRows  | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvExt
$extPerms | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvExtP
$notes    | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvNote

Write-Host "`nDONE. CSV outputs:" -ForegroundColor Cyan
Write-Host " - $csvWs"
Write-Host " - $csvUc"
Write-Host " - $csvWh"
Write-Host " - $csvWhP"
Write-Host " - $csvCat"
Write-Host " - $csvCatP"
Write-Host " - $csvExt"
Write-Host " - $csvExtP"
Write-Host " - $csvNote"
exit 0
