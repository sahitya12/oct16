# sanitychecks/scripts/Scan-Databricks.ps1
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

    [switch]$GrantRbac,
    [switch]$RevokeRbacAfter
)

Import-Module Az.Accounts, Az.Resources, Az.KeyVault -ErrorAction Stop
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

function Build-InfraKvName([string]$group, [string]$subGroup, [string]$env) {
    if ([string]::IsNullOrWhiteSpace($subGroup)) {
        return ("ADH-{0}-Infra-KV-{1}" -f $group.ToUpper(), $env)
    }
    return ("ADH-{0}-{1}-Infra-KV-{2}" -f $group.ToUpper(), $subGroup.ToUpper(), $env)
}

function Ensure-RbacRole {
    param(
        [Parameter(Mandatory)][string]$ObjectId,
        [Parameter(Mandatory)][string]$Scope,
        [Parameter(Mandatory)][string]$RoleName
    )
    try {
        $existing = Get-AzRoleAssignment -ObjectId $ObjectId -RoleDefinitionName $RoleName -Scope $Scope -ErrorAction SilentlyContinue
        if (-not $existing) {
            New-AzRoleAssignment -ObjectId $ObjectId -RoleDefinitionName $RoleName -Scope $Scope -ErrorAction Stop | Out-Null
            Write-Host "RBAC: Assigned '$RoleName' on $Scope" -ForegroundColor Green
            Start-Sleep -Seconds 25
        }
    } catch {
        Write-Warning "RBAC: Failed assign '$RoleName' on $Scope : $($_.Exception.Message)"
    }
}

function Remove-RbacRole {
    param(
        [Parameter(Mandatory)][string]$ObjectId,
        [Parameter(Mandatory)][string]$Scope,
        [Parameter(Mandatory)][string]$RoleName
    )
    try {
        $assignments = Get-AzRoleAssignment -ObjectId $ObjectId -RoleDefinitionName $RoleName -Scope $Scope -ErrorAction SilentlyContinue
        foreach ($a in @($assignments)) {
            Remove-AzRoleAssignment -RoleAssignmentId $a.Id -ErrorAction SilentlyContinue
        }
        if ($assignments) {
            Write-Host "RBAC: Revoked '$RoleName' on $Scope" -ForegroundColor DarkYellow
        }
    } catch {
        Write-Warning "RBAC: Failed revoke '$RoleName' on $Scope : $($_.Exception.Message)"
    }
}

# Returns object: @{ Value=...; Error=... }
function Get-SecretVerbose {
    param(
        [Parameter(Mandatory)][string]$VaultName,
        [Parameter(Mandatory)][string]$SecretName
    )
    try {
        $s = Get-AzKeyVaultSecret -VaultName $VaultName -Name $SecretName -ErrorAction Stop
        $v = $s.SecretValueText
        if ($null -ne $v) {
            # sanitize (remove quotes/newlines/spaces that often come from KV imports)
            $v = $v.Replace("`r","").Replace("`n","").Trim()
            $v = $v.Trim('"').Trim("'").Trim()
        }
        return @{ Value = $v; Error = '' }
    } catch {
        return @{ Value = $null; Error = $_.Exception.Message }
    }
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
        [string]$Body = $null
    )

    $script:LastDbxError = ''

    $WorkspaceUrl = Normalize-WorkspaceUrl $WorkspaceUrl
    $hostPart = $WorkspaceUrl -replace '^https?://',''
    $uri = "https://$hostPart$Path"

    $headers = @{ Authorization = "Bearer $BearerToken" }

    try {
        if ($Body) {
            return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers -ContentType 'application/json' -Body $Body -ErrorAction Stop
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

function LooksLikeDbxPat([string]$v) {
    if ([string]::IsNullOrWhiteSpace($v)) { return $false }
    return ($v.Trim() -match '^dapi')
}

function LooksLikeJwt([string]$v) {
    if ([string]::IsNullOrWhiteSpace($v)) { return $false }
    return ($v.Trim().StartsWith('eyJ') -and ($v -split '\.').Count -ge 3)
}

# IMPORTANT FIX:
# - Token validation must not fail just because SCIM/current-user is forbidden.
# - Treat 403 as "token is valid, but this API is not allowed".
function Test-DbxAuth {
    param(
        [Parameter(Mandatory)][string]$WorkspaceUrl,
        [Parameter(Mandatory)][string]$BearerToken
    )

    # Prefer current-user (common) and interpret 403 correctly.
    $resp = Invoke-DbRest -WorkspaceUrl $WorkspaceUrl -Method GET -Path "/api/2.0/current-user" -BearerToken $BearerToken
    if ($resp) { return $true }

    if ($script:LastDbxError -match 'HTTP=403') { return $true }   # authenticated, forbidden
    if ($script:LastDbxError -match 'HTTP=401') { return $false }  # not authenticated

    # Try a second endpoint (clusters list) for robustness
    $resp2 = Invoke-DbRest -WorkspaceUrl $WorkspaceUrl -Method GET -Path "/api/2.0/clusters/list" -BearerToken $BearerToken
    if ($resp2) { return $true }

    if ($script:LastDbxError -match 'HTTP=403') { return $true }
    if ($script:LastDbxError -match 'HTTP=401') { return $false }

    return $false
}

function Get-AadDatabricksToken {
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$SpnClientId,
        [Parameter(Mandatory)][string]$SpnClientSecret
    )
    try {
        # Azure Databricks resource App ID (standard)
        $scope = "2ff814a6-3304-4ab8-85cb-cd0e6f879c1d/.default"
        $body = @{
            client_id     = $SpnClientId
            client_secret = $SpnClientSecret
            grant_type    = "client_credentials"
            scope         = $scope
        }
        $tok = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
            -ContentType "application/x-www-form-urlencoded" -Body $body -ErrorAction Stop
        return $tok.access_token
    } catch {
        return $null
    }
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
Write-Host "INFO: GrantRbac             = $GrantRbac"
Write-Host "INFO: RevokeRbacAfter       = $RevokeRbacAfter"

if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure connection failed."
}

$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
if ($subs -isnot [System.Collections.IEnumerable]) { $subs = ,$subs }
if (-not $subs -or @($subs).Count -eq 0) { throw "No subscriptions resolved." }

Write-Host "INFO: Subscriptions = $(($subs | Select-Object -ExpandProperty Name) -join ', ')"

# SP object id (for RBAC assignments)
$spObjectId = $null
try {
    $sp = Get-AzADServicePrincipal -ApplicationId $ClientId -ErrorAction Stop
    $spObjectId = $sp.Id
} catch {
    Write-Warning "Unable to resolve SP object id from ClientId. RBAC grant may fail."
}

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

$rbacToRevoke = New-Object System.Collections.Generic.List[object]

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

        # -------- determine env for KV lookup --------
        $candidateEnvs = @()
        foreach ($e in $envs) {
            if ($wsName -match ("-{0}$" -f [Regex]::Escape($e)) -or $wsName -match ("_{0}$" -f [Regex]::Escape($e))) {
                $candidateEnvs += $e
            }
        }
        if ($candidateEnvs.Count -eq 0) { $candidateEnvs = $envs }

        # -------- Try to get an auth token --------
        $bearer = $null
        $authMode = ''
        $authOk = $false
        $kvUsed = ''
        $tokenSecretUsed = ''
        $checkedKvs = New-Object System.Collections.Generic.List[string]
        $reason = New-Object System.Collections.Generic.List[string]

        foreach ($env in $candidateEnvs) {
            $kvName = Build-InfraKvName -group $adh_group -subGroup $adh_sub_group -env $env
            $checkedKvs.Add($kvName) | Out-Null

            $kvRes = Get-AzResource -ResourceType "Microsoft.KeyVault/vaults" -Name $kvName -ErrorAction SilentlyContinue
            if (-not $kvRes) { continue }

            $kvScope = $kvRes.ResourceId

            if ($GrantRbac -and $spObjectId) {
                Ensure-RbacRole -ObjectId $spObjectId -Scope $kvScope -RoleName "Key Vault Secrets User"
                if ($RevokeRbacAfter) {
                    $rbacToRevoke.Add([pscustomobject]@{ ObjectId=$spObjectId; Scope=$kvScope; Role="Key Vault Secrets User" })
                }
            }

            # ---- 1) Try KV PAT tokens (dapi...) ----
            foreach ($secName in @("SPN-TOKEN-ADH-PLATFORM-ADO-CONFIGURATION","SPN-TOKEN-ADH-PLATFORM-TERRAFORM-CONFIGURATION","SPN-TOKEN-CUSTODIAN-GEN")) {
                $s = Get-SecretVerbose -VaultName $kvName -SecretName $secName
                if ($s.Error) {
                    $reason.Add("KV '$kvName' secret '$secName' read failed: $($s.Error)") | Out-Null
                    continue
                }

                if (-not [string]::IsNullOrWhiteSpace($s.Value)) {
                    if (LooksLikeDbxPat $s.Value -or LooksLikeJwt $s.Value) {
                        if (Test-DbxAuth -WorkspaceUrl $wsUrl -BearerToken $s.Value) {
                            $bearer = $s.Value
                            $authMode = "KV_DATABRICKS_PAT"
                            $authOk = $true
                            $kvUsed = $kvName
                            $tokenSecretUsed = $secName
                            break
                        } else {
                            $reason.Add("Token from '$kvName/$secName' rejected. $script:LastDbxError") | Out-Null
                        }
                    } else {
                        $reason.Add("KV '$kvName/$secName' is not a Databricks token (not dapi/JWT).") | Out-Null
                    }
                }
            }
            if ($authOk) { break }

            # ---- 2) Fallback: AAD token using Gen SPN ----
            $cid = Get-SecretVerbose -VaultName $kvName -SecretName "ADH-Gen-SPN-ClientID"
            $cse = Get-SecretVerbose -VaultName $kvName -SecretName "ADH-Gen-SPN-ClientSecret"

            if ($cid.Error) { $reason.Add("KV '$kvName' secret 'ADH-Gen-SPN-ClientID' read failed: $($cid.Error)") | Out-Null }
            if ($cse.Error) { $reason.Add("KV '$kvName' secret 'ADH-Gen-SPN-ClientSecret' read failed: $($cse.Error)") | Out-Null }

            if (-not [string]::IsNullOrWhiteSpace($cid.Value) -and -not [string]::IsNullOrWhiteSpace($cse.Value)) {
                $aadTok = Get-AadDatabricksToken -TenantId $TenantId -SpnClientId $cid.Value -SpnClientSecret $cse.Value
                if ($aadTok) {
                    if (Test-DbxAuth -WorkspaceUrl $wsUrl -BearerToken $aadTok) {
                        $bearer = $aadTok
                        $authMode = "AAD_GEN_SPN"
                        $authOk = $true
                        $kvUsed = $kvName
                        $tokenSecretUsed = "ADH-Gen-SPN-ClientID/ClientSecret"
                        break
                    } else {
                        $reason.Add("AAD token from Gen SPN in '$kvName' rejected. $script:LastDbxError") | Out-Null
                    }
                } else {
                    $reason.Add("Failed to obtain AAD token using Gen SPN secrets from '$kvName'.") | Out-Null
                }
            } else {
                $reason.Add("Gen SPN secrets missing/empty in '$kvName'.") | Out-Null
            }
        }

        if (-not $authOk) {
            $notes += [pscustomobject]@{
                SubscriptionName = $sub.Name
                WorkspaceName    = $wsName
                WorkspaceUrl     = $wsUrl
                InfraKVUsed      = $kvUsed
                TokenSecretUsed  = $tokenSecretUsed
                AuthMode         = $authMode
                AuthOk           = $false
                Note             = ("AUTH FAILED. Checked KVs: " + ($checkedKvs -join ', ') + " | " + (($reason | Select-Object -First 10) -join " || "))
            }
            continue
        }

        $notes += [pscustomobject]@{
            SubscriptionName = $sub.Name
            WorkspaceName    = $wsName
            WorkspaceUrl     = $wsUrl
            InfraKVUsed      = $kvUsed
            TokenSecretUsed  = $tokenSecretUsed
            AuthMode         = $authMode
            AuthOk           = $true
            Note             = "Auth OK"
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
    }
}

# -------- Revoke RBAC if requested --------
if ($RevokeRbacAfter -and $rbacToRevoke.Count -gt 0) {
    Write-Host "`nRevoking temporary RBAC..." -ForegroundColor Yellow
    foreach ($r in $rbacToRevoke) {
        Remove-RbacRole -ObjectId $r.ObjectId -Scope $r.Scope -RoleName $r.Role
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
Ensure-AtLeastOneRow ([ref]$notes)    @{ SubscriptionName=''; WorkspaceName=''; WorkspaceUrl=''; InfraKVUsed=''; TokenSecretUsed=''; AuthMode=''; AuthOk=''; Note='' }

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
