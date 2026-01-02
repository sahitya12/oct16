# sanitychecks/scripts/Scan-Databricks.ps1
# FIXES:
# 1) Catalog/External Location permissions: use robust fallback.
#    - Try /unity-catalog/grants (newer)
#    - If 404/400/etc -> fallback to /unity-catalog/permissions/<type>/<name> (older / different workspaces)
# 2) REMOVE metastore output completely (no probe + no CSV)
# 3) Keep Gen SPN -> AAD token -> create short-lived PAT -> scan (preferred)

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

    # PAT lifetime created via token/create (seconds)
    [int]$PatLifetimeSeconds = 86400,

    # Revoke generated PAT after scan
    [switch]$RevokeGeneratedPat,

    # KV RBAC helpers (optional)
    [switch]$GrantRbac,
    [switch]$RevokeRbacAfter
)

Import-Module Az.Accounts, Az.Resources, Az.KeyVault -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

Ensure-Dir -Path $OutputDir | Out-Null

# ---------------- Helpers ----------------
function Normalize-Text([string]$s) { if ($null -eq $s) { '' } else { $s.Trim() } }

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

function Normalize-WorkspaceUrl([string]$u) {
    if ([string]::IsNullOrWhiteSpace($u)) { return '' }
    $u = $u.Trim().TrimEnd('/')
    if ($u -notmatch '^https?://') { $u = "https://$u" }
    return $u
}

function UrlEncode([string]$s) { [System.Uri]::EscapeDataString($s) }

function Is-SystemCatalog([string]$name) {
    if ([string]::IsNullOrWhiteSpace($name)) { return $true }
    $n = $name.ToLowerInvariant()
    return @('__databricks_internal','system','samples','hive_metastore') -contains $n
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
            $v = $v.Replace("`r","").Replace("`n","").Trim()
            $v = $v.Trim('"').Trim("'").Trim()
        }
        return @{ Value = $v; Error = '' }
    } catch {
        return @{ Value = $null; Error = $_.Exception.Message }
    }
}

# Global last error from DBX REST
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
            if ($one.Length -gt 0) { $msg = $msg + " | BODY=" + $one.Substring(0,[Math]::Min(400,$one.Length)) }
        }
        $script:LastDbxError = $msg
        return $null
    }
}

function Test-DbxAuth {
    param([Parameter(Mandatory)][string]$WorkspaceUrl, [Parameter(Mandatory)][string]$BearerToken)

    $me = Invoke-DbRest -WorkspaceUrl $WorkspaceUrl -Method GET -Path "/api/2.0/current-user" -BearerToken $BearerToken
    if ($me) { return $true }
    if ($script:LastDbxError -match 'HTTP=403') { return $true } # token valid but endpoint forbidden
    if ($script:LastDbxError -match 'HTTP=401') { return $false }

    $c = Invoke-DbRest -WorkspaceUrl $WorkspaceUrl -Method GET -Path "/api/2.0/clusters/list" -BearerToken $BearerToken
    if ($c) { return $true }
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

function New-DatabricksPatWithId {
    param(
        [Parameter(Mandatory)][string]$WorkspaceUrl,
        [Parameter(Mandatory)][string]$AadBearerToken,
        [int]$LifetimeSeconds = 86400,
        [string]$Comment = "sanitychecks-auto"
    )

    $json = (@{ lifetime_seconds = $LifetimeSeconds; comment = $Comment } | ConvertTo-Json -Depth 5)
    $resp = Invoke-DbRest -WorkspaceUrl $WorkspaceUrl -Method POST -Path "/api/2.0/token/create" `
        -BearerToken $AadBearerToken -Body $json -ContentType "application/json"

    if (-not $resp) { return $null }
    if ([string]::IsNullOrWhiteSpace($resp.token_value)) { return $null }

    $tokenId = $null
    try { $tokenId = $resp.token_info.token_id } catch {}
    return @{ Pat = $resp.token_value; TokenId = $tokenId }
}

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

function Get-DbxPatFromSpn {
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$SpnClientId,
        [Parameter(Mandatory)][string]$SpnClientSecret,
        [Parameter(Mandatory)][string]$WorkspaceUrl,
        [int]$LifetimeSeconds = 86400,
        [string]$Comment = "sanitychecks-auto"
    )

    $aadTok = Get-AadDatabricksToken -TenantId $TenantId -SpnClientId $SpnClientId -SpnClientSecret $SpnClientSecret
    if (-not $aadTok) { return $null }

    if (-not (Test-DbxAuth -WorkspaceUrl $WorkspaceUrl -BearerToken $aadTok)) { return $null }

    $patObj = New-DatabricksPatWithId -WorkspaceUrl $WorkspaceUrl -AadBearerToken $aadTok -LifetimeSeconds $LifetimeSeconds -Comment $Comment
    if (-not $patObj -or [string]::IsNullOrWhiteSpace($patObj.Pat)) { return $null }

    return @{ AadToken = $aadTok; Pat = $patObj.Pat; TokenId = $patObj.TokenId }
}

# ---- UC Grants helpers (catalog + external location) ----
function Get-UcGrants {
    param(
        [Parameter(Mandatory)][string]$WorkspaceUrl,
        [Parameter(Mandatory)][string]$Pat,
        [Parameter(Mandatory)][ValidateSet('CATALOG','EXTERNAL_LOCATION')][string]$SecurableType,
        [Parameter(Mandatory)][string]$SecurableName
    )

    $nameEnc = UrlEncode $SecurableName

    # 1) Try "grants" endpoint (works in many workspaces)
    $gr = Invoke-DbRest -WorkspaceUrl $WorkspaceUrl -Method GET `
        -Path "/api/2.1/unity-catalog/grants?securable_type=$SecurableType&securable_name=$nameEnc" `
        -BearerToken $Pat

    if ($gr -and $gr.privilege_assignments) {
        return @{ Mode='grants'; Ok=$true; Assignments=$gr.privilege_assignments; Error='' }
    }

    $err1 = $script:LastDbxError

    # 2) Fallback to permissions endpoint (older / different UC APIs)
    #    - catalogs: /permissions/catalogs/{name}
    #    - external locations: /permissions/external-locations/{name}
    $permPath = $null
    if ($SecurableType -eq 'CATALOG') { $permPath = "/api/2.1/unity-catalog/permissions/catalogs/$nameEnc" }
    else { $permPath = "/api/2.1/unity-catalog/permissions/external-locations/$nameEnc" }

    $p = Invoke-DbRest -WorkspaceUrl $WorkspaceUrl -Method GET -Path $permPath -BearerToken $Pat
    if ($p -and $p.privilege_assignments) {
        return @{ Mode='permissions'; Ok=$true; Assignments=$p.privilege_assignments; Error='' }
    }

    $err2 = $script:LastDbxError
    $combined = @()
    if ($err1) { $combined += "grants:$err1" }
    if ($err2) { $combined += "permissions:$err2" }
    return @{ Mode='none'; Ok=$false; Assignments=@(); Error=($combined -join " || ") }
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
Write-Host "INFO: PatLifetimeSeconds    = $PatLifetimeSeconds"
Write-Host "INFO: RevokeGeneratedPat    = $RevokeGeneratedPat"
Write-Host "INFO: GrantRbac             = $GrantRbac"
Write-Host "INFO: RevokeRbacAfter       = $RevokeRbacAfter"

if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure connection failed."
}

$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
if ($subs -isnot [System.Collections.IEnumerable]) { $subs = ,$subs }
if (-not $subs -or @($subs).Count -eq 0) { throw "No subscriptions resolved." }

Write-Host "INFO: Subscriptions = $(($subs | Select-Object -ExpandProperty Name) -join ', ')"

# SP object id (for temporary KV RBAC assignments)
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
        if ($ws.Properties.workspaceUrl) { $wsUrl = $ws.Properties.workspaceUrl }
        elseif ($ws.Properties.parameters.workspaceUrl.value) { $wsUrl = $ws.Properties.parameters.workspaceUrl.value }
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

        # -------- determine env (for KV lookup) --------
        $candidateEnvs = @()
        foreach ($e in $envs) {
            if ($wsName -match ("-{0}$" -f [Regex]::Escape($e)) -or $wsName -match ("_{0}$" -f [Regex]::Escape($e))) {
                $candidateEnvs += $e
            }
        }
        if ($candidateEnvs.Count -eq 0) { $candidateEnvs = $envs }

        # -------- Auth: Prefer Gen SPN from KV -> AAD -> PAT --------
        $pat = $null
        $aadUsed = $null
        $tokenIdForRevoke = $null
        $authMode = ''
        $kvUsed = ''
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

            $genCid = Get-SecretVerbose -VaultName $kvName -SecretName "ADH-Gen-SPN-ClientID"
            $genCse = Get-SecretVerbose -VaultName $kvName -SecretName "ADH-Gen-SPN-ClientSecret"

            if ($genCid.Error) { $reason.Add("KV '$kvName' 'ADH-Gen-SPN-ClientID' read failed: $($genCid.Error)") | Out-Null }
            if ($genCse.Error) { $reason.Add("KV '$kvName' 'ADH-Gen-SPN-ClientSecret' read failed: $($genCse.Error)") | Out-Null }

            if (-not [string]::IsNullOrWhiteSpace($genCid.Value) -and -not [string]::IsNullOrWhiteSpace($genCse.Value)) {
                $r = Get-DbxPatFromSpn -TenantId $TenantId -SpnClientId $genCid.Value -SpnClientSecret $genCse.Value `
                    -WorkspaceUrl $wsUrl -LifetimeSeconds $PatLifetimeSeconds -Comment "sanitychecks-gen-spn"

                if ($r) {
                    $pat = $r.Pat
                    $aadUsed = $r.AadToken
                    $tokenIdForRevoke = $r.TokenId
                    $authMode = "GEN_SPN_AAD_TO_PAT"
                    $kvUsed = $kvName
                    break
                } else {
                    $reason.Add("Gen SPN -> PAT failed for KV '$kvName' on workspace '$wsName'. $script:LastDbxError") | Out-Null
                }
            }
        }

        # Fallback to pipeline SPN -> AAD -> PAT
        if (-not $pat) {
            $r = Get-DbxPatFromSpn -TenantId $TenantId -SpnClientId $ClientId -SpnClientSecret $ClientSecret `
                -WorkspaceUrl $wsUrl -LifetimeSeconds $PatLifetimeSeconds -Comment "sanitychecks-pipeline-spn"
            if ($r) {
                $pat = $r.Pat
                $aadUsed = $r.AadToken
                $tokenIdForRevoke = $r.TokenId
                $authMode = "PIPELINE_SPN_AAD_TO_PAT"
            } else {
                $reason.Add("Pipeline SPN -> PAT failed on workspace '$wsName'. $script:LastDbxError") | Out-Null
            }
        }

        if (-not $pat) {
            $notes += [pscustomobject]@{
                SubscriptionName = $sub.Name
                WorkspaceName    = $wsName
                WorkspaceUrl     = $wsUrl
                InfraKVUsed      = $kvUsed
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
            AuthMode         = $authMode
            AuthOk           = $true
            Note             = "Auth OK"
        }

        # -------- SQL Warehouses --------
        $wh = Invoke-DbRest -WorkspaceUrl $wsUrl -Method GET -Path "/api/2.0/sql/warehouses" -BearerToken $pat
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

                $perm = Invoke-DbRest -WorkspaceUrl $wsUrl -Method GET -Path ("/api/2.0/permissions/warehouses/{0}" -f $w.id) -BearerToken $pat
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

        # -------- Unity Catalog: Catalogs + Grants --------
        $cats = Invoke-DbRest -WorkspaceUrl $wsUrl -Method GET -Path "/api/2.1/unity-catalog/catalogs" -BearerToken $pat
        if ($cats -and $cats.catalogs) {
            foreach ($c in $cats.catalogs) {
                $catName = $c.name

                $catRows += [pscustomobject]@{
                    SubscriptionName = $sub.Name
                    ResourceGroup    = $rg
                    WorkspaceName    = $wsName
                    CatalogName      = $catName
                    Owner            = $c.owner
                    Comment          = $c.comment
                    Note             = ''
                }

                if (Is-SystemCatalog $catName) {
                    $catPerms += [pscustomobject]@{
                        SubscriptionName = $sub.Name
                        WorkspaceName    = $wsName
                        CatalogName      = $catName
                        PrincipalName    = ''
                        Privileges       = ''
                        Note             = 'SKIPPED: system/internal catalog'
                    }
                    continue
                }

                $g = Get-UcGrants -WorkspaceUrl $wsUrl -Pat $pat -SecurableType 'CATALOG' -SecurableName $catName
                if ($g.Ok -and $g.Assignments) {
                    foreach ($pa in $g.Assignments) {
                        $catPerms += [pscustomobject]@{
                            SubscriptionName = $sub.Name
                            WorkspaceName    = $wsName
                            CatalogName      = $catName
                            PrincipalName    = $pa.principal
                            Privileges       = ($pa.privileges -join ',')
                            Note             = "OK ($($g.Mode))"
                        }
                    }
                } else {
                    $catPerms += [pscustomobject]@{
                        SubscriptionName = $sub.Name
                        WorkspaceName    = $wsName
                        CatalogName      = $catName
                        PrincipalName    = ''
                        Privileges       = ''
                        Note             = ("CANNOT_VIEW_GRANTS. " + $g.Error)
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

        # -------- Unity Catalog: External Locations + Grants --------
        $ext = Invoke-DbRest -WorkspaceUrl $wsUrl -Method GET -Path "/api/2.1/unity-catalog/external-locations" -BearerToken $pat
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

                $g2 = Get-UcGrants -WorkspaceUrl $wsUrl -Pat $pat -SecurableType 'EXTERNAL_LOCATION' -SecurableName $l.name
                if ($g2.Ok -and $g2.Assignments) {
                    foreach ($pa in $g2.Assignments) {
                        $extPerms += [pscustomobject]@{
                            SubscriptionName = $sub.Name
                            WorkspaceName    = $wsName
                            ExternalLocation = $l.name
                            PrincipalName    = $pa.principal
                            Privileges       = ($pa.privileges -join ',')
                            Note             = "OK ($($g2.Mode))"
                        }
                    }
                } else {
                    $extPerms += [pscustomobject]@{
                        SubscriptionName = $sub.Name
                        WorkspaceName    = $wsName
                        ExternalLocation = $l.name
                        PrincipalName    = ''
                        Privileges       = ''
                        Note             = ("CANNOT_VIEW_GRANTS. " + $g2.Error)
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

        # -------- revoke PAT --------
        if ($RevokeGeneratedPat -and $tokenIdForRevoke -and $aadUsed) {
            Write-Host "INFO: Revoking generated PAT for $wsName (token_id=$tokenIdForRevoke)" -ForegroundColor DarkYellow
            Revoke-DatabricksPat -WorkspaceUrl $wsUrl -AadBearerToken $aadUsed -TokenId $tokenIdForRevoke
        }
    }
}

# -------- Revoke temporary KV RBAC if requested --------
if ($RevokeRbacAfter -and $rbacToRevoke.Count -gt 0) {
    Write-Host "`nRevoking temporary Key Vault RBAC..." -ForegroundColor Yellow
    foreach ($r in $rbacToRevoke) {
        Remove-RbacRole -ObjectId $r.ObjectId -Scope $r.Scope -RoleName $r.Role
    }
}

# -------- Ensure not-empty outputs --------
Ensure-AtLeastOneRow ([ref]$wsRows)   @{ SubscriptionName=''; SubscriptionId=''; ResourceGroup=''; WorkspaceName=''; Location=''; WorkspaceUrl=''; WorkspaceResourceId=''; Note='' }
Ensure-AtLeastOneRow ([ref]$whRows)   @{ SubscriptionName=''; ResourceGroup=''; WorkspaceName=''; WarehouseId=''; WarehouseName=''; State=''; ClusterSize=''; Note='' }
Ensure-AtLeastOneRow ([ref]$whPerms)  @{ SubscriptionName=''; WorkspaceName=''; WarehouseName=''; WarehouseId=''; PrincipalType=''; PrincipalName=''; PermissionLevel=''; Inherited=''; Note='' }
Ensure-AtLeastOneRow ([ref]$catRows)  @{ SubscriptionName=''; ResourceGroup=''; WorkspaceName=''; CatalogName=''; Owner=''; Comment=''; Note='' }
Ensure-AtLeastOneRow ([ref]$catPerms) @{ SubscriptionName=''; WorkspaceName=''; CatalogName=''; PrincipalName=''; Privileges=''; Note='' }
Ensure-AtLeastOneRow ([ref]$extRows)  @{ SubscriptionName=''; ResourceGroup=''; WorkspaceName=''; ExternalLocation=''; Url=''; Owner=''; Comment=''; Note='' }
Ensure-AtLeastOneRow ([ref]$extPerms) @{ SubscriptionName=''; WorkspaceName=''; ExternalLocation=''; PrincipalName=''; Privileges=''; Note='' }
Ensure-AtLeastOneRow ([ref]$notes)    @{ SubscriptionName=''; WorkspaceName=''; WorkspaceUrl=''; InfraKVUsed=''; AuthMode=''; AuthOk=''; Note='' }

# -------- Output files (metastore removed) --------
$stamp = Get-Date -Format 'yyyyMMdd'
$base  = "DB_{0}_{1}_{2}" -f $adh_group, $adh_subscription_type, $stamp

$csvWs     = Join-Path $OutputDir "$base`_ws.csv"
$csvWh     = Join-Path $OutputDir "$base`_wh.csv"
$csvWhP    = Join-Path $OutputDir "$base`_wh_permissions.csv"
$csvCat    = Join-Path $OutputDir "$base`_uc_catalogs.csv"
$csvCatP   = Join-Path $OutputDir "$base`_uc_catalog_permissions.csv"
$csvExt    = Join-Path $OutputDir "$base`_uc_external_locations.csv"
$csvExtP   = Join-Path $OutputDir "$base`_uc_external_location_permissions.csv"
$csvNote   = Join-Path $OutputDir "$base`_note.csv"

$wsRows   | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvWs
$whRows   | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvWh
$whPerms  | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvWhP
$catRows  | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvCat
$catPerms | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvCatP
$extRows  | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvExt
$extPerms | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvExtP
$notes    | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvNote

Write-Host "`nDONE. CSV outputs:" -ForegroundColor Cyan
Write-Host " - $csvWs"
Write-Host " - $csvWh"
Write-Host " - $csvWhP"
Write-Host " - $csvCat"
Write-Host " - $csvCatP"
Write-Host " - $csvExt"
Write-Host " - $csvExtP"
Write-Host " - $csvNote"
exit 0
