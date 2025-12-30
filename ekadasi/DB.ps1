# sanitychecks/scripts/Scan-Databricks-UC.ps1
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
function Normalize-Text([string]$s) { if ($null -eq $s) { '' } else { $s.Trim() } }

function Get-EnvList([string]$subType) { if ($subType -eq 'prd') { @('prd') } else { @('dev','tst','stg') } }

function Build-InfraKvName([string]$group, [string]$subGroup, [string]$env) {
    if ([string]::IsNullOrWhiteSpace($subGroup)) {
        "ADH-{0}-Infra-KV-{1}" -f $group.ToUpper(), $env
    } else {
        "ADH-{0}-{1}-Infra-KV-{2}" -f $group.ToUpper(), $subGroup.ToUpper(), $env
    }
}

function Ensure-RbacRole {
    param([Parameter(Mandatory)][string]$ObjectId,[Parameter(Mandatory)][string]$Scope,[Parameter(Mandatory)][string]$RoleName)
    try {
        $existing = Get-AzRoleAssignment -ObjectId $ObjectId -RoleDefinitionName $RoleName -Scope $Scope -ErrorAction SilentlyContinue
        if (-not $existing) {
            New-AzRoleAssignment -ObjectId $ObjectId -RoleDefinitionName $RoleName -Scope $Scope -ErrorAction Stop | Out-Null
            Write-Host "RBAC: Assigned '$RoleName' on $Scope" -ForegroundColor Green
            Start-Sleep -Seconds 15
        }
    } catch {
        Write-Warning "RBAC: Failed assign '$RoleName' on $Scope : $($_.Exception.Message)"
    }
}

function Remove-RbacRole {
    param([Parameter(Mandatory)][string]$ObjectId,[Parameter(Mandatory)][string]$Scope,[Parameter(Mandatory)][string]$RoleName)
    try {
        $assignments = Get-AzRoleAssignment -ObjectId $ObjectId -RoleDefinitionName $RoleName -Scope $Scope -ErrorAction SilentlyContinue
        foreach ($a in @($assignments)) { Remove-AzRoleAssignment -RoleAssignmentId $a.Id -ErrorAction SilentlyContinue }
    } catch {
        Write-Warning "RBAC: Failed revoke '$RoleName' on $Scope : $($_.Exception.Message)"
    }
}

function Get-SecretSafe {
    param([Parameter(Mandatory)][string]$VaultName,[Parameter(Mandatory)][string]$SecretName)
    try { (Get-AzKeyVaultSecret -VaultName $VaultName -Name $SecretName -ErrorAction Stop).SecretValueText } catch { $null }
}

function Test-DatabricksPat([string]$Token) {
    if ([string]::IsNullOrWhiteSpace($Token)) { return $false }
    $t = $Token.Trim()
    return ($t.Length -ge 10 -and $t.StartsWith('dapi'))
}

# Global last REST error
$script:LastDbxError = ''

function Invoke-DbRestPat {
    param(
        [Parameter(Mandatory)][string]$WorkspaceUrl,
        [Parameter(Mandatory)][ValidateSet('GET','POST','PUT','PATCH','DELETE')][string]$Method,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$PatToken,
        [string]$Body = $null
    )

    $script:LastDbxError = ''
    $tok = $PatToken.Trim()

    # WorkspaceUrl sometimes is "adb-xxx.azuredatabricks.net"
    $hostPart = ($WorkspaceUrl -replace '^https://','').Trim().TrimEnd('/')
    $uri = "https://$hostPart$Path"

    $headers = @{ Authorization = "Bearer $tok" }

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
            $msg = $msg + " | BODY=" + $one.Substring(0,[Math]::Min(300,$one.Length))
        }
        $script:LastDbxError = $msg
        return $null
    }
}

function Ensure-AtLeastOneRow([ref]$arr, [hashtable]$row) {
    if (-not $arr.Value -or @($arr.Value).Count -eq 0) { $arr.Value = @([pscustomobject]$row) }
}

# ---------------- Start ----------------
$adh_sub_group = Normalize-Text $adh_sub_group

Write-Host "INFO: adh_group             = $adh_group"
Write-Host "INFO: adh_sub_group         = '$adh_sub_group'"
Write-Host "INFO: adh_subscription_type = $adh_subscription_type"
Write-Host "INFO: OutputDir             = $OutputDir"

if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure connection failed."
}

$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
if ($subs -isnot [System.Collections.IEnumerable]) { $subs = ,$subs }
if (-not $subs -or @($subs).Count -eq 0) { throw "No subscriptions resolved." }

Write-Host "INFO: Subscriptions = $(($subs | Select-Object -ExpandProperty Name) -join ', ')"

# SP object id (for KV RBAC assignment)
$spObjectId = $null
try {
    $spObjectId = (Get-AzADServicePrincipal -ApplicationId $ClientId -ErrorAction Stop).Id
} catch {
    Write-Warning "Unable to resolve SP object id from ClientId. KV RBAC grant may fail."
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

    # IMPORTANT: don't swallow errors here
    $wsResources = $null
    try {
        $wsResources = Get-AzResource -ResourceType "Microsoft.Databricks/workspaces" -ExpandProperties -ErrorAction Stop
    } catch {
        $notes += [pscustomobject]@{
            SubscriptionName = $sub.Name
            WorkspaceName    = ''
            WorkspaceUrl     = ''
            InfraKVUsed      = ''
            TokenSecretUsed  = ''
            PatValid         = $false
            Note             = "Get-AzResource(workspaces) FAILED: $($_.Exception.Message)"
        }
        continue
    }

    if (-not $wsResources -or @($wsResources).Count -eq 0) {
        $notes += [pscustomobject]@{
            SubscriptionName = $sub.Name
            WorkspaceName    = ''
            WorkspaceUrl     = ''
            InfraKVUsed      = ''
            TokenSecretUsed  = ''
            PatValid         = $false
            Note             = "No Databricks workspaces found in this subscription (or no RBAC permission to list them)."
        }
        continue
    }

    foreach ($ws in $wsResources) {
        $wsName = $ws.Name
        $rg     = $ws.ResourceGroupName
        $loc    = $ws.Location
        $wsId   = $ws.ResourceId

        # workspaceUrl
        $wsUrl = $null
        try {
            if ($ws.Properties.workspaceUrl) { $wsUrl = $ws.Properties.workspaceUrl }
            elseif ($ws.Properties.parameters.workspaceUrl.value) { $wsUrl = $ws.Properties.parameters.workspaceUrl.value }
        } catch {}

        $wsRows += [pscustomobject]@{
            SubscriptionName    = $sub.Name
            SubscriptionId      = $sub.Id
            ResourceGroup       = $rg
            WorkspaceName       = $wsName
            Location            = $loc
            WorkspaceUrl        = ($wsUrl ?? '')
            WorkspaceResourceId = $wsId
            Note                = (if ($wsUrl) { '' } else { 'workspaceUrl missing in ARM properties' })
        }

        if (-not $wsUrl) {
            $notes += [pscustomobject]@{
                SubscriptionName = $sub.Name
                WorkspaceName    = $wsName
                WorkspaceUrl     = ''
                InfraKVUsed      = ''
                TokenSecretUsed  = ''
                PatValid         = $false
                Note             = "Skipping REST: workspaceUrl not available from ARM for this workspace."
            }
            continue
        }

        # -------- determine env for KV lookup --------
        $candidateEnvs = @()
        foreach ($e in $envs) {
            if ($wsName -match ("-{0}$" -f [Regex]::Escape($e)) -or $wsName -match ("_{0}$" -f [Regex]::Escape($e))) {
                $candidateEnvs += $e
            }
        }
        if ($candidateEnvs.Count -eq 0) { $candidateEnvs = $envs }

        $patToken = $null
        $kvUsed   = $null
        $tokenSecretUsed = $null

        foreach ($env in $candidateEnvs) {
            $kvName = Build-InfraKvName -group $adh_group -subGroup $adh_sub_group -env $env

            $kvRes = $null
            try {
                $kvRes = Get-AzResource -ResourceType "Microsoft.KeyVault/vaults" -Name $kvName -ErrorAction Stop
            } catch { continue }

            $kvScope = $kvRes.ResourceId

            if ($GrantRbac -and $spObjectId) {
                Ensure-RbacRole -ObjectId $spObjectId -Scope $kvScope -RoleName "Key Vault Secrets User"
                if ($RevokeRbacAfter) {
                    $rbacToRevoke.Add([pscustomobject]@{ ObjectId=$spObjectId; Scope=$kvScope; Role="Key Vault Secrets User" })
                }
            }

            # MUST use PAT from either of these secrets
            $candidateSecrets = @(
                "SPN-TOKEN-ADH-PLATFORM-ADO-CONFIGURATION",
                "SPN-TOKEN-ADH-PLATFORM-TERRAFORM-CONFIGURATION"
            )

            foreach ($sec in $candidateSecrets) {
                $tmp = Get-SecretSafe -VaultName $kvName -SecretName $sec
                if ($tmp) { $tmp = $tmp.Trim() }
                if (Test-DatabricksPat $tmp) {
                    $patToken = $tmp
                    $tokenSecretUsed = $sec
                    $kvUsed = $kvName
                    break
                }
            }

            if ($patToken) { break }
        }

        if (-not $patToken) {
            $notes += [pscustomobject]@{
                SubscriptionName = $sub.Name
                WorkspaceName    = $wsName
                WorkspaceUrl     = $wsUrl
                InfraKVUsed      = ($kvUsed ?? '')
                TokenSecretUsed  = ''
                PatValid         = $false
                Note             = "No VALID Databricks PAT found in KV secrets (must start with 'dapi'). Checked env(s): $($candidateEnvs -join ', ')"
            }
            continue
        }

        # ---------- UC probe ----------
        $ms = Invoke-DbRestPat -WorkspaceUrl $wsUrl -Method GET -Path "/api/2.1/unity-catalog/metastore" -PatToken $patToken
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
                Note             = $script:LastDbxError
            }
        }

        # ---------- SQL Warehouses ----------
        $wh = Invoke-DbRestPat -WorkspaceUrl $wsUrl -Method GET -Path "/api/2.0/sql/warehouses" -PatToken $patToken
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

                $perm = Invoke-DbRestPat -WorkspaceUrl $wsUrl -Method GET -Path ("/api/2.0/permissions/warehouses/{0}" -f $w.id) -PatToken $patToken
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
                        Note             = $script:LastDbxError
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
                Note             = $script:LastDbxError
            }
        }

        # ---------- UC objects only if metastore probe OK ----------
        $ucIsOk = ($ucProbe | Where-Object { $_.SubscriptionName -eq $sub.Name -and $_.WorkspaceName -eq $wsName -and $_.Status -eq 'OK' } | Select-Object -First 1)

        if ($ucIsOk) {
            $cats = Invoke-DbRestPat -WorkspaceUrl $wsUrl -Method GET -Path "/api/2.1/unity-catalog/catalogs" -PatToken $patToken
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

                    $cp = Invoke-DbRestPat -WorkspaceUrl $wsUrl -Method GET -Path ("/api/2.1/unity-catalog/permissions/catalogs/{0}" -f $c.name) -PatToken $patToken
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
                            Note             = $script:LastDbxError
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
                    Note             = $script:LastDbxError
                }
            }

            $ext = Invoke-DbRestPat -WorkspaceUrl $wsUrl -Method GET -Path "/api/2.1/unity-catalog/external-locations" -PatToken $patToken
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

                    $lp = Invoke-DbRestPat -WorkspaceUrl $wsUrl -Method GET -Path ("/api/2.1/unity-catalog/permissions/external-locations/{0}" -f $l.name) -PatToken $patToken
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
                            Note             = $script:LastDbxError
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
                    Note             = $script:LastDbxError
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
                Note             = "Skipped: UC metastore not accessible. See _db_uc_metastore.csv"
            }
            $extRows += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $rg
                WorkspaceName    = $wsName
                ExternalLocation = ''
                Url              = ''
                Owner            = ''
                Comment          = ''
                Note             = "Skipped: UC metastore not accessible. See _db_uc_metastore.csv"
            }
        }

        # Always log note per workspace (so you never get “all null” again)
        $notes += [pscustomobject]@{
            SubscriptionName = $sub.Name
            WorkspaceName    = $wsName
            WorkspaceUrl     = $wsUrl
            InfraKVUsed      = $kvUsed
            TokenSecretUsed  = $tokenSecretUsed
            PatValid         = $true
            Note             = ''
        }
    }
}

# revoke temp RBAC
if ($RevokeRbacAfter -and $rbacToRevoke.Count -gt 0) {
    foreach ($r in $rbacToRevoke) {
        Remove-RbacRole -ObjectId $r.ObjectId -Scope $r.Scope -RoleName $r.Role
    }
}

# Ensure not-empty outputs
Ensure-AtLeastOneRow ([ref]$wsRows)   @{ SubscriptionName=''; SubscriptionId=''; ResourceGroup=''; WorkspaceName=''; Location=''; WorkspaceUrl=''; WorkspaceResourceId=''; Note='' }
Ensure-AtLeastOneRow ([ref]$ucProbe)  @{ SubscriptionName=''; WorkspaceName=''; WorkspaceUrl=''; Status=''; UcMetastoreId=''; UcMetastoreName=''; DefaultCatalog=''; Note='' }
Ensure-AtLeastOneRow ([ref]$whRows)   @{ SubscriptionName=''; ResourceGroup=''; WorkspaceName=''; WarehouseId=''; WarehouseName=''; State=''; ClusterSize=''; Note='' }
Ensure-AtLeastOneRow ([ref]$whPerms)  @{ SubscriptionName=''; WorkspaceName=''; WarehouseName=''; WarehouseId=''; PrincipalType=''; PrincipalName=''; PermissionLevel=''; Inherited=''; Note='' }
Ensure-AtLeastOneRow ([ref]$catRows)  @{ SubscriptionName=''; ResourceGroup=''; WorkspaceName=''; CatalogName=''; Owner=''; Comment=''; Note='' }
Ensure-AtLeastOneRow ([ref]$catPerms) @{ SubscriptionName=''; WorkspaceName=''; CatalogName=''; PrincipalName=''; Privileges=''; Note='' }
Ensure-AtLeastOneRow ([ref]$extRows)  @{ SubscriptionName=''; ResourceGroup=''; WorkspaceName=''; ExternalLocation=''; Url=''; Owner=''; Comment=''; Note='' }
Ensure-AtLeastOneRow ([ref]$extPerms) @{ SubscriptionName=''; WorkspaceName=''; ExternalLocation=''; PrincipalName=''; Privileges=''; Note='' }
Ensure-AtLeastOneRow ([ref]$notes)    @{ SubscriptionName=''; WorkspaceName=''; WorkspaceUrl=''; InfraKVUsed=''; TokenSecretUsed=''; PatValid=''; Note='' }

# Output files
$stamp = Get-Date -Format 'yyyyMMdd'
$base  = "{0}_{1}_{2}" -f $adh_group, $adh_subscription_type, $stamp

$csvWs     = Join-Path $OutputDir "$base`_db_ws.csv"
$csvUc     = Join-Path $OutputDir "$base`_db_uc_metastore.csv"
$csvWh     = Join-Path $OutputDir "$base`_db_wh.csv"
$csvWhP    = Join-Path $OutputDir "$base`_db_wh_permissions.csv"
$csvCat    = Join-Path $OutputDir "$base`_db_uc_catalogs.csv"
$csvCatP   = Join-Path $OutputDir "$base`_db_uc_catalog_permissions.csv"
$csvExt    = Join-Path $OutputDir "$base`_db_uc_external_locations.csv"
$csvExtP   = Join-Path $OutputDir "$base`_db_uc_external_location_permissions.csv"
$csvNote   = Join-Path $OutputDir "$base`_db_note.csv"

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
