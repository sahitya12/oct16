# sanitychecks/scripts/Scan-Databricks.ps1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$ClientId,       # ADO login SPN (used for Az login)
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

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module Az.Accounts, Az.Resources, Az.KeyVault -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

Ensure-Dir -Path $OutputDir | Out-Null

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

function Get-SecretSafe([string]$VaultName, [string]$SecretName) {
    try { (Get-AzKeyVaultSecret -VaultName $VaultName -Name $SecretName -ErrorAction Stop).SecretValueText }
    catch { $null }
}

function Test-DatabricksPat([string]$Token) {
    if ([string]::IsNullOrWhiteSpace($Token)) { return $false }
    $t = $Token.Trim()
    return ($t.StartsWith('dapi') -and $t.Length -ge 20)
}

# Azure Databricks resource ID for AAD tokens
$DatabricksResource = "2ff814a6-3304-4ab8-85cb-cd0e6f879c1d"

$script:LastDbxError = ''

function Invoke-DbxRest {
    param(
        [Parameter(Mandatory)][string]$WorkspaceUrl,
        [Parameter(Mandatory)][ValidateSet('GET','POST','PUT','PATCH','DELETE')][string]$Method,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][hashtable]$Headers,
        [string]$Body = $null
    )
    $script:LastDbxError = ''
    $hostPart = ($WorkspaceUrl -replace '^https://','').Trim().TrimEnd('/')
    $uri = "https://$hostPart$Path"

    try {
        if ($Body) {
            return Invoke-RestMethod -Method $Method -Uri $uri -Headers $Headers -ContentType 'application/json' -Body $Body
        } else {
            return Invoke-RestMethod -Method $Method -Uri $uri -Headers $Headers
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

function Get-AadTokenClientCreds {
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$ClientSecret,
        [Parameter(Mandatory)][string]$Resource
    )
    # v1 endpoint (resource-based) works well for ADO/Windows agents
    $uri = "https://login.microsoftonline.com/$TenantId/oauth2/token"
    $body = @{
        grant_type    = "client_credentials"
        client_id     = $ClientId
        client_secret = $ClientSecret
        resource      = $Resource
    }
    try {
        $resp = Invoke-RestMethod -Method Post -Uri $uri -Body $body -ContentType "application/x-www-form-urlencoded"
        return $resp.access_token
    } catch {
        return $null
    }
}

function Ensure-AtLeastOneRow([ref]$arr, [hashtable]$row) {
    if (-not $arr.Value -or @($arr.Value).Count -eq 0) { $arr.Value = @([pscustomobject]$row) }
}

# ---------------- Start ----------------
$adh_sub_group = Normalize-Text $adh_sub_group

Write-Host "INFO: adh_group=$adh_group adh_sub_group='$adh_sub_group' subType=$adh_subscription_type OutputDir=$OutputDir"

if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure connection failed."
}

$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
if ($subs -isnot [System.Collections.IEnumerable]) { $subs = ,$subs }
if (-not $subs -or @($subs).Count -eq 0) { throw "No subscriptions resolved." }

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

$tokenSecrets = @(
    "SPN-TOKEN-ADH-PLATFORM-ADO-CONFIGURATION",
    "SPN-TOKEN-ADH-PLATFORM-TERRAFORM-CONFIGURATION"
)

foreach ($sub in $subs) {
    Set-ScContext -Subscription $sub
    Write-Host "`n=== Databricks scan: $($sub.Name) ($($sub.Id)) ==="

    $wsResources = Get-AzResource -ResourceType "Microsoft.Databricks/workspaces" -ExpandProperties -ErrorAction SilentlyContinue
    if (-not $wsResources -or @($wsResources).Count -eq 0) {
        $notes += [pscustomobject]@{
            SubscriptionName=$sub.Name; WorkspaceName=''; WorkspaceUrl=''; InfraKVUsed=''; TokenSecretUsed='';
            AuthMode=''; AuthOk=$false; Note="No workspaces found OR no permission to list."
        }
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

        $wsRows += [pscustomobject]@{
            SubscriptionName=$sub.Name; SubscriptionId=$sub.Id; ResourceGroup=$rg; WorkspaceName=$wsName;
            Location=$loc; WorkspaceUrl=($wsUrl ?? ''); WorkspaceResourceId=$wsId; Note=($wsUrl ? '' : 'workspaceUrl missing')
        }

        if (-not $wsUrl) {
            $notes += [pscustomobject]@{
                SubscriptionName=$sub.Name; WorkspaceName=$wsName; WorkspaceUrl='';
                InfraKVUsed=''; TokenSecretUsed=''; AuthMode=''; AuthOk=$false; Note="Skipping REST: workspaceUrl missing."
            }
            continue
        }

        # Build KV list (no guessing from workspace name -> always try all env KVs)
        $kvList = foreach ($env in $envs) {
            Build-InfraKvName -group $adh_group -subGroup $adh_sub_group -env $env
        }

        $patToken = $null
        $kvUsed = $null
        $tokenSecretUsed = $null

        $genSpnClientId = $null
        $genSpnClientSecret = $null

        foreach ($kvName in $kvList) {
            $kvRes = Get-AzResource -ResourceType "Microsoft.KeyVault/vaults" -Name $kvName -ErrorAction SilentlyContinue
            if (-not $kvRes) { continue }

            # Read Gen SPN creds too (for fallback)
            if (-not $genSpnClientId)     { $genSpnClientId     = Get-SecretSafe -VaultName $kvName -SecretName "ADH-Gen-SPN-ClientID" }
            if (-not $genSpnClientSecret) { $genSpnClientSecret = Get-SecretSafe -VaultName $kvName -SecretName "ADH-Gen-SPN-ClientSecret" }

            foreach ($sec in $tokenSecrets) {
                $tmp = Get-SecretSafe -VaultName $kvName -SecretName $sec
                if (Test-DatabricksPat $tmp) {
                    $patToken = $tmp.Trim()
                    $kvUsed = $kvName
                    $tokenSecretUsed = $sec
                    break
                }
            }
            if ($patToken) { break }
        }

        $headers = $null
        $authMode = ''
        $authOk = $false
        $authNote = ''

        if ($patToken) {
            $headers = @{ Authorization = "Bearer $patToken" }
            $authMode = "PAT"
            $authOk = $true
        }
        else {
            # Fallback: AAD OAuth token using Gen SPN
            if (-not [string]::IsNullOrWhiteSpace($genSpnClientId) -and -not [string]::IsNullOrWhiteSpace($genSpnClientSecret)) {
                $aadToken = Get-AadTokenClientCreds -TenantId $TenantId -ClientId $genSpnClientId.Trim() -ClientSecret $genSpnClientSecret.Trim() -Resource $DatabricksResource
                if ($aadToken) {
                    $headers = @{ Authorization = "Bearer $aadToken" }
                    $authMode = "AAD_SP"
                    $authOk = $true
                    $authNote = "Used Gen SPN OAuth (no dapi PAT in KV)."
                } else {
                    $authMode = "AAD_SP"
                    $authOk = $false
                    $authNote = "Gen SPN present but OAuth token fetch FAILED."
                }
            } else {
                $authMode = ""
                $authOk = $false
                $authNote = "No dapi PAT in KV and Gen SPN secrets missing."
            }
        }

        if (-not $authOk) {
            $notes += [pscustomobject]@{
                SubscriptionName=$sub.Name; WorkspaceName=$wsName; WorkspaceUrl=$wsUrl;
                InfraKVUsed=($kvUsed ?? ''); TokenSecretUsed=($tokenSecretUsed ?? '');
                AuthMode=$authMode; AuthOk=$false;
                Note=("AUTH FAILED. " + $authNote + " | Checked KVs: " + ($kvList -join ', '))
            }
            continue
        }

        # --- UC Metastore probe (tells immediately if UC is attached / accessible)
        $ms = Invoke-DbxRest -WorkspaceUrl $wsUrl -Method GET -Path "/api/2.1/unity-catalog/metastore" -Headers $headers
        if ($ms) {
            $ucProbe += [pscustomobject]@{
                SubscriptionName=$sub.Name; WorkspaceName=$wsName; WorkspaceUrl=$wsUrl;
                Status='OK'; UcMetastoreId=$ms.metastore_id; UcMetastoreName=$ms.metastore_name;
                DefaultCatalog=$ms.default_catalog_name; Note=''
            }
        } else {
            $ucProbe += [pscustomobject]@{
                SubscriptionName=$sub.Name; WorkspaceName=$wsName; WorkspaceUrl=$wsUrl;
                Status='ERROR'; UcMetastoreId=''; UcMetastoreName=''; DefaultCatalog='';
                Note=$script:LastDbxError
            }
        }

        # --- SQL Warehouses + permissions
        $wh = Invoke-DbxRest -WorkspaceUrl $wsUrl -Method GET -Path "/api/2.0/sql/warehouses" -Headers $headers
        if ($wh -and $wh.warehouses) {
            foreach ($w in $wh.warehouses) {
                $whRows += [pscustomobject]@{
                    SubscriptionName=$sub.Name; ResourceGroup=$rg; WorkspaceName=$wsName;
                    WarehouseId=$w.id; WarehouseName=$w.name; State=$w.state; ClusterSize=$w.cluster_size; Note=''
                }

                $perm = Invoke-DbxRest -WorkspaceUrl $wsUrl -Method GET -Path ("/api/2.0/permissions/warehouses/{0}" -f $w.id) -Headers $headers
                if ($perm -and $perm.access_control_list) {
                    foreach ($ace in $perm.access_control_list) {
                        $ptype='unknown'; $pname=$null
                        if ($ace.user_name) { $ptype='user'; $pname=$ace.user_name }
                        elseif ($ace.group_name) { $ptype='group'; $pname=$ace.group_name }
                        elseif ($ace.service_principal_name) { $ptype='service_principal'; $pname=$ace.service_principal_name }

                        foreach ($p in @($ace.all_permissions)) {
                            $whPerms += [pscustomobject]@{
                                SubscriptionName=$sub.Name; WorkspaceName=$wsName; WarehouseName=$w.name; WarehouseId=$w.id;
                                PrincipalType=$ptype; PrincipalName=$pname; PermissionLevel=$p.permission_level; Inherited=$p.inherited; Note=''
                            }
                        }
                    }
                } else {
                    $whPerms += [pscustomobject]@{
                        SubscriptionName=$sub.Name; WorkspaceName=$wsName; WarehouseName=$w.name; WarehouseId=$w.id;
                        PrincipalType=''; PrincipalName=''; PermissionLevel=''; Inherited=''; Note=$script:LastDbxError
                    }
                }
            }
        } else {
            $whRows += [pscustomobject]@{
                SubscriptionName=$sub.Name; ResourceGroup=$rg; WorkspaceName=$wsName;
                WarehouseId=''; WarehouseName=''; State=''; ClusterSize=''; Note=$script:LastDbxError
            }
        }

        # --- UC Catalogs + permissions
        $cats = Invoke-DbxRest -WorkspaceUrl $wsUrl -Method GET -Path "/api/2.1/unity-catalog/catalogs" -Headers $headers
        if ($cats -and $cats.catalogs) {
            foreach ($c in $cats.catalogs) {
                $catRows += [pscustomobject]@{
                    SubscriptionName=$sub.Name; ResourceGroup=$rg; WorkspaceName=$wsName; CatalogName=$c.name;
                    Owner=$c.owner; Comment=$c.comment; Note=''
                }

                $cp = Invoke-DbxRest -WorkspaceUrl $wsUrl -Method GET -Path ("/api/2.1/unity-catalog/permissions/catalogs/{0}" -f $c.name) -Headers $headers
                if ($cp -and $cp.privilege_assignments) {
                    foreach ($pa in $cp.privilege_assignments) {
                        $catPerms += [pscustomobject]@{
                            SubscriptionName=$sub.Name; WorkspaceName=$wsName; CatalogName=$c.name;
                            PrincipalName=$pa.principal; Privileges=($pa.privileges -join ','); Note=''
                        }
                    }
                } else {
                    $catPerms += [pscustomobject]@{
                        SubscriptionName=$sub.Name; WorkspaceName=$wsName; CatalogName=$c.name;
                        PrincipalName=''; Privileges=''; Note=$script:LastDbxError
                    }
                }
            }
        } else {
            $catRows += [pscustomobject]@{
                SubscriptionName=$sub.Name; ResourceGroup=$rg; WorkspaceName=$wsName;
                CatalogName=''; Owner=''; Comment=''; Note=$script:LastDbxError
            }
        }

        # --- UC External locations + permissions
        $ext = Invoke-DbxRest -WorkspaceUrl $wsUrl -Method GET -Path "/api/2.1/unity-catalog/external-locations" -Headers $headers
        if ($ext -and $ext.external_locations) {
            foreach ($l in $ext.external_locations) {
                $extRows += [pscustomobject]@{
                    SubscriptionName=$sub.Name; ResourceGroup=$rg; WorkspaceName=$wsName;
                    ExternalLocation=$l.name; Url=$l.url; Owner=$l.owner; Comment=$l.comment; Note=''
                }

                $lp = Invoke-DbxRest -WorkspaceUrl $wsUrl -Method GET -Path ("/api/2.1/unity-catalog/permissions/external-locations/{0}" -f $l.name) -Headers $headers
                if ($lp -and $lp.privilege_assignments) {
                    foreach ($pa in $lp.privilege_assignments) {
                        $extPerms += [pscustomobject]@{
                            SubscriptionName=$sub.Name; WorkspaceName=$wsName; ExternalLocation=$l.name;
                            PrincipalName=$pa.principal; Privileges=($pa.privileges -join ','); Note=''
                        }
                    }
                } else {
                    $extPerms += [pscustomobject]@{
                        SubscriptionName=$sub.Name; WorkspaceName=$wsName; ExternalLocation=$l.name;
                        PrincipalName=''; Privileges=''; Note=$script:LastDbxError
                    }
                }
            }
        } else {
            $extRows += [pscustomobject]@{
                SubscriptionName=$sub.Name; ResourceGroup=$rg; WorkspaceName=$wsName;
                ExternalLocation=''; Url=''; Owner=''; Comment=''; Note=$script:LastDbxError
            }
        }

        $notes += [pscustomobject]@{
            SubscriptionName=$sub.Name; WorkspaceName=$wsName; WorkspaceUrl=$wsUrl;
            InfraKVUsed=($kvUsed ?? ''); TokenSecretUsed=($tokenSecretUsed ?? '');
            AuthMode=$authMode; AuthOk=$true; Note=$authNote
        }
    }
}

# Ensure not-empty outputs (so artifacts always publish)
Ensure-AtLeastOneRow ([ref]$wsRows)   @{ SubscriptionName=''; SubscriptionId=''; ResourceGroup=''; WorkspaceName=''; Location=''; WorkspaceUrl=''; WorkspaceResourceId=''; Note='' }
Ensure-AtLeastOneRow ([ref]$ucProbe)  @{ SubscriptionName=''; WorkspaceName=''; WorkspaceUrl=''; Status=''; UcMetastoreId=''; UcMetastoreName=''; DefaultCatalog=''; Note='' }
Ensure-AtLeastOneRow ([ref]$whRows)   @{ SubscriptionName=''; ResourceGroup=''; WorkspaceName=''; WarehouseId=''; WarehouseName=''; State=''; ClusterSize=''; Note='' }
Ensure-AtLeastOneRow ([ref]$whPerms)  @{ SubscriptionName=''; WorkspaceName=''; WarehouseName=''; WarehouseId=''; PrincipalType=''; PrincipalName=''; PermissionLevel=''; Inherited=''; Note='' }
Ensure-AtLeastOneRow ([ref]$catRows)  @{ SubscriptionName=''; ResourceGroup=''; WorkspaceName=''; CatalogName=''; Owner=''; Comment=''; Note='' }
Ensure-AtLeastOneRow ([ref]$catPerms) @{ SubscriptionName=''; WorkspaceName=''; CatalogName=''; PrincipalName=''; Privileges=''; Note='' }
Ensure-AtLeastOneRow ([ref]$extRows)  @{ SubscriptionName=''; ResourceGroup=''; WorkspaceName=''; ExternalLocation=''; Url=''; Owner=''; Comment=''; Note='' }
Ensure-AtLeastOneRow ([ref]$extPerms) @{ SubscriptionName=''; WorkspaceName=''; ExternalLocation=''; PrincipalName=''; Privileges=''; Note='' }
Ensure-AtLeastOneRow ([ref]$notes)    @{ SubscriptionName=''; WorkspaceName=''; WorkspaceUrl=''; InfraKVUsed=''; TokenSecretUsed=''; AuthMode=''; AuthOk=''; Note='' }

# Export
$stamp = Get-Date -Format 'yyyyMMdd'
$base  = "{0}_{1}_{2}" -f $adh_group, $adh_subscription_type, $stamp

$wsRows   | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutputDir "$base`_db_ws.csv")
$ucProbe  | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutputDir "$base`_db_uc_metastore.csv")
$whRows   | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutputDir "$base`_db_wh.csv")
$whPerms  | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutputDir "$base`_db_wh_permissions.csv")
$catRows  | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutputDir "$base`_db_uc_catalogs.csv")
$catPerms | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutputDir "$base`_db_uc_catalog_permissions.csv")
$extRows  | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutputDir "$base`_db_uc_external_locations.csv")
$extPerms | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutputDir "$base`_db_uc_external_location_permissions.csv")
$notes    | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutputDir "$base`_db_note.csv")

Write-Host "`nDONE. Outputs in $OutputDir" -ForegroundColor Green
