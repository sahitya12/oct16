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

function Get-SecretSafe {
  param(
    [Parameter(Mandatory)][string]$VaultName,
    [Parameter(Mandatory)][string]$SecretName
  )
  try {
    $s = Get-AzKeyVaultSecret -VaultName $VaultName -Name $SecretName -ErrorAction Stop
    return $s.SecretValueText
  } catch {
    return $null
  }
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
      Start-Sleep -Seconds 20
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

function Invoke-DbRestPat {
  param(
    [Parameter(Mandatory)][string]$WorkspaceUrl,
    [Parameter(Mandatory)][ValidateSet('GET','POST','PUT','PATCH','DELETE')][string]$Method,
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$PatToken,
    [string]$Body = $null
  )

  $hostPart = $WorkspaceUrl -replace '^https://',''
  $uri = "https://$hostPart$Path"

  $headers = @{ Authorization = "Bearer $PatToken" }

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
      $msg = $msg + " | BODY=" + $one.Substring(0,[Math]::Min(400,$one.Length))
    }
    Write-Warning ("DBX REST FAILED: {0} {1} :: {2}" -f $Method, $Path, $msg)
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

# SP object id (for RBAC assignments to KV)
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
$notes    = @()

# Track RBAC scopes to optionally revoke later
$rbacToRevoke = New-Object System.Collections.Generic.List[object]

foreach ($sub in $subs) {
  Set-ScContext -Subscription $sub
  Write-Host "`n=== Databricks scan: $($sub.Name) ($($sub.Id)) ===" -ForegroundColor Cyan

  # ARM workspaces
  $wsResources = Get-AzResource -ResourceType "Microsoft.Databricks/workspaces" -ExpandProperties -ErrorAction SilentlyContinue
  if (-not $wsResources -or @($wsResources).Count -eq 0) {
    Write-Warning "No Databricks workspaces in subscription $($sub.Name)"
    $notes += [pscustomobject]@{
      SubscriptionName = $sub.Name
      WorkspaceName    = ''
      WorkspaceUrl     = ''
      InfraKVUsed      = ''
      Note             = 'No Databricks workspaces found'
    }
    continue
  }

  foreach ($ws in $wsResources) {

    $wsName = $ws.Name
    $rg     = $ws.ResourceGroupName
    $loc    = $ws.Location
    $wsId   = $ws.ResourceId

    # workspace url
    $wsUrl = $null
    if ($ws.Properties.workspaceUrl) { $wsUrl = $ws.Properties.workspaceUrl }
    elseif ($ws.Properties.parameters.workspaceUrl.value) { $wsUrl = $ws.Properties.parameters.workspaceUrl.value }

    $wsRows += [pscustomobject]@{
      SubscriptionName    = $sub.Name
      SubscriptionId      = $sub.Id
      ResourceGroup       = $rg
      WorkspaceName       = $wsName
      Location            = $loc
      WorkspaceUrl        = ($wsUrl ?? '')
      WorkspaceResourceId = $wsId
      Note                = (if ($wsUrl) { '' } else { 'workspaceUrl missing' })
    }

    if (-not $wsUrl) {
      $notes += [pscustomobject]@{
        SubscriptionName = $sub.Name
        WorkspaceName    = $wsName
        WorkspaceUrl     = ''
        InfraKVUsed      = ''
        Note             = 'workspaceUrl missing from ARM properties'
      }
      continue
    }

    # Infer env from workspace name (best effort), otherwise try all envs
    $candidateEnvs = @()
    foreach ($e in $envs) {
      if ($wsName -match ("-{0}$" -f [Regex]::Escape($e)) -or $wsName -match ("_{0}$" -f [Regex]::Escape($e))) {
        $candidateEnvs += $e
      }
    }
    if ($candidateEnvs.Count -eq 0) { $candidateEnvs = $envs }

    $patToken = $null
    $kvUsed   = $null

    foreach ($env in $candidateEnvs) {
      $kvName = Build-InfraKvName -group $adh_group -subGroup $adh_sub_group -env $env

      # KV exists in this subscription?
      $kvRes = Get-AzResource -ResourceType "Microsoft.KeyVault/vaults" -Name $kvName -ErrorAction SilentlyContinue
      if (-not $kvRes) { continue }

      $kvScope = $kvRes.ResourceId

      # RBAC grant if requested
      if ($GrantRbac -and $spObjectId) {
        Ensure-RbacRole -ObjectId $spObjectId -Scope $kvScope -RoleName "Key Vault Secrets User"
        if ($RevokeRbacAfter) {
          $rbacToRevoke.Add([pscustomobject]@{ ObjectId=$spObjectId; Scope=$kvScope; Role="Key Vault Secrets User" })
        }
      }

      # ✅ ONLY token secret you requested
      $patToken = Get-SecretSafe -VaultName $kvName -SecretName "SPN-TOKEN-CUSTODIAN-GEN"
      if ($patToken) {
        $kvUsed = $kvName
        break
      }
    }

    if (-not $patToken) {
      $notes += [pscustomobject]@{
        SubscriptionName = $sub.Name
        WorkspaceName    = $wsName
        WorkspaceUrl     = $wsUrl
        InfraKVUsed      = ($kvUsed ?? '')
        Note             = "Missing secret 'SPN-TOKEN-CUSTODIAN-GEN' in Infra KV for env(s): $($candidateEnvs -join ', ')"
      }
      continue
    }

    # ---------------- Sanity check /Me ----------------
    $me = Invoke-DbRestPat -WorkspaceUrl $wsUrl -Method GET -Path "/api/2.0/preview/scim/v2/Me" -PatToken $patToken
    if (-not $me) {
      $notes += [pscustomobject]@{
        SubscriptionName = $sub.Name
        WorkspaceName    = $wsName
        WorkspaceUrl     = $wsUrl
        InfraKVUsed      = $kvUsed
        Note             = "Token works for ARM but failed for DBX /Me. Token invalid / expired / not authorized for workspace."
      }
      continue
    }

    Write-Host "DBX /Me OK: $($me.userName) | Workspace=$wsName | KV=$kvUsed" -ForegroundColor DarkGreen

    # ---------------- SQL Warehouses ----------------
    $wh = Invoke-DbRestPat -WorkspaceUrl $wsUrl -Method GET -Path "/api/2.0/sql/warehouses" -PatToken $patToken
    if ($wh -and $wh.warehouses -and @($wh.warehouses).Count -gt 0) {

      foreach ($w in $wh.warehouses) {
        $whRows += [pscustomobject]@{
          SubscriptionName = $sub.Name
          ResourceGroup    = $rg
          WorkspaceName    = $wsName
          WarehouseName    = $w.name
          WarehouseId      = $w.id
          Status           = $w.state
          Region           = ($w.spot_instance_policy ?? '') # not always present; safe
          Version          = ($w.enable_serverless_compute ?? '') # safe placeholder
          RelatedCount     = '' # portal shows "Related" - not always obtainable via this API
          IRType           = 'Azure'
          IRSubType        = 'SQL Warehouse'
          Note             = ''
        }

        # Warehouse permissions
        $perm = Invoke-DbRestPat -WorkspaceUrl $wsUrl -Method GET -Path ("/api/2.0/permissions/warehouses/{0}" -f $w.id) -PatToken $patToken
        if ($perm -and $perm.access_control_list -and @($perm.access_control_list).Count -gt 0) {
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
            Note             = 'No ACL returned OR permissions endpoint blocked'
          }
        }
      }

    } else {
      # Put a note row instead of leaving sheet empty
      $whRows += [pscustomobject]@{
        SubscriptionName = $sub.Name
        ResourceGroup    = $rg
        WorkspaceName    = $wsName
        WarehouseName    = ''
        WarehouseId      = ''
        Status           = ''
        Region           = ''
        Version          = ''
        RelatedCount     = ''
        IRType           = ''
        IRSubType        = ''
        Note             = 'No SQL Warehouses OR SQL API blocked'
      }
    }

    # ---------------- Unity Catalog: Catalogs + Permissions ----------------
    $cats = Invoke-DbRestPat -WorkspaceUrl $wsUrl -Method GET -Path "/api/2.1/unity-catalog/catalogs" -PatToken $patToken
    if ($cats -and $cats.catalogs -and @($cats.catalogs).Count -gt 0) {

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
        if ($cp -and $cp.privilege_assignments -and @($cp.privilege_assignments).Count -gt 0) {
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
            Note             = 'No privilege_assignments OR UC permission API blocked'
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
        Note             = 'Unity Catalog not enabled / metastore not attached OR UC API blocked'
      }
    }

    # Notes row (shows what KV and token were used)
    $notes += [pscustomobject]@{
      SubscriptionName = $sub.Name
      WorkspaceName    = $wsName
      WorkspaceUrl     = $wsUrl
      InfraKVUsed      = $kvUsed
      Note             = ''
    }
  }
}

# ---------------- Revoke RBAC if asked ----------------
if ($RevokeRbacAfter -and $rbacToRevoke.Count -gt 0) {
  Write-Host "`nRevoking temporary RBAC..." -ForegroundColor Yellow
  foreach ($r in $rbacToRevoke) {
    Remove-RbacRole -ObjectId $r.ObjectId -Scope $r.Scope -RoleName $r.Role
  }
}

# ---------------- Ensure not-empty outputs ----------------
Ensure-AtLeastOneRow ([ref]$wsRows)   @{
  SubscriptionName=''; SubscriptionId=''; ResourceGroup=''; WorkspaceName=''; Location=''; WorkspaceUrl=''; WorkspaceResourceId=''; Note=''
}
Ensure-AtLeastOneRow ([ref]$whRows)   @{
  SubscriptionName=''; ResourceGroup=''; WorkspaceName=''; WarehouseName=''; WarehouseId=''; Status=''; RelatedCount=''; Region=''; Version=''; IRType=''; IRSubType=''; Note=''
}
Ensure-AtLeastOneRow ([ref]$whPerms)  @{
  SubscriptionName=''; WorkspaceName=''; WarehouseName=''; WarehouseId=''; PrincipalType=''; PrincipalName=''; PermissionLevel=''; Inherited=''; Note=''
}
Ensure-AtLeastOneRow ([ref]$catRows)  @{
  SubscriptionName=''; ResourceGroup=''; WorkspaceName=''; CatalogName=''; Owner=''; Comment=''; Note=''
}
Ensure-AtLeastOneRow ([ref]$catPerms) @{
  SubscriptionName=''; WorkspaceName=''; CatalogName=''; PrincipalName=''; Privileges=''; Note=''
}
Ensure-AtLeastOneRow ([ref]$notes)    @{
  SubscriptionName=''; WorkspaceName=''; WorkspaceUrl=''; InfraKVUsed=''; Note=''
}

# ---------------- Output files ----------------
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$base  = "{0}_{1}_{2}" -f $adh_group, $adh_subscription_type, $stamp

# short names (as you requested)
$csvWs   = Join-Path $OutputDir "$base`_db_ws.csv"
$csvWh   = Join-Path $OutputDir "$base`_db_wh.csv"
$csvWhP  = Join-Path $OutputDir "$base`_db_whp.csv"
$csvCat  = Join-Path $OutputDir "$base`_db_cat.csv"
$csvCatP = Join-Path $OutputDir "$base`_db_catp.csv"
$csvNote = Join-Path $OutputDir "$base`_db_note.csv"

$wsRows   | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvWs
$whRows   | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvWh
$whPerms  | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvWhP
$catRows  | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvCat
$catPerms | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvCatP
$notes    | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvNote

Write-Host "`nDONE. CSV outputs:" -ForegroundColor Cyan
Write-Host " - $csvWs"
Write-Host " - $csvWh"
Write-Host " - $csvWhP"
Write-Host " - $csvCat"
Write-Host " - $csvCatP"
Write-Host " - $csvNote"

# XLSX (optional)
if (Get-Module -ListAvailable -Name ImportExcel) {
  Import-Module ImportExcel -ErrorAction SilentlyContinue
  $xlsx = Join-Path $OutputDir "$base`_db_inventory.xlsx"
  if (Test-Path $xlsx) { Remove-Item $xlsx -Force }

  $wsRows   | Export-Excel -Path $xlsx -WorksheetName "Workspaces"    -AutoSize -FreezeTopRow
  $whRows   | Export-Excel -Path $xlsx -WorksheetName "SQLWarehouses" -AutoSize -FreezeTopRow
  $whPerms  | Export-Excel -Path $xlsx -WorksheetName "SQLWhPerms"    -AutoSize -FreezeTopRow
  $catRows  | Export-Excel -Path $xlsx -WorksheetName "Catalogs"      -AutoSize -FreezeTopRow
  $catPerms | Export-Excel -Path $xlsx -WorksheetName "CatalogPerms"  -AutoSize -FreezeTopRow
  $notes    | Export-Excel -Path $xlsx -WorksheetName "Notes"         -AutoSize -FreezeTopRow

  Write-Host "XLSX: $xlsx" -ForegroundColor Green
} else {
  Write-Warning "ImportExcel not found; XLSX skipped."
}

Write-Host "`nCounts:" -ForegroundColor Yellow
Write-Host " Workspaces    = $($wsRows.Count)"
Write-Host " Warehouses    = $($whRows.Count)"
Write-Host " WhPerms       = $($whPerms.Count)"
Write-Host " Catalogs      = $($catRows.Count)"
Write-Host " CatalogPerms  = $($catPerms.Count)"
Write-Host " Notes         = $($notes.Count)"
