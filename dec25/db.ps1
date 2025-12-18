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

  # Optional: grant RBAC to read KV secrets (recommended if KV uses RBAC)
  [switch]$GrantRbac,

  # Optional: revoke RBAC after run (off by default)
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

  $headers = @{
    Authorization = "Bearer $PatToken"
  }

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

# ---------------- Start ----------------
$adh_sub_group = Normalize-Text $adh_sub_group

Write-Host "INFO: adh_group             = $adh_group"
Write-Host "INFO: adh_sub_group         = '$adh_sub_group'"
Write-Host "INFO: adh_subscription_type = $adh_subscription_type"
Write-Host "INFO: OutputDir             = $OutputDir"
Write-Host "INFO: BranchName            = $BranchName"
Write-Host "INFO: GrantRbac             = $GrantRbac"
Write-Host "INFO: RevokeRbacAfter        = $RevokeRbacAfter"

if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
  throw "Azure connection failed."
}

$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
if ($subs -isnot [System.Collections.IEnumerable]) { $subs = ,$subs }
if (-not $subs -or @($subs).Count -eq 0) { throw "No subscriptions resolved." }

$subNames = ($subs | Select-Object -ExpandProperty Name) -join ', '
Write-Host "INFO: Subscriptions = $subNames"

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

  # Enumerate workspaces (ARM)
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

    # workspace url
    $wsUrl = $null
    if ($ws.Properties.workspaceUrl) { $wsUrl = $ws.Properties.workspaceUrl }
    elseif ($ws.Properties.parameters.workspaceUrl.value) { $wsUrl = $ws.Properties.parameters.workspaceUrl.value }

    if (-not $wsUrl) {
      Write-Warning "WorkspaceUrl not found for $wsName; skipping REST."
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

    # ---------------- Determine env for KV lookup ----------------
    # Rule you gave: nonprd -> dev/tst/stg, prd -> prd
    # We infer env from workspace name suffix if possible; otherwise we try all envs in order.
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
    $genSpnClientId = $null
    $genSpnClientSecret = $null

    foreach ($env in $candidateEnvs) {

      $kvName = Build-InfraKvName -group $adh_group -subGroup $adh_sub_group -env $env

      # Find KV (by name) in subscription
      $kvRes = Get-AzResource -ResourceType "Microsoft.KeyVault/vaults" -Name $kvName -ErrorAction SilentlyContinue
      if (-not $kvRes) { continue }

      $kvScope = $kvRes.ResourceId

      # Grant RBAC to read secrets (if requested)
      if ($GrantRbac -and $spObjectId) {
        Ensure-RbacRole -ObjectId $spObjectId -Scope $kvScope -RoleName "Key Vault Secrets User"
        if ($RevokeRbacAfter) {
          $rbacToRevoke.Add([pscustomobject]@{ ObjectId=$spObjectId; Scope=$kvScope; Role="Key Vault Secrets User" })
        }
      }

      # Read token secret (prefer ADO config token, else Terraform token)
      $patToken = Get-SecretSafe -VaultName $kvName -SecretName "SPN-TOKEN-ADH-PLATFORM-ADO-CONFIGURATION"
      if ($patToken) {
        $tokenSecretUsed = "SPN-TOKEN-ADH-PLATFORM-ADO-CONFIGURATION"
      } else {
        $patToken = Get-SecretSafe -VaultName $kvName -SecretName "SPN-TOKEN-ADH-PLATFORM-TERRAFORM-CONFIGURATION"
        if ($patToken) { $tokenSecretUsed = "SPN-TOKEN-ADH-PLATFORM-TERRAFORM-CONFIGURATION" }
      }

      # Also read Gen SPN creds if present (not required for PAT calls, but you asked to use/validate)
      $genSpnClientId = Get-SecretSafe -VaultName $kvName -SecretName "ADH-Gen-SPN-ClientID"
      $genSpnClientSecret = Get-SecretSafe -VaultName $kvName -SecretName "ADH-Gen-SPN-ClientSecret"

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
        Note             = "No Databricks PAT token found in Infra KV for env(s): $($candidateEnvs -join ', ')"
      }
      continue
    }

    Write-Host "Workspace REST auth: using KV='$kvUsed' tokenSecret='$tokenSecretUsed'" -ForegroundColor DarkGreen

    # ---------------- SQL Warehouses ----------------
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
        }

        # Permissions per warehouse
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
      $whRows += [pscustomobject]@{
        SubscriptionName = $sub.Name
        ResourceGroup    = $rg
        WorkspaceName    = $wsName
        WarehouseId      = ''
        WarehouseName    = ''
        State            = ''
        ClusterSize      = ''
        Note             = 'No warehouses OR SQL API blocked'
      }
    }

    # ---------------- Unity Catalog: Catalogs + Permissions ----------------
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

    # Optional: record which token was used (useful debugging)
    $notes += [pscustomobject]@{
      SubscriptionName = $sub.Name
      WorkspaceName    = $wsName
      WorkspaceUrl     = $wsUrl
      InfraKVUsed      = $kvUsed
      TokenSecretUsed  = $tokenSecretUsed
      GenSpnClientIdPresent = [bool]$genSpnClientId
      GenSpnClientSecretPresent = [bool]$genSpnClientSecret
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
function Ensure-AtLeastOneRow([ref]$arr, [hashtable]$row) {
  if (-not $arr.Value -or @($arr.Value).Count -eq 0) {
    $arr.Value = @([pscustomobject]$row)
  }
}

Ensure-AtLeastOneRow ([ref]$wsRows)   @{ SubscriptionName=''; SubscriptionId=''; ResourceGroup=''; WorkspaceName=''; Location=''; WorkspaceUrl=''; WorkspaceResourceId=''; Note='' }
Ensure-AtLeastOneRow ([ref]$whRows)   @{ SubscriptionName=''; ResourceGroup=''; WorkspaceName=''; WarehouseId=''; WarehouseName=''; State=''; ClusterSize=''; Note='' }
Ensure-AtLeastOneRow ([ref]$whPerms)  @{ SubscriptionName=''; WorkspaceName=''; WarehouseName=''; WarehouseId=''; PrincipalType=''; PrincipalName=''; PermissionLevel=''; Inherited=''; Note='' }
Ensure-AtLeastOneRow ([ref]$catRows)  @{ SubscriptionName=''; ResourceGroup=''; WorkspaceName=''; CatalogName=''; Owner=''; Comment=''; Note='' }
Ensure-AtLeastOneRow ([ref]$catPerms) @{ SubscriptionName=''; WorkspaceName=''; CatalogName=''; PrincipalName=''; Privileges=''; Note='' }
Ensure-AtLeastOneRow ([ref]$notes)    @{ SubscriptionName=''; WorkspaceName=''; WorkspaceUrl=''; InfraKVUsed=''; TokenSecretUsed=''; GenSpnClientIdPresent=''; GenSpnClientSecretPresent=''; Note='' }

# ---------------- Output files ----------------
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$base  = "{0}_{1}_{2}" -f $adh_group, $adh_subscription_type, $stamp

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

  $wsRows   | Export-Excel -Path $xlsx -WorksheetName "Workspaces"     -AutoSize -FreezeTopRow
  $whRows   | Export-Excel -Path $xlsx -WorksheetName "SQLWarehouses"  -AutoSize -FreezeTopRow
  $whPerms  | Export-Excel -Path $xlsx -WorksheetName "SQLWhPerms"     -AutoSize -FreezeTopRow
  $catRows  | Export-Excel -Path $xlsx -WorksheetName "Catalogs"       -AutoSize -FreezeTopRow
  $catPerms | Export-Excel -Path $xlsx -WorksheetName "CatalogPerms"   -AutoSize -FreezeTopRow
  $notes    | Export-Excel -Path $xlsx -WorksheetName "Notes"          -AutoSize -FreezeTopRow

  Write-Host " - $xlsx" -ForegroundColor Green
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
