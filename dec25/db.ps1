# Scan-Databricks.ps1
# IMPORTANT: Save as UTF-8 (without BOM). BOM at byte 1 can break parsing in ADO.

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$TenantId,
  [Parameter(Mandatory=$true)][string]$ClientId,
  [Parameter(Mandatory=$true)][string]$ClientSecret,

  [Parameter(Mandatory=$true)][string]$adh_group,
  [string]$adh_sub_group = '',

  [ValidateSet('nonprd','prd')]
  [string]$adh_subscription_type = 'nonprd',

  [Parameter(Mandatory=$true)][string]$OutputDir,
  [string]$BranchName = '',

  [switch]$GrantRbac,
  [switch]$RevokeRbacAfter
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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
  $g = $group.ToUpper()
  $e = $env.ToLower()
  if ([string]::IsNullOrWhiteSpace($subGroup)) {
    return ("ADH-{0}-Infra-KV-{1}" -f $g, $e)
  }
  $sg = $subGroup.ToUpper()
  return ("ADH-{0}-{1}-Infra-KV-{2}" -f $g, $sg, $e)
}

function Get-SecretSafe {
  param(
    [Parameter(Mandatory=$true)][string]$VaultName,
    [Parameter(Mandatory=$true)][string]$SecretName
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
    [Parameter(Mandatory=$true)][string]$ObjectId,
    [Parameter(Mandatory=$true)][string]$Scope,
    [Parameter(Mandatory=$true)][string]$RoleName
  )
  try {
    $existing = Get-AzRoleAssignment -ObjectId $ObjectId -RoleDefinitionName $RoleName -Scope $Scope -ErrorAction SilentlyContinue
    if (-not $existing) {
      New-AzRoleAssignment -ObjectId $ObjectId -RoleDefinitionName $RoleName -Scope $Scope -ErrorAction Stop | Out-Null
      Write-Host "RBAC: Assigned '$RoleName' on $Scope" -ForegroundColor Green
      Start-Sleep -Seconds 20
    }
  } catch {
    Write-Warning ("RBAC assign failed: {0}" -f $_.Exception.Message)
  }
}

function Remove-RbacRole {
  param(
    [Parameter(Mandatory=$true)][string]$ObjectId,
    [Parameter(Mandatory=$true)][string]$Scope,
    [Parameter(Mandatory=$true)][string]$RoleName
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
    Write-Warning ("RBAC revoke failed: {0}" -f $_.Exception.Message)
  }
}

function Invoke-DbRestPat {
  param(
    [Parameter(Mandatory=$true)][string]$WorkspaceUrl,
    [Parameter(Mandatory=$true)][ValidateSet('GET','POST','PUT','PATCH','DELETE')][string]$Method,
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)][string]$PatToken,
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
      if ($one.Length -gt 400) { $one = $one.Substring(0,400) }
      $msg = $msg + " | BODY=" + $one
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

Write-Host ("INFO: adh_group={0} adh_sub_group='{1}' envType={2}" -f $adh_group, $adh_sub_group, $adh_subscription_type)
Write-Host ("INFO: OutputDir={0} BranchName={1}" -f $OutputDir, $BranchName)
Write-Host ("INFO: GrantRbac={0} RevokeRbacAfter={1}" -f [bool]$GrantRbac, [bool]$RevokeRbacAfter)

if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
  throw "Azure connection failed."
}

$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
if ($subs -isnot [System.Collections.IEnumerable]) { $subs = ,$subs }
if (-not $subs -or @($subs).Count -eq 0) { throw "No subscriptions resolved." }

Write-Host ("INFO: Subscriptions = {0}" -f (($subs | Select-Object -ExpandProperty Name) -join ', '))

# SP object id for RBAC grants (optional)
$spObjectId = $null
try {
  $sp = Get-AzADServicePrincipal -ApplicationId $ClientId -ErrorAction Stop
  $spObjectId = $sp.Id
} catch {
  Write-Warning "Unable to resolve SP object id from ClientId. RBAC grant may fail."
}

$envs = Get-EnvList $adh_subscription_type

$wsRows   = @()
$whRows   = @()
$whPerms  = @()
$catRows  = @()
$catPerms = @()
$notes    = @()

$rbacToRevoke = New-Object System.Collections.Generic.List[object]

foreach ($sub in $subs) {
  Set-ScContext -Subscription $sub
  Write-Host ("`n=== Databricks scan: {0} ({1}) ===" -f $sub.Name, $sub.Id) -ForegroundColor Cyan

  $wsResources = Get-AzResource -ResourceType "Microsoft.Databricks/workspaces" -ExpandProperties -ErrorAction SilentlyContinue
  if (-not $wsResources -or @($wsResources).Count -eq 0) {
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

    $wsUrl = $null
    if ($ws.Properties -and $ws.Properties.workspaceUrl) {
      $wsUrl = $ws.Properties.workspaceUrl
    } elseif ($ws.Properties -and $ws.Properties.parameters -and $ws.Properties.parameters.workspaceUrl -and $ws.Properties.parameters.workspaceUrl.value) {
      $wsUrl = $ws.Properties.parameters.workspaceUrl.value
    }

    $wsRows += [pscustomobject]@{
      SubscriptionName    = $sub.Name
      SubscriptionId      = $sub.Id
      ResourceGroup       = $rg
      WorkspaceName       = $wsName
      Location            = $loc
      WorkspaceUrl        = (if ($wsUrl) { $wsUrl } else { '' })
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

    # Candidate envs: if name ends with -dev/-tst/-stg/-prd else try all
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

      $kvRes = Get-AzResource -ResourceType "Microsoft.KeyVault/vaults" -Name $kvName -ErrorAction SilentlyContinue
      if (-not $kvRes) { continue }

      $kvScope = $kvRes.ResourceId

      if ($GrantRbac -and $spObjectId) {
        Ensure-RbacRole -ObjectId $spObjectId -Scope $kvScope -RoleName "Key Vault Secrets User"
        if ($RevokeRbacAfter) {
          $rbacToRevoke.Add([pscustomobject]@{ ObjectId=$spObjectId; Scope=$kvScope; Role="Key Vault Secrets User" })
        }
      }

      # ✅ Use only this secret
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
        InfraKVUsed      = (if ($kvUsed) { $kvUsed } else { '' })
        Note             = ("Missing secret 'SPN-TOKEN-CUSTODIAN-GEN' in Infra KV for env(s): {0}" -f ($candidateEnvs -join ', '))
      }
      continue
    }

    # Sanity check: /Me
    $me = Invoke-DbRestPat -WorkspaceUrl $wsUrl -Method GET -Path "/api/2.0/preview/scim/v2/Me" -PatToken $patToken
    if (-not $me) {
      $notes += [pscustomobject]@{
        SubscriptionName = $sub.Name
        WorkspaceName    = $wsName
        WorkspaceUrl     = $wsUrl
        InfraKVUsed      = $kvUsed
        Note             = "Token failed for DBX /Me. Token invalid/expired/not authorized."
      }
      continue
    }

    Write-Host ("DBX /Me OK: {0} | Workspace={1} | KV={2}" -f $me.userName, $wsName, $kvUsed) -ForegroundColor DarkGreen

    # SQL Warehouses
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
          Note             = ''
        }

        $perm = Invoke-DbRestPat -WorkspaceUrl $wsUrl -Method GET -Path ("/api/2.0/permissions/warehouses/{0}" -f $w.id) -PatToken $patToken
        if ($perm -and $perm.access_control_list -and @($perm.access_control_list).Count -gt 0) {
          foreach ($ace in $perm.access_control_list) {
            $ptype = ''
            $pname = ''
            if ($ace.user_name) { $ptype='user'; $pname=$ace.user_name }
            elseif ($ace.group_name) { $ptype='group'; $pname=$ace.group_name }
            elseif ($ace.service_principal_name) { $ptype='service_principal'; $pname=$ace.service_principal_name }
            else { $ptype='unknown' }

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
      $whRows += [pscustomobject]@{
        SubscriptionName = $sub.Name
        ResourceGroup    = $rg
        WorkspaceName    = $wsName
        WarehouseName    = ''
        WarehouseId      = ''
        Status           = ''
        Note             = 'No SQL Warehouses OR SQL API blocked'
      }
    }

    # Unity Catalog: Catalogs + Permissions
    $cats = Invoke-DbRestPat -WorkspaceUrl $wsUrl -Method GET -Path "/api/2.1/unity-catalog/catalogs" -PatToken $patToken
    if ($cats -and $cats.catalogs -and @($cats.catalogs).Count -gt 0) {
      foreach ($c in $cats.catalogs) {
        $catRows += [pscustomobject]@{
          SubscriptionName = $sub.Name
          ResourceGroup    = $rg
          WorkspaceName    = $wsName
          CatalogName      = $c.name
          Owner            = $c.owner
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
        Note             = 'Unity Catalog not enabled / metastore not attached OR UC API blocked'
      }
    }

    $notes += [pscustomobject]@{
      SubscriptionName = $sub.Name
      WorkspaceName    = $wsName
      WorkspaceUrl     = $wsUrl
      InfraKVUsed      = $kvUsed
      Note             = ''
    }
  }
}

# Revoke RBAC if asked
if ($RevokeRbacAfter -and $rbacToRevoke.Count -gt 0) {
  Write-Host "`nRevoking temporary RBAC..." -ForegroundColor Yellow
  foreach ($r in $rbacToRevoke) {
    Remove-RbacRole -ObjectId $r.ObjectId -Scope $r.Scope -RoleName $r.Role
  }
}

# Ensure outputs not empty
Ensure-AtLeastOneRow ([ref]$wsRows)   @{ SubscriptionName=''; SubscriptionId=''; ResourceGroup=''; WorkspaceName=''; Location=''; WorkspaceUrl=''; WorkspaceResourceId=''; Note='' }
Ensure-AtLeastOneRow ([ref]$whRows)   @{ SubscriptionName=''; ResourceGroup=''; WorkspaceName=''; WarehouseName=''; WarehouseId=''; Status=''; Note='' }
Ensure-AtLeastOneRow ([ref]$whPerms)  @{ SubscriptionName=''; WorkspaceName=''; WarehouseName=''; WarehouseId=''; PrincipalType=''; PrincipalName=''; PermissionLevel=''; Inherited=''; Note='' }
Ensure-AtLeastOneRow ([ref]$catRows)  @{ SubscriptionName=''; ResourceGroup=''; WorkspaceName=''; CatalogName=''; Owner=''; Note='' }
Ensure-AtLeastOneRow ([ref]$catPerms) @{ SubscriptionName=''; WorkspaceName=''; CatalogName=''; PrincipalName=''; Privileges=''; Note='' }
Ensure-AtLeastOneRow ([ref]$notes)    @{ SubscriptionName=''; WorkspaceName=''; WorkspaceUrl=''; InfraKVUsed=''; Note='' }

# Output (short names, yyyyMMdd)
$stamp = Get-Date -Format 'yyyyMMdd'
$base  = "{0}_{1}_{2}" -f $adh_group, $adh_subscription_type, $stamp

$csvWs   = Join-Path $OutputDir ($base + "_db_ws.csv")
$csvWh   = Join-Path $OutputDir ($base + "_db_wh.csv")
$csvWhP  = Join-Path $OutputDir ($base + "_db_whp.csv")
$csvCat  = Join-Path $OutputDir ($base + "_db_cat.csv")
$csvCatP = Join-Path $OutputDir ($base + "_db_catp.csv")
$csvNote = Join-Path $OutputDir ($base + "_db_note.csv")

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

# Optional XLSX
if (Get-Module -ListAvailable -Name ImportExcel) {
  Import-Module ImportExcel -ErrorAction SilentlyContinue
  $xlsx = Join-Path $OutputDir ($base + "_db_inventory.xlsx")
  if (Test-Path $xlsx) { Remove-Item $xlsx -Force }

  $wsRows   | Export-Excel -Path $xlsx -WorksheetName "Workspaces"   -AutoSize -FreezeTopRow
  $whRows   | Export-Excel -Path $xlsx -WorksheetName "SQLWarehouses" -AutoSize -FreezeTopRow
  $whPerms  | Export-Excel -Path $xlsx -WorksheetName "SQLWhPerms"   -AutoSize -FreezeTopRow
  $catRows  | Export-Excel -Path $xlsx -WorksheetName "Catalogs"     -AutoSize -FreezeTopRow
  $catPerms | Export-Excel -Path $xlsx -WorksheetName "CatalogPerms" -AutoSize -FreezeTopRow
  $notes    | Export-Excel -Path $xlsx -WorksheetName "Notes"        -AutoSize -FreezeTopRow

  Write-Host "XLSX: $xlsx" -ForegroundColor Green
} else {
  Write-Warning "ImportExcel not found; XLSX skipped."
}
