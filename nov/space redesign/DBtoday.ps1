# Scan-Databricks.ps1
# Exports Databricks inventory to CSV (and XLSX if ImportExcel is available)
# Works with Service Principal by using the required Databricks Azure headers.

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

  # Optional: if you want to force scan only a specific subscription
  [string[]]$SubscriptionIds = @()
)

# ---------------------------
# Helpers
# ---------------------------
function Ensure-Dir {
  param([Parameter(Mandatory)][string]$Path)
  if (-not (Test-Path $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
  (Resolve-Path $Path).Path
}

function Connect-SpnAz {
  param([string]$TenantId,[string]$ClientId,[string]$ClientSecret)
  $sec = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
  $cred = New-Object System.Management.Automation.PSCredential($ClientId,$sec)
  Connect-AzAccount -ServicePrincipal -Tenant $TenantId -Credential $cred -ErrorAction Stop | Out-Null
}

function Get-Tokens {
  # Databricks resource ID (AAD app) token + ARM management token
  $dbxResourceId = "2ff814a6-3304-4ab8-85cb-cd0e6f879c1d"
  $dbx = Get-AzAccessToken -ResourceUrl $dbxResourceId -ErrorAction Stop
  $arm = Get-AzAccessToken -ResourceUrl "https://management.azure.com/" -ErrorAction Stop

  if (-not $dbx.Token) { throw "Failed to acquire Databricks AAD token." }
  if (-not $arm.Token) { throw "Failed to acquire ARM management token." }

  [pscustomobject]@{
    DatabricksToken = $dbx.Token
    ArmToken        = $arm.Token
  }
}

function Invoke-DbxRest {
  param(
    [Parameter(Mandatory)][string]$WorkspaceUrl,  # e.g. adb-xxxx.azuredatabricks.net
    [Parameter(Mandatory)][string]$Method,
    [Parameter(Mandatory)][string]$Path,          # e.g. /api/2.1/unity-catalog/catalogs
    [Parameter(Mandatory)][string]$DbxToken,
    [Parameter(Mandatory)][string]$ArmToken,
    [Parameter(Mandatory)][string]$WorkspaceResourceId
  )

  $uri = "https://$WorkspaceUrl$Path"

  $headers = @{
    Authorization                           = "Bearer $DbxToken"
    "X-Databricks-Azure-SP-Management-Token" = $ArmToken
    "X-Databricks-Azure-Workspace-Resource-Id" = $WorkspaceResourceId
  }

  try {
    return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers -ContentType "application/json" -ErrorAction Stop
  }
  catch {
    $msg = $_.Exception.Message
    # Surface the real REST error in logs (this is usually why you got empty CSVs)
    Write-Warning "Databricks REST failed: $Method $uri :: $msg"
    return $null
  }
}

# ---------------------------
# Main
# ---------------------------
$OutputDir = Ensure-Dir -Path $OutputDir

Write-Host "INFO: OutputDir = $OutputDir" -ForegroundColor Cyan
Write-Host "INFO: adh_group = $adh_group | adh_sub_group = '$adh_sub_group' | type = $adh_subscription_type" -ForegroundColor Cyan

Import-Module Az.Accounts, Az.Resources -ErrorAction Stop

Connect-SpnAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret

# Identify subscriptions to scan
$subs = @()

if ($SubscriptionIds.Count -gt 0) {
  $subs = foreach ($sid in $SubscriptionIds) { Get-AzSubscription -SubscriptionId $sid -ErrorAction Stop }
}
else {
  # Adjust this filter if your naming differs
  $subs = Get-AzSubscription | Where-Object {
    ($_.Name -match [regex]::Escape($adh_group)) -and ($_.Name -match $adh_subscription_type)
  }
}

if (-not $subs -or $subs.Count -eq 0) {
  throw "No subscriptions matched. Provide -SubscriptionIds or adjust subscription name filter."
}

# Acquire tokens once
$tokens = Get-Tokens

# Results
$workspaceResults   = @()
$sqlWhResults       = @()
$catalogListResults = @()
$extLocResults      = @()

foreach ($sub in $subs) {
  Write-Host "---- Subscription: $($sub.Name) / $($sub.Id)" -ForegroundColor Yellow
  Set-AzContext -SubscriptionId $sub.Id -ErrorAction Stop | Out-Null

  # List Databricks workspaces in this subscription
  $wsResources = Get-AzResource -ResourceType "Microsoft.Databricks/workspaces" -ExpandProperties -ErrorAction SilentlyContinue
  if (-not $wsResources) {
    Write-Warning "No Databricks workspaces found in subscription $($sub.Name)"
    continue
  }

  foreach ($ws in $wsResources) {
    $wsName   = $ws.Name
    $rg       = $ws.ResourceGroupName
    $location = $ws.Location
    $wsId     = $ws.ResourceId

    # workspaceUrl can be in different places depending on API version
    $wsUrl = $null
    if ($ws.Properties.workspaceUrl) { $wsUrl = $ws.Properties.workspaceUrl }
    elseif ($ws.Properties.parameters.workspaceUrl.value) { $wsUrl = $ws.Properties.parameters.workspaceUrl.value }

    if (-not $wsUrl) {
      Write-Warning "WorkspaceUrl not found for $wsName ($wsId) – skipping REST calls"
      continue
    }

    Write-Host "  Workspace: $wsName | $wsUrl" -ForegroundColor Green

    $workspaceResults += [pscustomobject]@{
      SubscriptionName = $sub.Name
      SubscriptionId   = $sub.Id
      ResourceGroup    = $rg
      WorkspaceName    = $wsName
      Location         = $location
      WorkspaceUrl     = $wsUrl
      WorkspaceResourceId = $wsId
      adh_group        = $adh_group
      adh_sub_group    = $adh_sub_group
      adh_subscription_type = $adh_subscription_type
    }

    # --- SQL Warehouses ---
    $wh = Invoke-DbxRest -WorkspaceUrl $wsUrl -Method GET -Path "/api/2.0/sql/warehouses" `
      -DbxToken $tokens.DatabricksToken -ArmToken $tokens.ArmToken -WorkspaceResourceId $wsId

    if ($wh -and $wh.warehouses) {
      foreach ($w in $wh.warehouses) {
        $sqlWhResults += [pscustomobject]@{
          SubscriptionName = $sub.Name
          ResourceGroup    = $rg
          WorkspaceName    = $wsName
          WarehouseId      = $w.id
          WarehouseName    = $w.name
          WarehouseState   = $w.state
          ClusterSize      = $w.cluster_size
          AutoStopMins     = $w.auto_stop_mins
          SpotInstancePolicy = $w.spot_instance_policy
          EnableServerlessCompute = $w.enable_serverless_compute
          adh_group        = $adh_group
          adh_sub_group    = $adh_sub_group
        }
      }
    }

    # --- Unity Catalog: Catalogs ---
    $cats = Invoke-DbxRest -WorkspaceUrl $wsUrl -Method GET -Path "/api/2.1/unity-catalog/catalogs" `
      -DbxToken $tokens.DatabricksToken -ArmToken $tokens.ArmToken -WorkspaceResourceId $wsId

    if ($cats -and $cats.catalogs) {
      foreach ($c in $cats.catalogs) {
        $catalogListResults += [pscustomobject]@{
          SubscriptionName = $sub.Name
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
      }
    }

    # --- Unity Catalog: External Locations ---
    $ext = Invoke-DbxRest -WorkspaceUrl $wsUrl -Method GET -Path "/api/2.1/unity-catalog/external-locations" `
      -DbxToken $tokens.DatabricksToken -ArmToken $tokens.ArmToken -WorkspaceResourceId $wsId

    if ($ext -and $ext.external_locations) {
      foreach ($l in $ext.external_locations) {
        $extLocResults += [pscustomobject]@{
          SubscriptionName = $sub.Name
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
    }
  }
}

# ---------------------------
# Export
# ---------------------------
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$prefix = "{0}_{1}_{2}" -f $adh_group, $adh_subscription_type, $stamp

$csvWorkspaces = Join-Path $OutputDir "$prefix`_databricks_workspaces.csv"
$csvWh         = Join-Path $OutputDir "$prefix`_databricks_sql_warehouses.csv"
$csvCats       = Join-Path $OutputDir "$prefix`_databricks_catalogs.csv"
$csvExt        = Join-Path $OutputDir "$prefix`_databricks_external_locations.csv"

$workspaceResults   | Export-Csv -NoTypeInformation -Path $csvWorkspaces -Encoding UTF8
$sqlWhResults       | Export-Csv -NoTypeInformation -Path $csvWh         -Encoding UTF8
$catalogListResults | Export-Csv -NoTypeInformation -Path $csvCats       -Encoding UTF8
$extLocResults      | Export-Csv -NoTypeInformation -Path $csvExt        -Encoding UTF8

Write-Host "DONE. CSV outputs:" -ForegroundColor Cyan
Write-Host " - $csvWorkspaces"
Write-Host " - $csvWh"
Write-Host " - $csvCats"
Write-Host " - $csvExt"

# Optional: XLSX (multi-sheet) if ImportExcel module exists
if (Get-Module -ListAvailable -Name ImportExcel) {
  Import-Module ImportExcel -ErrorAction SilentlyContinue
  $xlsx = Join-Path $OutputDir "$prefix`_databricks_inventory.xlsx"
  if (Test-Path $xlsx) { Remove-Item $xlsx -Force }

  $workspaceResults   | Export-Excel -Path $xlsx -WorksheetName "Workspaces"        -AutoSize -FreezeTopRow
  $sqlWhResults       | Export-Excel -Path $xlsx -WorksheetName "SQLWarehouses"     -AutoSize -FreezeTopRow
  $catalogListResults | Export-Excel -Path $xlsx -WorksheetName "Catalogs"          -AutoSize -FreezeTopRow
  $extLocResults      | Export-Excel -Path $xlsx -WorksheetName "ExternalLocations" -AutoSize -FreezeTopRow

  Write-Host " - $xlsx" -ForegroundColor Green
}
else {
  Write-Warning "ImportExcel module not found; skipped XLSX generation."
}

# Quick sanity summary
Write-Host "Counts:" -ForegroundColor Yellow
Write-Host " Workspaces        = $($workspaceResults.Count)"
Write-Host " SQL Warehouses    = $($sqlWhResults.Count)"
Write-Host " Catalogs          = $($catalogListResults.Count)"
Write-Host " External Locations= $($extLocResults.Count)"
