param(
  [Parameter(Mandatory)][string]$TenantId,
  [Parameter(Mandatory)][string]$ClientId,
  [Parameter(Mandatory)][string]$ClientSecret,

  [Parameter(Mandatory)][string]$adh_group,

  # May come as ' ' from pipeline – normalize below
  [string]$adh_sub_group = '',

  [ValidateSet('nonprd','prd')]
  [string]$adh_subscription_type = 'nonprd',

  [Parameter(Mandatory)][string]$OutputDir,
  [string]$BranchName = ''
)

Import-Module Az.Accounts, Az.Resources, Az.KeyVault -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop
Ensure-Dir $OutputDir | Out-Null

# --------------------------------------------------------------------
# Normalize adh_sub_group (handle single-space from pipeline)
# --------------------------------------------------------------------
if ($null -ne $adh_sub_group) {
    $adh_sub_group = $adh_sub_group.Trim()
}
if ([string]::IsNullOrWhiteSpace($adh_sub_group)) {
    Write-Host "DEBUG: adh_sub_group is empty/space -> treating as <none>"
    $adh_sub_group = ''
}

# Custodian used for filtering KV names and file naming
$custodian = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) {
    $adh_group                          # e.g. KTK
} else {
    "${adh_group}_${adh_sub_group}"     # e.g. KTK_OPX
}
$custUpper = $custodian.ToUpper()

Write-Host "DEBUG: TenantId        = $TenantId"
Write-Host "DEBUG: ClientId        = $ClientId"
Write-Host "DEBUG: adh_group       = $adh_group"
Write-Host "DEBUG: adh_sub_group   = '$adh_sub_group'"
Write-Host "DEBUG: Custodian       = $custodian"
Write-Host "DEBUG: CustodianUpper  = $custUpper"
Write-Host "DEBUG: subscription    = $adh_subscription_type"
Write-Host "DEBUG: OutputDir       = $OutputDir"
Write-Host "DEBUG: BranchName      = $BranchName"

# --------------------------------------------------------------------
# Connect to Azure
# --------------------------------------------------------------------
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
  throw "Azure connection failed."
}

$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
if ($subs -isnot [System.Collections.IEnumerable]) { $subs = ,$subs }

$rows = @()

# Service principal objectId for temporary KV admin assignment
$sp = Get-AzADServicePrincipal -ApplicationId $ClientId -ErrorAction Stop
$spObjectId = $sp.Id

foreach ($sub in $subs) {
  Set-ScContext -Subscription $sub

  Write-Host ""
  Write-Host "=== KV network scan for subscription: $($sub.Name) ===" -ForegroundColor Cyan

  # Get Key Vault resources in this subscription and filter by custodian
  $allKvs = Get-AzResource -ResourceType "Microsoft.KeyVault/vaults" -ErrorAction SilentlyContinue
  if (-not $allKvs) { continue }

  # Only scan KVs whose names contain our custodian code
  $kvs = $allKvs | Where-Object { $_.Name -like "*$custUpper*" }

  if (-not $kvs -or $kvs.Count -eq 0) {
      Write-Host "DEBUG: No KeyVaults matching custodian '$custUpper' in subscription $($sub.Name)"
      continue
  }

  foreach ($kv in $kvs) {
    $scope   = $kv.Id
    $success = $false

    # --------------------------------------------------------------
    # Assign Key Vault Administrator role if not present
    # --------------------------------------------------------------
    try {
      $assignment = Get-AzRoleAssignment `
                      -ObjectId $spObjectId `
                      -RoleDefinitionName "Key Vault Administrator" `
                      -Scope $scope `
                      -ErrorAction SilentlyContinue

      if (-not $assignment) {
        New-AzRoleAssignment `
          -ObjectId $spObjectId `
          -RoleDefinitionName "Key Vault Administrator" `
          -Scope $scope `
          -ErrorAction Stop

        Write-Host "Assigned 'Key Vault Administrator' to SPN on $($kv.Name)"
        Start-Sleep -Seconds 30
      }
    } catch {
      Write-Warning "Failed to assign Key Vault Administrator role on $($kv.Name): $_"
    }

    # --------------------------------------------------------------
    # Get network settings and private endpoint info
    # --------------------------------------------------------------
    try {
      $keyVault = Get-AzKeyVault -Name $kv.Name -ResourceGroupName $kv.ResourceGroupName -ErrorAction Stop

      $def                = $keyVault.NetworkAcls.DefaultAction
      $publicNetworkAccess = $keyVault.PublicNetworkAccess

      # Private Endpoint connections summary
      $privateEndpointsSummary = ''
      try {
        $privateEndpoints = Get-AzKeyVaultPrivateEndpointConnection `
                              -VaultName $kv.Name `
                              -ResourceGroupName $kv.ResourceGroupName `
                              -ErrorAction Stop

        if ($privateEndpoints -and $privateEndpoints.Count -gt 0) {
          $privateEndpointsSummary = $privateEndpoints | ForEach-Object {
            "$($_.Name): $($_.Properties.PrivateLinkServiceConnectionState.Status)"
          } -join "; "
        }
        else {
          $privateEndpointsSummary = "None"
        }
      } catch {
        Write-Warning "Failed to list private endpoint connections for $($kv.Name): $_"
        $privateEndpointsSummary = "No permission"
      }

      $access = if ($publicNetworkAccess -eq 'Enabled') {
        'Public or Mixed'
      } else {
        'Private Only / Disabled Public Access'
      }

      $rows += [pscustomobject]@{
        SubscriptionName           = $sub.Name
        SubscriptionId             = $sub.Id
        VaultName                  = $kv.Name
        ResourceGroup              = $kv.ResourceGroupName
        DefaultAction              = $def
        PublicNetworkAccess        = $publicNetworkAccess
        PublicOrPrivate            = $access
        PrivateEndpointConnections = $privateEndpointsSummary
      }

      $success = $true
    } catch {
      Write-Warning "Unable to retrieve network settings for KV $($kv.Name): $_"
    }

    # --------------------------------------------------------------
    # OPTIONAL: Remove Key Vault Administrator role afterwards
    # --------------------------------------------------------------
    if ($success) {
      try {
        $assignment = Get-AzRoleAssignment `
                        -ObjectId $spObjectId `
                        -RoleDefinitionName "Key Vault Administrator" `
                        -Scope $scope `
                        -ErrorAction SilentlyContinue

        if ($assignment) {
          Remove-AzRoleAssignment -RoleAssignmentId $assignment.Id -Force
          Write-Host "Revoked 'Key Vault Administrator' from SPN on $($kv.Name)"
        }
      } catch {
        Write-Warning "Failed to revoke 'Key Vault Administrator' from SPN on $($kv.Name): $_"
      }
    }
  }
}

# --------------------------------------------------------------------
# Handle no results (optional safeguard)
# --------------------------------------------------------------------
if (-not $rows -or $rows.Count -eq 0) {
    $rows = @(
        [pscustomobject]@{
            SubscriptionName           = ''
            SubscriptionId             = ''
            VaultName                  = ''
            ResourceGroup              = ''
            DefaultAction              = ''
            PublicNetworkAccess        = ''
            PublicOrPrivate            = ''
            PrivateEndpointConnections = ''
        }
    )
}

# --------------------------------------------------------------------
# Output results
# File name uses adh_group or adh_group_adh_sub_group
# --------------------------------------------------------------------
$groupForFile = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) {
    $adh_group
} else {
    "${adh_group}_${adh_sub_group}"
}

$csvOut = New-StampedPath -BaseDir $OutputDir -Prefix ("kv_networks_{0}_{1}" -f $groupForFile, $adh_subscription_type)
Write-CsvSafe -Rows $rows -Path $csvOut

$htmlOut = $csvOut -replace '\.csv$', '.html'
Convert-CsvToHtml -CsvPath $csvOut -HtmlPath $htmlOut -Title "KV Networking ($groupForFile / $adh_subscription_type) $BranchName"

Write-Host "KV network scan completed."
Write-Host "CSV : $csvOut"
Write-Host "HTML: $htmlOut"
