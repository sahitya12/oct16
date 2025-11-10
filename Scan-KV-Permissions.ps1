param(
  [Parameter(Mandatory)][string]$TenantId,
  [Parameter(Mandatory)][string]$ClientId,
  [Parameter(Mandatory)][string]$ClientSecret,
  [Parameter(Mandatory)][string]$adh_group,
  [ValidateSet('nonprd','prd')][string]$adh_subscription_type = 'nonprd',
  [Parameter(Mandatory)][string]$OutputDir,
  [string]$BranchName = ''
)

Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force
Ensure-Dir $OutputDir
Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret

$rows = @()
$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
foreach ($sub in $subs) {
  Set-ScContext -Subscription $sub

  # all vaults in subscription (no narrowing to the first)
  $vaults = Get-AzKeyVault -ErrorAction SilentlyContinue
  foreach ($v in $vaults) {
    # RBAC
    $scope = "/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.KeyVault/vaults/{2}" -f $sub.Id,$v.ResourceGroupName,$v.VaultName
    $rbac = Get-AzRoleAssignment -Scope $scope -ErrorAction SilentlyContinue
    foreach ($ra in $rbac) {
      $rows += [pscustomobject]@{
        SubscriptionName = $sub.Name
        SubscriptionId   = $sub.Id
        ResourceGroup    = $v.ResourceGroupName
        Vault            = $v.VaultName
        Principal        = $ra.DisplayName
        PrincipalId      = $ra.ObjectId
        Role             = $ra.RoleDefinitionName
        Scope            = $ra.Scope
        Type             = 'RBAC'
      }
    }

    # Access policies (for classic KVs)
    $ap = $v.AccessPolicies
    foreach ($p in $ap) {
      $rows += [pscustomobject]@{
        SubscriptionName = $sub.Name
        SubscriptionId   = $sub.Id
        ResourceGroup    = $v.ResourceGroupName
        Vault            = $v.VaultName
        Principal        = $p.DisplayName
        PrincipalId      = $p.ObjectId
        Role             = 'AccessPolicy'
        Scope            = 'Vault'
        Type             = 'AccessPolicy'
      }
    }
  }
}

$csv = New-StampedPath -BaseDir $OutputDir -Prefix "kv_permissions_${adh_group}_${adh_subscription_type}"
Write-CsvSafe -Rows $rows -Path $csv
Convert-CsvToHtml -CsvPath $csv -HtmlPath ($csv -replace '\.csv$','.html') -Title "KV Permissions ($adh_group / $adh_subscription_type) $BranchName"
