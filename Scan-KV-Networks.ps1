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

  $vaults = Get-AzKeyVault -ErrorAction SilentlyContinue
  foreach ($v in $vaults) {
    $rows += [pscustomobject]@{
      SubscriptionName     = $sub.Name
      SubscriptionId       = $sub.Id
      ResourceGroup        = $v.ResourceGroupName
      Vault                = $v.VaultName
      PublicNetworkAccess  = $v.Properties.PublicNetworkAccess
      DefaultAction        = $v.Properties.NetworkAcls.DefaultAction
      IpRules              = ($v.Properties.NetworkAcls.IpRules | ForEach-Object {$_.Value} -join ';')
      VnetRules            = ($v.Properties.NetworkAcls.VirtualNetworkRules | ForEach-Object {$_.Id} -join ';')
    }
  }
}

$csv = New-StampedPath -BaseDir $OutputDir -Prefix "kv_networks_${adh_group}_${adh_subscription_type}"
Write-CsvSafe -Rows $rows -Path $csv
Convert-CsvToHtml -CsvPath $csv -HtmlPath ($csv -replace '\.csv$','.html') -Title "KV Firewall ($adh_group / $adh_subscription_type) $BranchName"
