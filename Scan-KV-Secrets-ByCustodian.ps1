param(
  [Parameter(Mandatory)][string]$TenantId,
  [Parameter(Mandatory)][string]$ClientId,
  [Parameter(Mandatory)][string]$ClientSecret,
  [Parameter(Mandatory)][string]$kvSecretsCsvPath,   # CSV with column: SECRET_NAME
  [Parameter(Mandatory)][string]$adh_group,
  [ValidateSet('nonprd','prd')][string]$adh_subscription_type = 'nonprd',
  [Parameter(Mandatory)][string]$OutputDir,
  [string]$BranchName = ''
)

Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force
Ensure-Dir $OutputDir
Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret

$required = Import-Csv $kvSecretsCsvPath | Where-Object { $_.SECRET_NAME -and ($_.SECRET_NAME.Trim() -ne '') }

$rows = @()
$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
foreach ($sub in $subs) {
  Set-ScContext -Subscription $sub

  $vaults = Get-AzKeyVault -ErrorAction SilentlyContinue
  foreach ($v in $vaults) {
    foreach ($r in $required) {
      $s = Get-AzKeyVaultSecret -VaultName $v.VaultName -Name $r.SECRET_NAME -ErrorAction SilentlyContinue
      $rows += [pscustomobject]@{
        SubscriptionName = $sub.Name
        SubscriptionId   = $sub.Id
        ResourceGroup    = $v.ResourceGroupName
        Vault            = $v.VaultName
        SecretName       = $r.SECRET_NAME
        Exists           = if ($s) { 'EXISTS' } else { 'MISSING' }
      }
    }
  }
}

$csv = New-StampedPath -BaseDir $OutputDir -Prefix "kv_secrets_${adh_group}_${adh_subscription_type}"
Write-CsvSafe -Rows $rows -Path $csv
Convert-CsvToHtml -CsvPath $csv -HtmlPath ($csv -replace '\.csv$','.html') -Title "KV Secrets ($adh_group / $adh_subscription_type) $BranchName"
