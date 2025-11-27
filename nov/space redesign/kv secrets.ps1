param(
  [Parameter(Mandatory)][string]$TenantId,
  [Parameter(Mandatory)][string]$ClientId,
  [Parameter(Mandatory)][string]$ClientSecret,

  [Parameter(Mandatory)][string]$adh_group,

  # May come as ' ' from pipeline – normalize below
  [string]$adh_sub_group = '',

  [ValidateSet('nonprd','prd')][string]$adh_subscription_type = 'nonprd',

  [Parameter(Mandatory)][string]$InputCsvPath,
  [Parameter(Mandatory)][string]$OutputDir,
  [string]$BranchName = ''
)

Import-Module Az.Accounts, Az.KeyVault, Az.Resources -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop
Ensure-Dir $OutputDir | Out-Null

# --------------------------------------------------------------------
# Normalize adh_sub_group (handle single space from pipeline)
# --------------------------------------------------------------------
if ($null -ne $adh_sub_group) {
    $adh_sub_group = $adh_sub_group.Trim()
}
if ([string]::IsNullOrWhiteSpace($adh_sub_group)) {
    Write-Host "DEBUG: adh_sub_group is empty/space -> treating as <none>"
    $adh_sub_group = ''
}

Write-Host "DEBUG: TenantId        = $TenantId"
Write-Host "DEBUG: ClientId        = $ClientId"
Write-Host "DEBUG: adh_group       = $adh_group"
Write-Host "DEBUG: adh_sub_group   = '$adh_sub_group'"
Write-Host "DEBUG: subscription    = $adh_subscription_type"
Write-Host "DEBUG: InputCsvPath    = $InputCsvPath"
Write-Host "DEBUG: OutputDir       = $OutputDir"
Write-Host "DEBUG: BranchName      = $BranchName"

# --------------------------------------------------------------------
# Load CSV (expects KEYVAULT_NAME, SECRET_NAME columns)
# --------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $InputCsvPath)) {
  throw "Secrets CSV not found: $InputCsvPath"
}

$csvRaw = Import-Csv $InputCsvPath
if (-not $csvRaw -or $csvRaw.Count -eq 0) {
  throw "Secrets CSV '$InputCsvPath' has no rows at all."
}

Write-Host ("DEBUG: Raw header columns  : " + ($csvRaw[0].psobject.Properties.Name -join ', '))
Write-Host ("DEBUG: Raw row count       : " + $csvRaw.Count)

# Keep only rows that actually have KV + secret values
$csvContent = $csvRaw | Where-Object {
    ($_.'KEYVAULT_NAME' -and $_.'KEYVAULT_NAME'.ToString().Trim() -ne '') -or
    ($_.'KeyVaultName'   -and $_.'KeyVaultName'.ToString().Trim()   -ne '') -or
    ($_.'VaultName'      -and $_.'VaultName'.ToString().Trim()      -ne '')
} | Where-Object {
    ($_.'SECRET_NAME' -and $_.'SECRET_NAME'.ToString().Trim() -ne '') -or
    ($_.'SecretName'  -and $_.'SecretName'.ToString().Trim()  -ne '')
}

Write-Host ("DEBUG: Filtered data rows  : " + $csvContent.Count)

if (-not $csvContent -or $csvContent.Count -eq 0) {
  Write-Host "WARN: After filtering, CSV has no usable rows (no KEYVAULT_NAME+SECRET_NAME)."
  $csvContent = @()
}

# --------------------------------------------------------------------
# Custodian + env logic  (<Custodian> & <env> placeholders)
# --------------------------------------------------------------------
$custodian = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) {
    $adh_group
} else {
    "${adh_group}_${adh_sub_group}"
}

$envs = if ($adh_subscription_type -eq 'prd') { @('prd') } else { @('dev','tst','stg') }

Write-Host "DEBUG: Custodian       = $custodian"
Write-Host "DEBUG: Environments    = $($envs -join ', ')"

# --------------------------------------------------------------------
# Connect to Azure
# --------------------------------------------------------------------
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
  throw "Azure connection failed."
}

# --------------------------------------------------------------------
# Subscription selection – ALWAYS use Resolve-ScSubscriptions
#    (old working behaviour)
# --------------------------------------------------------------------
$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
if ($subs -isnot [System.Collections.IEnumerable]) { $subs = ,$subs }

if (-not $subs -or $subs.Count -eq 0) {
  Write-Host "WARN: No subscriptions resolved for $adh_group / $adh_subscription_type"
}

Write-Host "DEBUG: Subscriptions   = $($subs.Name -join ', ')"

$result = @()

foreach ($sub in $subs) {

  Write-Host ""
  Write-Host "=== Subscription: $($sub.Name) ===" -ForegroundColor Cyan

  Set-ScContext -Subscription $sub

  # Cache all KVs once per subscription
  $allKVs = Get-AzResource -ResourceType "Microsoft.KeyVault/vaults" -ErrorAction SilentlyContinue
  if ($allKVs) {
      Write-Host "DEBUG: KeyVaults in sub '$($sub.Name)': " + ($allKVs.Name -join ', ')
  } else {
      Write-Host "DEBUG: No KeyVaults found in subscription '$($sub.Name)'"
  }

  $rowIndex = 0
  foreach ($row in $csvContent) {
    $rowIndex++

    # Robust header handling
    $rawKvName  = ($row.KEYVAULT_NAME, $row.KeyVaultName, $row.VaultName |
                   Where-Object { $_ -and $_.ToString().Trim() -ne '' } |
                   Select-Object -First 1)
    $secretName = ($row.SECRET_NAME, $row.SecretName |
                   Where-Object { $_ -and $_.ToString().Trim() -ne '' } |
                   Select-Object -First 1)

    if ([string]::IsNullOrWhiteSpace($rawKvName) -or
        [string]::IsNullOrWhiteSpace($secretName)) {
        Write-Host "DEBUG: Row #$rowIndex has empty KV / Secret, skipping."
        continue
    }

    $rawKvName  = $rawKvName.Trim()
    $secretName = $secretName.Trim()

    foreach ($env in $envs) {

        $vaultName = $rawKvName
        $vaultName = $vaultName -replace '<Custodian>', $custodian
        $vaultName = $vaultName -replace '<env>',       $env
        $vaultName = $vaultName.Trim()

        Write-Host "DEBUG: row#$rowIndex sub='$($sub.Name)' env='$env' template='$rawKvName' -> vault='$vaultName', secret='$secretName'"

        $kvRg   = ''
        $exists = $false
        $note   = ''

        $kvRes = $allKVs | Where-Object { $_.Name -ieq $vaultName }

        if ($kvRes) {
            foreach ($kv in $kvRes) {
                $kvRg = $kv.ResourceGroupName

                try {
                    $sec = Get-AzKeyVaultSecret -VaultName $kv.Name -Name $secretName -ErrorAction Stop
                    if ($null -ne $sec) { $exists = $true }
                }
                catch {
                    $exists = $false
                }

                $note = if ($exists) { 'Secret exists' } else { 'Secret missing' }

                $result += [pscustomobject]@{
                    SubscriptionName = $sub.Name
                    VaultName        = $kv.Name
                    ResourceGroup    = $kvRg
                    Environment      = $env
                    SecretName       = $secretName
                    Exists           = (if ($exists) { 'Yes' } else { 'No' })
                    Notes            = $note
                }
            }
        }
        else {
            # KV not found in this subscription – still record row
            $result += [pscustomobject]@{
                SubscriptionName = $sub.Name
                VaultName        = $vaultName
                ResourceGroup    = ''
                Environment      = $env
                SecretName       = $secretName
                Exists           = 'No'
                Notes            = 'Key Vault not found'
            }
        }
    }
  }
}

# --------------------------------------------------------------------
# Guard for completely empty result
# --------------------------------------------------------------------
if (-not $result -or $result.Count -eq 0) {
  Write-Host "WARN: No KV secrets evaluated; emitting NO_RESULTS row."
  $result = @(
    [pscustomobject]@{
      SubscriptionName = ''
      VaultName        = ''
      ResourceGroup    = ''
      Environment      = ''
      SecretName       = ''
      Exists           = 'NO_RESULTS'
      Notes            = 'No keyvaults matched OR CSV rows were empty/invalid'
    }
  )
}

# --------------------------------------------------------------------
# Output file naming: include adh_group_adh_sub_group when present
# --------------------------------------------------------------------
$groupForFile = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) {
    $adh_group
} else {
    "${adh_group}_${adh_sub_group}"
}

$csvOut = New-StampedPath -BaseDir $OutputDir -Prefix ("kv_secrets_{0}_{1}" -f $groupForFile, $adh_subscription_type)
Write-CsvSafe -Rows $result -Path $csvOut

$htmlOut = $csvOut -replace '\.csv$','.html'
Convert-CsvToHtml -CsvPath $csvOut -HtmlPath $htmlOut -Title "KV Secrets ($groupForFile / $adh_subscription_type) $BranchName"

Write-Host "KV Secrets scan completed."
Write-Host "CSV : $csvOut"
Write-Host "HTML: $htmlOut"
