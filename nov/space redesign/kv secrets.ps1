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
# Normalize adh_sub_group (handle single-space from pipeline)
# --------------------------------------------------------------------
$adh_sub_group = $adh_sub_group.Trim()
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

if (-not (Test-Path -LiteralPath $InputCsvPath)) {
  throw "Secrets CSV not found: $InputCsvPath"
}

$csvContent = Import-Csv $InputCsvPath
Write-Host ("DEBUG: Found header columns: " + ($csvContent[0].psobject.Properties.Name -join ', '))

# --------------------------------------------------------------------
# Determine Custodian used in KV name replacement
# --------------------------------------------------------------------
$custodian = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) {
    $adh_group
} else {
    "${adh_group}_${adh_sub_group}"
}
$custodianUpper = $custodian.ToUpper()

# Environments based on subscription type
$envs = if ($adh_subscription_type -eq 'prd') { @('prd') } else { @('dev','tst','stg') }

Write-Host "DEBUG: Custodian       = $custodian"
Write-Host "DEBUG: CustodianUpper  = $custodianUpper"
Write-Host "DEBUG: Environments    = $($envs -join ', ')"

# --------------------------------------------------------------------
# Connect & resolve subscriptions
# --------------------------------------------------------------------
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
  throw "Azure connection failed."
}
$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type

$result = @()

foreach ($sub in $subs) {
  Set-ScContext -Subscription $sub

  foreach ($row in $csvContent) {

    # Expecting columns: KEYVAULT_NAME, SECRET_NAME (from kvsecretsscan.csv)
    $rawKvName   = $row.KEYVAULT_NAME
    $secretName  = $row.SECRET_NAME

    if ([string]::IsNullOrWhiteSpace($rawKvName) -or [string]::IsNullOrWhiteSpace($secretName)) {
        continue
    }

    foreach ($env in $envs) {

        # Replace <Custodian> and <env> in KEYVAULT_NAME
        $vaultName = $rawKvName
        $vaultName = $vaultName -replace '<Custodian>', $custodianUpper
        $vaultName = $vaultName -replace '<env>', $env

        Write-Host "DEBUG: Checking KV '$vaultName' / secret '$secretName' in sub '$($sub.Name)' env '$env'"

        $exists = $false
        try {
            # Resolve actual KV resource to confirm existence
            $kvRes = Get-AzResource -ResourceType "Microsoft.KeyVault/vaults" -Name $vaultName -ErrorAction Stop
            $kvRg  = $kvRes.ResourceGroupName

            try {
                $s = Get-AzKeyVaultSecret -VaultName $vaultName -Name $secretName -ErrorAction Stop
                if ($null -ne $s) { $exists = $true }
            } catch {
                $exists = $false
            }
        }
        catch {
            # KV itself not found
            $kvRg = ''
            $exists = $false
        }

        $existsText = if ($exists) { 'Yes' } else { 'No' }
        $notes      = if ($exists) { 'Secret exists' } else { 'Secret missing' }

        $result += [pscustomobject]@{
            SubscriptionName = $sub.Name
            VaultName        = $vaultName
            ResourceGroup    = $kvRg
            Environment      = $env
            SecretName       = $secretName
            Exists           = $existsText
            Notes            = $notes
        }
    }
  }
}

# --------------------------------------------------------------------
# Output file naming: include adh_sub_group when present
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
