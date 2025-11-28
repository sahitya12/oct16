param(
    [Parameter(Mandatory = $true)][string]$TenantId,
    [Parameter(Mandatory = $true)][string]$ClientId,
    [Parameter(Mandatory = $true)][string]$ClientSecret,

    [Parameter(Mandatory = $true)][string]$adh_group,

    # Will often be passed as " " from pipeline – normalize below
    [string]$adh_sub_group = '',

    [ValidateSet('nonprd','prd')][string]$adh_subscription_type = 'nonprd',

    [Parameter(Mandatory = $true)][string]$InputCsvPath,
    [Parameter(Mandatory = $true)][string]$OutputDir,
    [string]$BranchName = ''
)

Import-Module Az.Accounts, Az.KeyVault, Az.Resources -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop
Ensure-Dir $OutputDir | Out-Null

# --------------------------------------------------------------------
# Normalize adh_sub_group (handle " " from pipeline)
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
# Load CSV and detect KV / Secret columns
# --------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $InputCsvPath)) {
    throw "Secrets CSV not found: $InputCsvPath"
}

$csvRaw = Import-Csv -LiteralPath $InputCsvPath
if (-not $csvRaw -or $csvRaw.Count -eq 0) {
    throw "Secrets CSV '$InputCsvPath' has no rows at all."
}

$headers = $csvRaw[0].PSObject.Properties.Name
Write-Host ("DEBUG: Raw header columns      : " + ($headers -join ', '))
Write-Host ("DEBUG: Raw row count           : " + $csvRaw.Count)

# Try to find a KV column (contains 'KEYVAULT' or 'VAULT')
$kvHeader = $headers |
    Where-Object { $_ -match 'KEYVAULT' -or $_ -match 'VAULT' } |
    Select-Object -First 1

# Try to find a Secret column (contains 'SECRET')
$secHeader = $headers |
    Where-Object { $_ -match 'SECRET' } |
    Select-Object -First 1

if (-not $kvHeader -or -not $secHeader) {
    throw "Could not detect KEYVAULT / SECRET columns. Headers are: $($headers -join ', ')"
}

Write-Host "DEBUG: Detected KV column       : $kvHeader"
Write-Host "DEBUG: Detected Secret column   : $secHeader"

# Normalise rows into a simple (KvTemplate, SecretName) structure
$csvContent = @()
$rowNumber = 0
foreach ($row in $csvRaw) {
    $rowNumber++

    $kvName  = $row.$kvHeader
    $secName = $row.$secHeader

    $kvName  = if ($kvName)  { $kvName.ToString().Trim() }  else { '' }
    $secName = if ($secName) { $secName.ToString().Trim() } else { '' }

    if ([string]::IsNullOrWhiteSpace($kvName) -and [string]::IsNullOrWhiteSpace($secName)) {
        Write-Host "DEBUG: Row #$rowNumber is completely empty, skipping."
        continue
    }
    if ([string]::IsNullOrWhiteSpace($kvName) -or [string]::IsNullOrWhiteSpace($secName)) {
        Write-Host "DEBUG: Row #$rowNumber missing KV or Secret (KV='$kvName', Secret='$secName'), skipping."
        continue
    }

    $csvContent += [pscustomobject]@{
        KvTemplate = $kvName
        SecretName = $secName
    }
}

Write-Host ("DEBUG: Usable CSV data rows     : " + $csvContent.Count)

if (-not $csvContent -or $csvContent.Count -eq 0) {
    Write-Host "WARN: After filtering, CSV has no usable rows (no KEYVAULT_NAME + SECRET_NAME)."
}

# --------------------------------------------------------------------
# Custodian + env logic
#   <Custodian> → adh_group OR adh_group-adh_sub_group (hyphen)
#   <env>       → dev/tst/stg (nonprd) or prd (prd)
# --------------------------------------------------------------------
$custodian = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) {
    $adh_group
}
else {
    "$adh_group-$adh_sub_group"   # IMPORTANT: hyphen, not underscore
}

$envs = if ($adh_subscription_type -eq 'prd') { @('prd') } else { @('dev','tst','stg') }

Write-Host "DEBUG: Custodian string         = $custodian"
Write-Host "DEBUG: Environments to scan     = $($envs -join ', ')"

# --------------------------------------------------------------------
# Connect to Azure
# --------------------------------------------------------------------
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure connection failed."
}

# --------------------------------------------------------------------
# Resolve subscriptions (same way as other sanitycheck scripts)
# --------------------------------------------------------------------
$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
if ($subs -isnot [System.Collections.IEnumerable]) { $subs = ,$subs }

if (-not $subs -or $subs.Count -eq 0) {
    Write-Host "WARN: No subscriptions resolved for $adh_group / $adh_subscription_type"
}

Write-Host "DEBUG: Subscriptions resolved   = $($subs.Name -join ', ')"

# --------------------------------------------------------------------
# Main scan
# --------------------------------------------------------------------
$result = @()

foreach ($sub in $subs) {

    Write-Host ""
    Write-Host "=== Subscription: $($sub.Name) ===" -ForegroundColor Cyan

    Set-ScContext -Subscription $sub

    # Cache all KVs in this subscription
    $allKVs = Get-AzResource -ResourceType "Microsoft.KeyVault/vaults" -ErrorAction SilentlyContinue
    if ($allKVs) {
        Write-Host "DEBUG: KeyVaults in '$($sub.Name)': $($allKVs.Name -join ', ')"
    }
    else {
        Write-Host "DEBUG: No KeyVaults found in subscription '$($sub.Name)'"
    }

    $rowIndex = 0
    foreach ($row in $csvContent) {
        $rowIndex++

        $rawKvName  = $row.KvTemplate
        $secretName = $row.SecretName

        foreach ($env in $envs) {

            # Replace <Custodian> and <env> in KEYVAULT_NAME template
            $vaultName = $rawKvName
            $vaultName = $vaultName -replace '<Custodian>', $custodian
            $vaultName = $vaultName -replace '<env>',       $env
            $vaultName = $vaultName.Trim()

            Write-Host "DEBUG: row#$rowIndex sub='$($sub.Name)' env='$env' template='$rawKvName' -> vault='$vaultName', secret='$secretName'"

            $kvRg   = ''
            $exists = $false
            $note   = ''

            # Look for KV in cached list (case insensitive)
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
# Debug: how many rows did we actually get?
# --------------------------------------------------------------------
Write-Host "DEBUG: Total result rows        = $($result.Count)"

if ($result.Count -gt 0) {
    Write-Host "DEBUG: First few result rows:"
    $result | Select-Object -First 5 |
        Format-Table -AutoSize |
        Out-String |
        Write-Host
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
# Output files (CSV + HTML)
# --------------------------------------------------------------------
$groupForFile = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) {
    $adh_group
}
else {
    "$adh_group-$adh_sub_group"   # Again: hyphen
}

$csvOut = New-StampedPath -BaseDir $OutputDir -Prefix ("kv_secrets_{0}_{1}" -f $groupForFile, $adh_subscription_type)
Write-CsvSafe -Rows $result -Path $csvOut

$htmlOut = $csvOut -replace '\.csv$','.html'
Convert-CsvToHtml -CsvPath $csvOut -HtmlPath $htmlOut -Title "KV Secrets ($groupForFile / $adh_subscription_type) $BranchName"

Write-Host "KV Secrets scan completed."
Write-Host "CSV : $csvOut"
Write-Host "HTML: $htmlOut"
