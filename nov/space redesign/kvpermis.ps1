param(
  [Parameter(Mandatory)][string]$TenantId,
  [Parameter(Mandatory)][string]$ClientId,
  [Parameter(Mandatory)][string]$ClientSecret,

  [Parameter(Mandatory)][string]$adh_group,

  # May come as ' ' from pipeline – normalize below
  [string]$adh_sub_group = '',

  [ValidateSet('nonprd','prd')][string]$adh_subscription_type = 'nonprd',

  [Parameter(Mandatory)][string]$KvPermCsvPath,
  [Parameter(Mandatory)][string]$OutputDir,
  [string]$BranchName = ''
)

Import-Module Az.Accounts, Az.KeyVault, Az.Resources -ErrorAction Stop
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

Write-Host "DEBUG: TenantId        = $TenantId"
Write-Host "DEBUG: ClientId        = $ClientId"
Write-Host "DEBUG: adh_group       = $adh_group"
Write-Host "DEBUG: adh_sub_group   = '$adh_sub_group'"
Write-Host "DEBUG: subscription    = $adh_subscription_type"
Write-Host "DEBUG: KvPermCsvPath   = $KvPermCsvPath"
Write-Host "DEBUG: OutputDir       = $OutputDir"
Write-Host "DEBUG: BranchName      = $BranchName"

if (-not (Test-Path -LiteralPath $KvPermCsvPath)) {
  throw "Permissions CSV not found: $KvPermCsvPath"
}
$csvContent = Import-Csv $KvPermCsvPath

# --------------------------------------------------------------------
# Determine <<cust>> token used in CSV replacement
#   - If ONLY adh_group     => <<cust>> = adh_group
#   - If adh_sub_group set  => <<cust>> = adh_group-adh_sub_group
# --------------------------------------------------------------------
$custToken = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) {
    $adh_group
} else {
    "{0}-{1}" -f $adh_group, $adh_sub_group
}

Write-Host "DEBUG: custToken (<<cust>> replacement) = $custToken"

# --------------------------------------------------------------------
# Environments to scan based on subscription type
# --------------------------------------------------------------------
$environmentsToScan = if ($adh_subscription_type -eq 'prd') {
    @('prd')
} else {
    @('dev','tst','stg')
}
Write-Host "DEBUG: EnvironmentsToScan = $($environmentsToScan -join ', ')"

# --------------------------------------------------------------------
# Replace <<cust>> tokens with custToken and filter environments
# CSV columns expected: Environment, resource_group_name, key_vault_name, name, role_definition_name, principal_type
# --------------------------------------------------------------------
$expanded = $csvContent |
  Where-Object { $environmentsToScan -contains $_.Environment } |
  ForEach-Object {
    [PSCustomObject]@{
      Environment           = $_.Environment
      resource_group_name   = $_.resource_group_name -replace '<<cust>>', $custToken
      key_vault_name        = $_.key_vault_name      -replace '<<cust>>', $custToken
      name                  = $_.name                -replace '<<cust>>', $custToken
      role_definition_name  = $_.role_definition_name
      principal_type        = $_.principal_type
    }
  }

# --------------------------------------------------------------------
# Connect to Azure
# --------------------------------------------------------------------
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
  throw "Azure connection failed."
}

# --------------------------------------------------------------------
# Subscription selection (kept as-is, with special cases)
# --------------------------------------------------------------------
switch ($adh_group.ToUpper()) {
  'KTK' {
    $subs = Get-AzSubscription | Where-Object { $_.Name -eq 'dev_azure_20401_ADHPlatform' }
  }
  'MDM' {
    if ($adh_subscription_type -eq 'prd') {
      $subs = Get-AzSubscription | Where-Object { $_.Name -eq 'prd_azure_20910_ADHMDM' }
    } else {
      $subs = Get-AzSubscription | Where-Object { $_.Name -eq 'dev_azure_20911_ADHMDM' }
    }
  }
  'NHH' {
    if ($adh_subscription_type -eq 'prd') {
      $subs = Get-AzSubscription | Where-Object { $_.Name -eq 'prd_azure_21000_ADHNHH' }
    } else {
      $subs = Get-AzSubscription | Where-Object { $_.Name -eq 'dev_azure_21001_ADHNHH' }
    }
  }
  Default {
    $subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
  }
}

$result = @()

foreach ($sub in $subs) {
  Set-ScContext -Subscription $sub
  $allKvs = Get-AzResource -ResourceType "Microsoft.KeyVault/vaults" -ErrorAction SilentlyContinue

  foreach ($row in $expanded) {

    $kvName   = $row.key_vault_name
    $role     = $row.role_definition_name
    $principal = $row.name

    $kv = $allKvs | Where-Object { $_.Name -eq $kvName }
    if (-not $kv) {
      Write-Host "DEBUG: Skipping as vault $kvName is not found in sub $($sub.Name)"
      continue
    }

    foreach ($v in $kv) { # handle multiple vaults of the same name in diff RGs
      $kvResourceId = $v.ResourceId

      $assign = Get-AzRoleAssignment -Scope $kvResourceId -ErrorAction SilentlyContinue |
                Where-Object {
                  ($_.RoleDefinitionName -eq $role) -and
                  (($_.DisplayName -eq $principal) -or ($_.PrincipalName -eq $principal))
                }

      $exists = [bool]$assign

      $result += [pscustomobject]@{
        SubscriptionName = $sub.Name
        VaultName        = $kvName
        Principal        = $principal
        RoleDefinition   = $role
        Exists           = $(if ($exists) { 'Yes' } else { 'No' })
      }
    }
  }
}

# --------------------------------------------------------------------
# Output file naming: include custToken (adh_group or adh_group-adh_sub_group)
# --------------------------------------------------------------------
$csvOut = New-StampedPath -BaseDir $OutputDir -Prefix ("kv_rbac_{0}_{1}" -f $custToken, $adh_subscription_type)
Write-CsvSafe -Rows $result -Path $csvOut

$htmlOut = $csvOut -replace '\.csv$','.html'
Convert-CsvToHtml -CsvPath $csvOut -HtmlPath $htmlOut -Title "KV Permissions ($custToken / $adh_subscription_type) $BranchName"

Write-Host "KV Permissions scan completed."
Write-Host "CSV : $csvOut"
Write-Host "HTML: $htmlOut"
