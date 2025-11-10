<# Validation: check expected RG-role-group assignments from CSV #>
param(
  [Parameter(Mandatory)][string]$TenantId,
  [Parameter(Mandatory)][string]$ClientId,
  [Parameter(Mandatory)][string]$ClientSecret,

  [Parameter(Mandatory)][string]$ProdCsvPath,
  [Parameter(Mandatory)][string]$NonProdCsvPath,

  [Parameter(Mandatory)][string]$adh_group,
  [ValidateSet('nonprd','prd')][string]$adh_subscription_type = 'nonprd',

  [Parameter(Mandatory)][string]$OutputDir,
  [string]$BranchName = ''
)

Import-Module Az.Accounts, Az.Resources -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret

# Pick the right CSV and load rows
$csvPath = if ($adh_subscription_type -eq 'prd') { $ProdCsvPath } else { $NonProdCsvPath }
if (-not (Test-Path -LiteralPath $csvPath)) {
  throw "CSV not found: $csvPath (expected columns: resource_group_name,role_definition_name,ad_group_name)"
}
$input = Import-Csv -Path $csvPath
if (-not $input -or $input.Count -eq 0) { throw "Input CSV is empty: $csvPath" }

# Normalize column names (case-insensitive, flexible)
$hdrMap = @{}
$first = $input[0]
foreach ($h in $first.PSObject.Properties.Name) {
  $hdrMap[ ($h -replace '\s','' -replace '_','' ).ToLowerInvariant() ] = $h
}
foreach ($need in @('resourcegroupname','roledefinitionname','adgroupname')) {
  if (-not $hdrMap.ContainsKey($need)) {
    throw "CSV missing a header like '$need'. Present headers: $($first.PSObject.Properties.Name -join ', ')"
  }
}

$subs = @(Resolve-AdhSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type)
if (-not $subs) { throw "No matching subscriptions for $adh_group / $adh_subscription_type" }

Ensure-Dir -Path $OutputDir
$csvOut  = New-StampedPath -BaseDir $OutputDir -Prefix "rg_permissions_validate_${adh_group}_$adh_subscription_type"
$htmlOut = [IO.Path]::ChangeExtension($csvOut, '.html')

$results = @()

foreach ($sub in $subs) {
  Set-AzContext -SubscriptionId $sub.Id | Out-Null

  foreach ($row in $input) {
    $rgRaw  = "$($row.$($hdrMap['resourcegroupname']))"
    $role   = "$($row.$($hdrMap['roledefinitionname']))"
    $aadRaw = "$($row.$($hdrMap['adgroupname']))"

    # Replace <Custodian> token
    $rgName    = $rgRaw  -replace '<Custodian>', $adh_group
    $aadExpect = $aadRaw -replace '<Custodian>', $adh_group

    $rg = Get-AzResourceGroup -Name $rgName -ErrorAction SilentlyContinue
    $rgStatus = if ($rg) { 'EXISTS' } else { 'NOT_FOUND' }
    $permStatus = 'N/A'
    $details = ''

    if ($rg) {
      $scope = "/subscriptions/{0}/resourceGroups/{1}" -f $sub.Id, $rgName
      $assign = Get-AzRoleAssignment -Scope $scope -ErrorAction SilentlyContinue |
                Where-Object { $_.RoleDefinitionName -eq $role -and $_.DisplayName -eq $aadExpect }

      $permStatus = if ($assign) { 'EXISTS' } else { 'MISSING' }
      if (-not $assign) { $details = 'Expected assignment not found at RG scope' }
    } else {
      $details = 'Resource group not found'
    }

    $results += [pscustomobject]@{
      SubscriptionName     = $sub.Name
      SubscriptionId       = $sub.Id
      Environment          = $adh_subscription_type
      Custodian            = $adh_group
      InputResourceGroup   = $rgRaw
      ScannedResourceGroup = $rgName
      RoleDefinition       = $role
      InputAdGroup         = $aadRaw
      ResolvedAdGroup      = $aadExpect
      RGStatus             = $rgStatus
      PermissionStatus     = $permStatus
      Details              = $details
    }
  }
}

Write-CsvSafe -Rows $results -Path $csvOut
Convert-CsvToHtml -CsvPath $csvOut -HtmlPath $htmlOut -Title "RG Permission Validation – $adh_group ($adh_subscription_type) $BranchName"

Write-Host "CSV:  $csvOut"
Write-Host "HTML: $htmlOut"
