#Requires -Modules Az.Accounts, Az.Resources
<#
  Scans RG-level role assignments against an expected CSV (prod/nonprod).
  - Replaces <Custodian> tokens with the passed -adh_group
  - Resolves subscriptions using helpers in Common.psm1:
      Connect-ScAz, Get-ScSubscriptions, Ensure-Dir, New-StampedPath, Write-CsvSafe, Convert-CsvToHtml
  - Writes CSV + HTML to -OutputDir
#>

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

# --- Load helpers
$common = Join-Path $PSScriptRoot 'Common.psm1'
if (-not (Test-Path -LiteralPath $common)) { throw "Common.psm1 not found at $common" }
Import-Module $common -Force

# --- Prep output
Ensure-Dir -Path $OutputDir | Out-Null

# --- Pick CSV by env
$csvPath = if ($adh_subscription_type -eq 'prd') { $ProdCsvPath } else { $NonProdCsvPath }
if (-not (Test-Path -LiteralPath $csvPath)) {
  throw "CSV not found: $csvPath. Expected headers: resource_group_name,role_definition_name,ad_group_name"
}

# --- Load CSV (header-insensitive)
$rowsRaw = Import-Csv -Path $csvPath
if (-not $rowsRaw -or $rowsRaw.Count -eq 0) { throw "Input CSV is empty: $csvPath" }

# build a header map to tolerate case/underscore differences
$hdr = @{}
$cols = $rowsRaw[0].PSObject.Properties.Name
foreach ($c in $cols) { $hdr[ ($c -replace '\s','' -replace '_','' ).ToLowerInvariant() ] = $c }

foreach ($need in @('resourcegroupname','roledefinitionname','adgroupname')) {
  if (-not $hdr.ContainsKey($need)) {
    $present = $cols -join ', '
    throw "CSV missing a header like '$need'. Present: $present"
  }
}

# --- Connect and get subscriptions
Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret | Out-Null
$subs = @( Get-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type )
if (-not $subs -or $subs.Count -eq 0) {
  throw "No subscriptions resolved for adh_group='$adh_group' environment='$adh_subscription_type'."
}

# --- Scan
$result = @()

foreach ($sub in $subs) {
  try {
    Set-AzContext -SubscriptionId $sub.Id -ErrorAction Stop | Out-Null
  } catch {
    Write-Warning "Failed to set context for subscription $($sub.Name): $_"
    continue
  }

  foreach ($r in $rowsRaw) {
    $rgRaw   = "$($r.$($hdr['resourcegroupname']))"
    $role    = "$($r.$($hdr['roledefinitionname']))"
    $aadRaw  = "$($r.$($hdr['adgroupname']))"

    # token replacement
    $rgName      = $rgRaw  -replace '<Custodian>', $adh_group
    $aadExpected = $aadRaw -replace '<Custodian>', $adh_group

    $rg = Get-AzResourceGroup -Name $rgName -ErrorAction SilentlyContinue
    $rgStatus = if ($rg) { 'EXISTS' } else { 'NOT_FOUND' }
    $permStatus = 'N/A'
    $details = ''

    if ($rg) {
      $scope = $rg.ResourceId
      # match on RoleDefinitionName and the principal's DisplayName
      $assign = Get-AzRoleAssignment -Scope $scope -ErrorAction SilentlyContinue |
                Where-Object { $_.RoleDefinitionName -eq $role -and $_.DisplayName -eq $aadExpected }

      $permStatus = if ($assign) { 'EXISTS' } else { 'MISSING' }
      if (-not $assign) { $details = "Expected assignment not found for '$aadExpected' as '$role' at $scope" }
    } else {
      $details = 'Resource group not found'
    }

    $result += [pscustomobject]@{
      SubscriptionName     = $sub.Name
      SubscriptionId       = $sub.Id
      Environment          = $adh_subscription_type
      Custodian            = $adh_group

      InputResourceGroup   = $rgRaw
      ScannedResourceGroup = $rgName

      RoleDefinition       = $role
      InputAdGroup         = $aadRaw
      ResolvedAdGroup      = $aadExpected

      RGStatus             = $rgStatus
      PermissionStatus     = $permStatus
      Details              = $details
    }
  }
}

# --- Write outputs (CSV + HTML)
$csvOut = New-StampedPath -BaseDir $OutputDir -Prefix ("rg_permissions_{0}_{1}" -f $adh_group,$adh_subscription_type) -Ext 'csv'
Write-CsvSafe -Rows $result -Path $csvOut
$htmlOut = [System.IO.Path]::ChangeExtension($csvOut,'html')
Convert-CsvToHtml -CsvPath $csvOut -HtmlPath $htmlOut -Title "RG Permissions ($adh_group / $adh_subscription_type) $BranchName"

Write-Host "CSV  : $csvOut"
Write-Host "HTML : $htmlOut"
