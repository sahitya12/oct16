param(
  [Parameter(Mandatory)][string]$TenantId,
  [Parameter(Mandatory)][string]$ClientId,
  [Parameter(Mandatory)][string]$ClientSecret,
  [string]$ProdCsvPath,
  [string]$NonProdCsvPath,
  [Parameter(Mandatory)][string]$adh_group,
  [ValidateSet('nonprd','prd')][string]$adh_subscription_type = 'nonprd',
  [Parameter(Mandatory)][string]$OutputDir,
  [string]$BranchName = ''
)

$ErrorActionPreference = 'Stop'

# --- helpers ---------------------------------------------------------------
function Write-Info($msg){ Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $msg" }
function Ensure-NonEmpty {
  param([object[]]$Rows,[string]$Reason)
  if (-not $Rows -or $Rows.Count -eq 0) {
    Write-Info "No data generated → creating placeholder row so CSV/HTML publish won’t fail."
    return ,([pscustomobject]@{
      SubscriptionName     = ''
      SubscriptionId       = ''
      Environment          = $adh_subscription_type
      InputResourceGroup   = ''
      ScannedResourceGroup = ''
      RoleDefinition       = ''
      InputAdGroup         = ''
      ResolvedAdGroup      = ''
      RGStatus             = 'SKIPPED'
      PermissionStatus     = 'SKIPPED'
      Details              = $Reason
    })
  }
  return $Rows
}

# --- imports / I/O ---------------------------------------------------------
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force
Ensure-Dir -Path $OutputDir | Out-Null

$csvPath = if ($adh_subscription_type -eq 'prd') { $ProdCsvPath } else { $NonProdCsvPath }
Write-Info "Resolved CSV path: $csvPath"
if (-not (Test-Path -LiteralPath $csvPath)) { throw "CSV not found: $csvPath" }

$inputRows = Import-Csv -Path $csvPath
Write-Info "CSV rows loaded: $($inputRows.Count)"

# --- Azure auth & subscription discovery -----------------------------------
Write-Info "Connecting to Azure…"
$connected = Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
if (-not $connected) { throw "Azure connection failed (Connect-ScAz returned falsy)." }
Write-Info "Azure connection OK."

Write-Info "Getting subscriptions for group '$adh_group' in '$adh_subscription_type'…"
$subs = Get-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
$subCount = ($subs | Measure-Object).Count
Write-Info "Subscriptions found: $subCount"

# --- main build ------------------------------------------------------------
$result = @()

if ($subCount -gt 0 -and $inputRows.Count -gt 0) {
  foreach ($sub in $subs) {
    foreach ($row in $inputRows) {
      $rgName = ($row.resource_group_name ?? '') -replace '<Custodian>', $adh_group
      $aadGrp = ($row.ad_group_name ?? '')       -replace '<Custodian>', $adh_group
      $role   = ($row.role_definition_name ?? '')

      $result += [pscustomobject]@{
        SubscriptionName     = $sub.Name
        SubscriptionId       = $sub.Id
        Environment          = $adh_subscription_type
        InputResourceGroup   = $row.resource_group_name
        ScannedResourceGroup = $rgName
        RoleDefinition       = $role
        InputAdGroup         = $row.ad_group_name
        ResolvedAdGroup      = $aadGrp
        RGStatus             = 'UNKNOWN'
        PermissionStatus     = 'UNKNOWN'
        Details              = ''
      }
    }
  }
} else {
  $why = @()
  if ($subCount -eq 0)      { $why += "No subscriptions returned by Get-ScSubscriptions." }
  if ($inputRows.Count -eq 0) { $why += "CSV is empty or headers didn’t parse." }
  $result = Ensure-NonEmpty -Rows $result -Reason ($why -join ' ')
}

# --- output ---------------------------------------------------------------
$csvOut = New-StampedPath -BaseDir $OutputDir -Prefix ("rg_permissions_{0}_{1}" -f $adh_group,$adh_subscription_type) -Ext 'csv'
Write-Info "Writing CSV → $csvOut (rows: $($result.Count))"

# Guard again (never pass empty to Write-CsvSafe)
$result = Ensure-NonEmpty -Rows $result -Reason "Pipeline safeguard: empty dataset."
Write-CsvSafe -Rows $result -Path $csvOut

$htmlOut = [System.IO.Path]::ChangeExtension($csvOut,'html')
Convert-CsvToHtml -CsvPath $csvOut -HtmlPath $htmlOut -Title "RG Permissions ($adh_group / $adh_subscription_type) $BranchName"

Write-Info "Done. CSV: $csvOut"
Write-Info "Done. HTML: $htmlOut"
