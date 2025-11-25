param(
  [Parameter(Mandatory)][string]$TenantId,
  [Parameter(Mandatory)][string]$ClientId,
  [Parameter(Mandatory)][string]$ClientSecret,

  [string]$ProdCsvPath,
  [string]$NonProdCsvPath,

  [Parameter(Mandatory)][string]$adh_group,
  [string]$adh_sub_group = '',

  [ValidateSet('nonprd','prd')][string]$adh_subscription_type = 'nonprd',

  [Parameter(Mandatory)][string]$OutputDir,
  [string]$BranchName = ''
)

Import-Module Az.Accounts, Az.Resources -ErrorAction Stop

# Debug: Locate and import Common.psm1
$commonModulePath = Join-Path $PSScriptRoot 'Common.psm1'
Write-Host "DEBUG: Attempting to import Common.psm1 from: $commonModulePath"
Import-Module $commonModulePath -Force -ErrorAction Stop

# Debug: List commands to confirm availability
Write-Host "DEBUG: Listing functions from 'Common' module:"
(Get-Command -Module Common).Name | ForEach-Object { Write-Host "  $_" }

# Confirm Resolve-ScSubscriptions is imported
if (-not (Get-Command Resolve-ScSubscriptions -ErrorAction SilentlyContinue)) {
    throw "ERROR: Resolve-ScSubscriptions is not available after importing Common.psm1."
}

Ensure-Dir -Path $OutputDir | Out-Null

if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure connection failed."
}

# --------------------------------------------------------------------
# Choose CSV based on environment
# --------------------------------------------------------------------
$csvPath = if ($adh_subscription_type -eq 'prd') { $ProdCsvPath } else { $NonProdCsvPath }

if (-not (Test-Path -LiteralPath $csvPath)) {
    throw "CSV not found: $csvPath"
}

# --------------------------------------------------------------------
# Input rows + subscriptions
# --------------------------------------------------------------------
$inputRows = Import-Csv -Path $csvPath
$subs      = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type

# --------------------------------------------------------------------
# Custodian logic:
#  - If adh_sub_group is empty -> only adh_group
#  - If adh_sub_group is set  -> adh_group AND adh_group_adh_sub_group
# --------------------------------------------------------------------
if ([string]::IsNullOrWhiteSpace($adh_sub_group)) {
    $custodians = @($adh_group)
}
else {
    $custodians = @(
        $adh_group
        ("{0}_{1}" -f $adh_group, $adh_sub_group)
    )
}

Write-Host "DEBUG: Custodians to scan:" -ForegroundColor Cyan
$custodians | ForEach-Object { Write-Host "  - $_" }

$result = @()

foreach ($sub in $subs) {
    Set-ScContext -Subscription $sub

    Write-Host ""
    Write-Host "=== Subscription: $($sub.Name) ===" -ForegroundColor Cyan

    foreach ($row in $inputRows) {

        foreach ($custodian in $custodians) {

            # ------------------------------------------------------------------
            # Expand <Custodian> with current custodian value
            # ------------------------------------------------------------------
            $rgName = $row.resource_group_name -replace '<Custodian>', $custodian
            $role   = $row.role_definition_name
            $aadGrp = $row.ad_group_name      -replace '<Custodian>', $custodian

            # Defensive check and debug output
            if ([string]::IsNullOrWhiteSpace($rgName)) {
                Write-Host "SKIP: Blank or null resource group name on input row (Custodian=$custodian): $($row | Out-String)"
                continue
            }

            Write-Host "DEBUG: Checking RG '$rgName' for Custodian '$custodian', Role '$role', AAD Group '$aadGrp'"

            # ------------------------------------------------------------------
            # Check RG existence
            # ------------------------------------------------------------------
            $rg        = Get-AzResourceGroup -Name $rgName -ErrorAction SilentlyContinue
            $rgStatus  = if ($rg) { 'EXISTS' } else { 'NOT_FOUND' }
            $permStatus = 'N/A'
            $details    = ''

            if ($rg) {
                $scope = "/subscriptions/{0}/resourceGroups/{1}" -f $sub.Id, $rgName

                $assign = Get-AzRoleAssignment -Scope $scope -ErrorAction SilentlyContinue |
                          Where-Object {
                              $_.RoleDefinitionName -eq $role -and
                              $_.DisplayName        -eq $aadGrp
                          }

                if ($assign) {
                    $permStatus = 'EXISTS'
                }
                else {
                    $permStatus = 'MISSING'
                    $details    = 'Expected assignment not found at RG scope'
                }
            }
            else {
                $details = 'RG not found'
            }

            # ------------------------------------------------------------------
            # Collect result row
            # ------------------------------------------------------------------
            $result += [pscustomobject]@{
                SubscriptionName      = $sub.Name
                SubscriptionId        = $sub.Id
                Environment           = $adh_subscription_type

                # This is the effective custodian used for this expansion
                Custodian             = $custodian

                InputResourceGroup    = $row.resource_group_name
                ScannedResourceGroup  = $rgName

                RoleDefinition        = $role
                InputAdGroup          = $row.ad_group_name
                ResolvedAdGroup       = $aadGrp

                RGStatus              = $rgStatus
                PermissionStatus      = $permStatus
                Details               = $details
            }
        }
    }
}

# --------------------------------------------------------------------
# Export CSV + HTML
# --------------------------------------------------------------------
$csvOut = New-StampedPath -BaseDir $OutputDir -Prefix ("rg_permissions_{0}_{1}" -f $adh_group, $adh_subscription_type) -Ext 'csv'
Write-CsvSafe -Rows $result -Path $csvOut

$htmlOut = [System.IO.Path]::ChangeExtension($csvOut, 'html')
Convert-CsvToHtml -CsvPath $csvOut -HtmlPath $htmlOut -Title "RG Permissions ($adh_group / $adh_subscription_type) $BranchName"

Write-Host "RG permissions scan completed." -ForegroundColor Green
Write-Host "CSV : $csvOut"
Write-Host "HTML: $htmlOut"
