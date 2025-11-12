Import-Module Az.Accounts, Az.Resources -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

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

# --- Setup and Connect ---
Ensure-Dir -Path $OutputDir | Out-Null
$csvPath = if ($adh_subscription_type -eq 'prd') { $ProdCsvPath } else { $NonProdCsvPath }
if (-not (Test-Path -LiteralPath $csvPath)) {
    throw "CSV not found: $csvPath"
}

$inputRows = Import-Csv -Path $csvPath
Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret

$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
$results = @()

foreach ($sub in $subs) {
    Write-Host "Scanning Subscription: $($sub.Name)"
    Set-ScContext -Subscription $sub

    foreach ($row in $inputRows) {
        $rgName = $row.resource_group_name -replace '<Custodian>', $adh_group
        $role   = $row.role_definition_name
        $aadGrp = $row.ad_group_name -replace '<Custodian>', $adh_group

        try {
            $rg = Get-AzResourceGroup -Name $rgName -ErrorAction Stop
            $assignments = Get-AzRoleAssignment -ResourceGroupName $rgName -ErrorAction SilentlyContinue

            $hasPerm = $assignments | Where-Object {
                $_.RoleDefinitionName -eq $role -and $_.DisplayName -eq $aadGrp
            }

            $results += [pscustomobject]@{
                SubscriptionName = $sub.Name
                SubscriptionId   = $sub.Id
                ResourceGroup    = $rgName
                RoleDefinition   = $role
                AdGroup          = $aadGrp
                Exists           = if ($rg) { 'Yes' } else { 'No' }
                PermissionStatus = if ($hasPerm) { 'Present' } else { 'Missing' }
                Location         = $rg.Location
            }
        }
        catch {
            $results += [pscustomobject]@{
                SubscriptionName = $sub.Name
                SubscriptionId   = $sub.Id
                ResourceGroup    = $rgName
                RoleDefinition   = $role
                AdGroup          = $aadGrp
                Exists           = 'No'
                PermissionStatus = 'Error'
                Location         = ''
            }
        }
    }
}

# --- Output ---
$csvOut = New-StampedPath -BaseDir $OutputDir -Prefix ("rg_permissions_{0}_{1}" -f $adh_group,$adh_subscription_type)
Write-CsvSafe -Rows $results -Path $csvOut
Convert-CsvToHtml -CsvPath $csvOut -HtmlPath ($csvOut -replace '\.csv$','.html') -Title "RG Permissions ($adh_group / $adh_subscription_type) $BranchName"
Write-Host "✅ Output saved to $csvOut"
