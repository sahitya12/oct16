param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$ClientId,
    [Parameter(Mandatory)][string]$ClientSecret,

    [Parameter(Mandatory)][string]$adh_group,
    [string]$adh_sub_group = '',

    [ValidateSet('nonprd','prd')]
    [string]$adh_subscription_type = 'nonprd',

    [Parameter(Mandatory)][string]$ProdCsvPath,
    [Parameter(Mandatory)][string]$NonProdCsvPath,

    [Parameter(Mandatory)][string]$OutputDir,
    [string]$BranchName = ''
)

Import-Module Az.Accounts, Az.Resources -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

Ensure-Dir -Path $OutputDir | Out-Null

#=============================
# Choose CSV by environment
#=============================
$csvPath = if ($adh_subscription_type -eq 'prd') { 
    $ProdCsvPath 
} else { 
    $NonProdCsvPath 
}

if (-not (Test-Path -LiteralPath $csvPath)) {
    throw "CSV not found: $csvPath"
}

$inputRows = Import-Csv -Path $csvPath

#=============================
# Connect to Azure
#=============================
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure connection failed."
}

#=============================
# Build custodian list
#=============================
$Custodians = @()

# Always include base custodian
$Custodians += $adh_group

# Include subgroup custodian if passed
if ($adh_sub_group -and $adh_sub_group.Trim() -ne "") {
    $Custodians += "${adh_group}_${adh_sub_group}"
}

Write-Host "Scanning custodians: $($Custodians -join ', ')"

#=============================
# Fetch subscriptions
#=============================
$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type

$result = @()

foreach ($sub in $subs) {
    Set-ScContext -Subscription $sub

    foreach ($row in $inputRows) {

        foreach ($cust in $Custodians) {

            $rgName = $row.resource_group_name -replace '<Custodian>', $cust
            $role   = $row.role_definition_name
            $aadGrp = $row.ad_group_name -replace '<Custodian>', $cust

            if ([string]::IsNullOrWhiteSpace($rgName)) { continue }

            $rg = Get-AzResourceGroup -Name $rgName -ErrorAction SilentlyContinue
            $rgStatus = if ($rg) { 'EXISTS' } else { 'NOT_FOUND' }

            $permStatus = 'N/A'
            $details = ''

            if ($rg) {
                $scope = "/subscriptions/{0}/resourceGroups/{1}" -f $sub.Id, $rgName
                $assign = Get-AzRoleAssignment -Scope $scope -ErrorAction SilentlyContinue |
                    Where-Object { $_.RoleDefinitionName -eq $role -and $_.DisplayName -eq $aadGrp }

                $permStatus = if ($assign) { 'EXISTS' } else { 'MISSING' }
                if (-not $assign) { $details = "Expected assignment missing" }
            }
            else {
                $details = "RG not found"
            }

            $result += [pscustomobject]@{
                SubscriptionName     = $sub.Name
                SubscriptionId       = $sub.Id
                Environment          = $adh_subscription_type
                Custodian            = $cust
                InputResourceGroup   = $row.resource_group_name
                ScannedResourceGroup = $rgName
                RoleDefinition       = $role
                InputAdGroup         = $row.ad_group_name
                ResolvedAdGroup      = $aadGrp
                RGStatus             = $rgStatus
                PermissionStatus     = $permStatus
                Details              = $details
            }
        }
    }
}

#=============================
# Output CSV & HTML
#=============================
$csvOut = New-StampedPath -BaseDir $OutputDir -Prefix ("rg_permissions_{0}_{1}" -f $adh_group, $adh_subscription_type)
Write-CsvSafe -Rows $result -Path $csvOut

$htmlOut = $csvOut -replace '\.csv$','.html'
Convert-CsvToHtml -CsvPath $csvOut -HtmlPath $htmlOut -Title "RG Permissions Scan ($adh_group / $adh_subscription_type)"

Write-Host "RG permission scan completed successfully."
Write-Host "CSV : $csvOut"
Write-Host "HTML: $htmlOut"
