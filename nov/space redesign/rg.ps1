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

# =============================================================
# NORMALIZE adh_sub_group  (handle single space from pipeline)
# =============================================================
$adh_sub_group = $adh_sub_group.Trim()
if ([string]::IsNullOrWhiteSpace($adh_sub_group)) {
    $adh_sub_group = ""
}

Write-Host "Normalized adh_sub_group = '$adh_sub_group'"

# =============================================================
# CHOOSE CSV BASED ON ENVIRONMENT
# =============================================================
$csvPath = if ($adh_subscription_type -eq 'prd') { 
    $ProdCsvPath 
} else { 
    $NonProdCsvPath 
}

if (-not (Test-Path -LiteralPath $csvPath)) {
    throw "CSV not found: $csvPath"
}

$inputRows = Import-Csv -LiteralPath $csvPath

# =============================================================
# CONNECT TO AZURE
# =============================================================
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure connection failed."
}

# =============================================================
# BUILD EXACT CUSTODIAN FOR SCAN
# =============================================================
if ($adh_sub_group -eq "") {
    # Example: KTK → scan KTK only
    $Custodian = $adh_group
}
else {
    # Example: adh_group = OPX, adh_sub_group = ABC
    # Custodian = OPX_ABC
    $Custodian = "${adh_group}_${adh_sub_group}"
}

Write-Host "Scanning ONLY custodian: $Custodian"

# Pattern for RG name check
$pattern = "*$Custodian*"
Write-Host "RG search pattern = $pattern"

# =============================================================
# SUBSCRIPTIONS
# =============================================================
$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
if ($subs -isnot [System.Collections.IEnumerable]) { $subs = ,$subs }

$result = @()

foreach ($sub in $subs) {

    Set-ScContext -Subscription $sub

    foreach ($row in $inputRows) {

        $resolvedRg    = $row.resource_group_name -replace '<Custodian>', $Custodian
        $resolvedAdGrp = $row.ad_group_name      -replace '<Custodian>', $Custodian
        $role          = $row.role_definition_name

        # Skip if RG after replacement does not match the custodian pattern
        if ($resolvedRg -notlike $pattern) { continue }

        $rg = Get-AzResourceGroup -Name $resolvedRg -ErrorAction SilentlyContinue
        $rgStatus = if ($rg) { 'EXISTS' } else { 'NOT_FOUND' }

        $permStatus = 'N/A'
        $details    = ''

        if ($rg) {
            $scope = "/subscriptions/{0}/resourceGroups/{1}" -f $sub.Id, $resolvedRg

            $assign = Get-AzRoleAssignment -Scope $scope -ErrorAction SilentlyContinue |
                      Where-Object { $_.RoleDefinitionName -eq $role -and $_.DisplayName -eq $resolvedAdGrp }

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

            Custodian            = $Custodian
            InputResourceGroup   = $row.resource_group_name
            ScannedResourceGroup = $resolvedRg

            RoleDefinition       = $role
            InputAdGroup         = $row.ad_group_name
            ResolvedAdGroup      = $resolvedAdGrp

            RGStatus             = $rgStatus
            PermissionStatus     = $permStatus
            Details              = $details
        }
    }
}

# =============================================================
# OUTPUT CSV & HTML – use adh_group / adh_group_adh_sub_group
# =============================================================
$groupForFile = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) {
    $adh_group
} else {
    "${adh_group}_${adh_sub_group}"
}

$csvOut = New-StampedPath -BaseDir $OutputDir -Prefix ("rg_permissions_{0}_{1}" -f $groupForFile, $adh_subscription_type)
Write-CsvSafe -Rows $result -Path $csvOut

$htmlOut = $csvOut -replace '\.csv$','.html'
Convert-CsvToHtml -CsvPath $csvOut -HtmlPath $htmlOut -Title "RG Permission Scan - $groupForFile"

Write-Host "RG permission scan completed successfully."
Write-Host "CSV : $csvOut"
Write-Host "HTML: $htmlOut"
