param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$ClientId,
    [Parameter(Mandatory)][string]$ClientSecret,
    [string]$ProdCsvPath,
    [string]$NonProdCsvPath,
    [string]$adh_group,
    [ValidateSet('nonprd','prd')][string]$adh_subscription_type = 'nonprd',
    [Parameter(Mandatory)][string]$OutputDir,
    [string]$BranchName = ''
)

Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force
Ensure-Dir -Path $OutputDir
Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret

$csvPath = if ($adh_subscription_type -eq 'prd') { $ProdCsvPath } else { $NonProdCsvPath }

# Check that the CSV file actually exists and has real data rows
if (-not (Test-Path -LiteralPath $csvPath)) {
    throw "CSV not found: $csvPath. Please provide a populated input file with columns resource_group_name,role_definition_name,ad_group_name"
}

# Optional: Log what we found in the CSV file
Write-Host "Reading input CSV: $csvPath"
Get-Content $csvPath | Write-Host

$inputRows = Import-Csv -Path $csvPath
if ($inputRows.Count -eq 0) {
    throw "Input CSV [$csvPath] is empty. Please provide at least one data row."
}

$custodian = $adh_group
$result = @()

$subs = Get-ScSubscriptions -AdhGroup $custodian -Environment $adh_subscription_type

foreach ($sub in $subs) {
    Set-AzContext -SubscriptionId $sub.Id | Out-Null

    foreach ($row in $inputRows) {
        # Replace <Custodian> token in each field
        $rgName         = $row.resource_group_name -replace '<Custodian>', $custodian
        $role           = $row.role_definition_name
        $inputAdGroup   = $row.ad_group_name
        $resolvedAdGroup= $inputAdGroup -replace '<Custodian>', $custodian

        $rg = Get-AzResourceGroup -Name $rgName -ErrorAction SilentlyContinue
        $rgStatus = if ($rg) { 'EXISTS' } else { 'NOT_FOUND' }
        $permStatus = 'N/A'
        if ($rg) {
            $scope = "/subscriptions/{0}/resourceGroups/{1}" -f $sub.Id, $rgName
            $assign = Get-AzRoleAssignment -Scope $scope -ErrorAction SilentlyContinue | Where-Object {
                $_.RoleDefinitionName -eq $role -and $_.DisplayName -eq $resolvedAdGroup
            }
            $permStatus = if ($assign) { 'EXISTS' } else { 'MISSING' }
        }

        $result += [pscustomobject]@{
            SubscriptionName      = $sub.Name
            SubscriptionId        = $sub.Id
            Environment           = $adh_subscription_type
            InputResourceGroup    = $row.resource_group_name       # Still with <Custodian> for traceability
            ScannedResourceGroup  = $rgName                        # Actual evaluated name
            RoleDefinition        = $role
            InputAdGroup          = $row.ad_group_name
            ResolvedAdGroup       = $resolvedAdGroup
            RGStatus              = $rgStatus
            PermissionStatus      = $permStatus
            Details               = if ($rg) { '' } else { 'RG not found' }
        }
    }
}

$csvOut = New-StampedPath -BaseDir $OutputDir -Prefix "rg_permissions_${custodian}_${adh_subscription_type}" -Ext 'csv'
Write-CsvSafe -Rows $result -Path $csvOut
$htmlOut = [System.IO.Path]::ChangeExtension($csvOut, '.html')
Convert-CsvToHtml -CsvPath $csvOut -HtmlPath $htmlOut -Title "RG Permissions ($custodian / $adh_subscription_type) $BranchName"
