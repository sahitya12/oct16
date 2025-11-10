<#
.SYNOPSIS
    Scans Resource Group role assignments for a given ADH custodian and environment
.DESCRIPTION
    - Connects to Azure via service principal
    - Enumerates subscriptions belonging to the specified ADH group and environment (nonprd/prd)
    - Lists each RG and its role assignments
    - Saves results to timestamped CSV/HTML in OutputDir
#>

param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$ClientId,
    [Parameter(Mandatory)][string]$ClientSecret,

    [string]$ProdCsvPath,
    [string]$NonProdCsvPath,

    [Parameter(Mandatory)][string]$adh_group,

    [ValidateSet('nonprd','prd')]
    [string]$adh_subscription_type = 'nonprd',

    [Parameter(Mandatory)][string]$OutputDir,
    [string]$BranchName = ''
)

Write-Host "Starting: Run sanitychecks/scripts/Scan-RG-Permissions-ByCustodian.ps1" -ForegroundColor Cyan
Write-Host "============================================================"

# --- Import required modules
Import-Module Az.Accounts, Az.Resources -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

# --- Connect to Azure ---
Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
Write-Host "Connected to Azure tenant: $TenantId" -ForegroundColor Green

# --- Determine subscriptions for the ADH group and environment ---
$subs = Get-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
if (-not $subs -or $subs.Count -eq 0) {
    throw "No matching subscriptions found for adh_group='$adh_group' environment='$adh_subscription_type'."
}

Write-Host "Found $($subs.Count) subscription(s) for $adh_group ($adh_subscription_type)" -ForegroundColor Yellow

# --- Prepare output paths ---
Ensure-Dir -Path $OutputDir
$csvFile = New-StampedPath -BaseDir $OutputDir -Prefix "rg_permissions_${adh_group}_$adh_subscription_type"
$htmlFile = $csvFile -replace '\.csv$', '.html'

$allResults = @()

foreach ($sub in $subs) {
    Write-Host "Processing subscription: $($sub.Name)" -ForegroundColor Cyan
    try {
        Set-AzContext -SubscriptionId $sub.Id -ErrorAction Stop | Out-Null
        $rgs = Get-AzResourceGroup

        foreach ($rg in $rgs) {
            $roles = Get-AzRoleAssignment -Scope $rg.ResourceId -ErrorAction SilentlyContinue
            foreach ($role in $roles) {
                $allResults += [PSCustomObject]@{
                    SubscriptionName = $sub.Name
                    SubscriptionId   = $sub.Id
                    Environment      = $adh_subscription_type
                    ResourceGroup    = $rg.ResourceGroupName
                    RoleDefinition   = $role.RoleDefinitionName
                    PrincipalName    = $role.DisplayName
                    PrincipalType    = $role.ObjectType
                    Custodian        = $adh_group
                }
            }
        }
    }
    catch {
        Write-Warning "Error scanning subscription $($sub.Name): $_"
    }
}

# --- Write output ---
Write-CsvSafe -Rows $allResults -Path $csvFile
Convert-CsvToHtml -CsvPath $csvFile -HtmlPath $htmlFile -Title "RG Permissions - $adh_group ($adh_subscription_type)"

Write-Host "Output CSV:  $csvFile"
Write-Host "Output HTML: $htmlFile"
Write-Host "Completed RG Permission Scan for $adh_group ($adh_subscription_type)" -ForegroundColor Green
Write-Host "============================================================"
