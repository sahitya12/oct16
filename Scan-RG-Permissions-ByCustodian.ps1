<# Inventory: dump every RG's role assignments for the selected subscriptions #>
param(
  [Parameter(Mandatory)][string]$TenantId,
  [Parameter(Mandatory)][string]$ClientId,
  [Parameter(Mandatory)][string]$ClientSecret,
  [Parameter(Mandatory)][string]$adh_group,
  [ValidateSet('nonprd','prd')][string]$adh_subscription_type = 'nonprd',
  [Parameter(Mandatory)][string]$OutputDir,
  [string]$BranchName = ''
)

Import-Module Az.Accounts, Az.Resources -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret

$subs = @(Resolve-AdhSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type)
if (-not $subs) { throw "No matching subscriptions for $adh_group / $adh_subscription_type" }

Ensure-Dir -Path $OutputDir
$csvFile = New-StampedPath -BaseDir $OutputDir -Prefix "rg_permissions_${adh_group}_$adh_subscription_type"
$htmlFile = [IO.Path]::ChangeExtension($csvFile, '.html')

$rows = @()
foreach ($sub in $subs) {
  Set-AzContext -SubscriptionId $sub.Id | Out-Null
  foreach ($rg in Get-AzResourceGroup) {
    $assignments = Get-AzRoleAssignment -Scope $rg.ResourceId -ErrorAction SilentlyContinue
    foreach ($a in $assignments) {
      $rows += [pscustomobject]@{
        SubscriptionName = $sub.Name
        SubscriptionId   = $sub.Id
        Environment      = $adh_subscription_type
        ResourceGroup    = $rg.ResourceGroupName
        RoleDefinition   = $a.RoleDefinitionName
        PrincipalName    = $a.DisplayName
        PrincipalType    = $a.ObjectType
        Custodian        = $adh_group
      }
    }
  }
}

Write-CsvSafe -Rows $rows -Path $csvFile
Convert-CsvToHtml -CsvPath $csvFile -HtmlPath $htmlFile -Title "RG Role Assignments – $adh_group ($adh_subscription_type) $BranchName"
Write-Host "CSV: $csvFile"
Write-Host "HTML: $htmlFile"
