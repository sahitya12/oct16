param(
  [Parameter(Mandatory)][string]$TenantId,
  [Parameter(Mandatory)][string]$ClientId,
  [Parameter(Mandatory)][string]$ClientSecret,
  [Parameter(Mandatory)][string]$adh_group,
  [ValidateSet('nonprd','prd')][string]$adh_subscription_type = 'nonprd',
  [Parameter(Mandatory)][string]$OutputDir,
  [string]$BranchName = ''
)

Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force
Ensure-Dir $OutputDir
Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret

$overview = @()
$lsRows   = @()
$irRows   = @()

$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
foreach ($sub in $subs) {
  Set-ScContext -Subscription $sub

  # All ADFs in subscription
  $dfs = Get-AzDataFactoryV2 -ErrorAction SilentlyContinue
  foreach ($df in $dfs) {
    $overview += [pscustomobject]@{
      SubscriptionName    = $sub.Name
      SubscriptionId      = $sub.Id
      ResourceGroup       = $df.ResourceGroupName
      DataFactory         = $df.Name
      Exists              = 'Yes'
      Location            = $df.Location
    }

    # Linked Services
    $ls = Get-AzDataFactoryV2LinkedService -ResourceGroupName $df.ResourceGroupName -DataFactoryName $df.Name -ErrorAction SilentlyContinue
    foreach ($l in $ls) {
      $lsRows += [pscustomobject]@{
        SubscriptionName = $sub.Name
        ResourceGroup    = $df.ResourceGroupName
        DataFactory      = $df.Name
        LinkedService    = $l.Name
        Type             = $l.Properties.Type
      }
    }

    # Integration Runtimes
    $irs = Get-AzDataFactoryV2IntegrationRuntime -ResourceGroupName $df.ResourceGroupName -DataFactoryName $df.Name -ErrorAction SilentlyContinue
    foreach ($ir in $irs) {
      $irRows += [pscustomobject]@{
        SubscriptionName = $sub.Name
        ResourceGroup    = $df.ResourceGroupName
        DataFactory      = $df.Name
        IRName           = $ir.Name
        IRType           = $ir.Properties.Type
        ComputeDesc      = ($ir.Properties.AdditionalProperties.ClusterSize ?? $ir.Properties.Description)
        State            = $ir.Properties.State
      }
    }
  }
}

# If no ADF in subscription, keep a “No” row so you still see coverage
if (-not $overview) {
  foreach ($sub in $subs) {
    $overview += [pscustomobject]@{
      SubscriptionName = $sub.Name
      SubscriptionId   = $sub.Id
      ResourceGroup    = ''
      DataFactory      = ''
      Exists           = 'No'
      Location         = ''
    }
  }
}

$csv1 = New-StampedPath -BaseDir $OutputDir -Prefix "adf_overview_${adh_group}_${adh_subscription_type}"
Write-CsvSafe -Rows $overview -Path $csv1
Convert-CsvToHtml -CsvPath $csv1 -HtmlPath ($csv1 -replace '\.csv$','.html') -Title "ADF Overview ($adh_group / $adh_subscription_type) $BranchName"

$csv2 = New-StampedPath -BaseDir $OutputDir -Prefix "adf_linkedservices_${adh_group}_${adh_subscription_type}"
Write-CsvSafe -Rows $lsRows -Path $csv2

$csv3 = New-StampedPath -BaseDir $OutputDir -Prefix "adf_integrationruntimes_${adh_group}_${adh_subscription_type}"
Write-CsvSafe -Rows $irRows -Path $csv3
