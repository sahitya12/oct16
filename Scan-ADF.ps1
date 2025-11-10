param(
  [Parameter(Mandatory)][string]$TenantId,
  [Parameter(Mandatory)][string]$ClientId,
  [Parameter(Mandatory)][string]$ClientSecret,
  [Parameter(Mandatory)][string]$adh_group,
  [ValidateSet('nonprd','prd')][string]$adh_subscription_type = 'nonprd',
  [Parameter(Mandatory)][string]$OutputDir,
  [string]$BranchName = ''
)

# ----- helpers / modules -----
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force
Ensure-Dir -Path $OutputDir

# Make sure Az.DataFactory is available
if (-not (Get-Module -ListAvailable Az.DataFactory)) {
  try { Install-Module Az.DataFactory -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop } catch {}
}
Import-Module Az.DataFactory -ErrorAction SilentlyContinue | Out-Null

# Simple masker for secrets inside JSON-ish type properties
function Mask-SecretJson([string]$json) {
  if ([string]::IsNullOrWhiteSpace($json)) { return '' }
  $masked = $json

  # mask common secret-ish fields
  $patterns = @(
    '"(password|passwd|secret|token|key|accountKey|sharedKey|clientSecret|sasToken|connectionString)"\s*:\s*"[^"]*"',
    '"(authorization|authorizationKey|encryptedCredential)"\s*:\s*"[^"]*"'
  )
  foreach ($p in $patterns) {
    $masked = [System.Text.RegularExpressions.Regex]::Replace($masked, $p, {'"'+$args[0].Groups[1].Value+'":"***"'}, 'IgnoreCase')
  }
  return $masked
}

# ----- auth -----
Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret

$custodian = $adh_group
$env = $adh_subscription_type

$overview = @()
$linkedRows = @()

# subscriptions for this custodian/env (your tolerant filter lives in Common.psm1)
$subs = Get-ScSubscriptions -AdhGroup $custodian -Environment $env

foreach ($sub in $subs) {
  Set-AzContext -SubscriptionId $sub.Id | Out-Null

  # list ADF factories by resource type, then filter by custodian token
  $adfResources = Get-AzResource -ResourceType "Microsoft.DataFactory/factories" -ErrorAction SilentlyContinue |
                  Where-Object { $_.Name -match $custodian }

  foreach ($res in $adfResources) {
    $rg   = $res.ResourceGroupName
    $name = $res.Name
    $loc  = $res.Location

    # collect inventories
    $pipelines    = @( Get-AzDataFactoryV2Pipeline       -ResourceGroupName $rg -DataFactoryName $name -ErrorAction SilentlyContinue )
    $linkedSvcs   = @( Get-AzDataFactoryV2LinkedService  -ResourceGroupName $rg -DataFactoryName $name -ErrorAction SilentlyContinue )
    $triggers     = @( Get-AzDataFactoryV2Trigger        -ResourceGroupName $rg -DataFactoryName $name -ErrorAction SilentlyContinue )
    $datasets     = @( Get-AzDataFactoryV2Dataset        -ResourceGroupName $rg -DataFactoryName $name -ErrorAction SilentlyContinue )

    # ----- overview row -----
    $overview += [pscustomobject]@{
      SubscriptionName       = $sub.Name
      SubscriptionId         = $sub.Id
      Environment            = $env
      ADF_Name               = $name
      ResourceGroup          = $rg
      Location               = $loc
      Pipelines_Count        = $pipelines.Count
      LinkedServices_Count   = $linkedSvcs.Count
      Datasets_Count         = $datasets.Count
      Triggers_Count         = $triggers.Count
      Pipelines_List         = ($pipelines.Name -join ', ')
      LinkedServices_List    = ($linkedSvcs.Name -join ', ')
      Triggers_List          = ($triggers.Name -join ', ')
      Branch                 = $BranchName
      AsOfUtc                = (Get-Date).ToUniversalTime().ToString('u')
    }

    # ----- per-linked-service rows -----
    foreach ($ls in $linkedSvcs) {
      $lsType = $ls.Properties.Type
      # properties can be complex (secureStrings, expressions) – convert to JSON then mask
      $rawProps = ($ls.Properties.TypeProperties | ConvertTo-Json -Depth 12 -Compress)
      $masked   = Mask-SecretJson $rawProps

      # try to surface IR name if present under connectVia / referenceName
      $ir = $null
      try {
        $ir = $ls.Properties.ConnectVia.ReferenceName
      } catch {}

      $linkedRows += [pscustomobject]@{
        SubscriptionName  = $sub.Name
        SubscriptionId    = $sub.Id
        Environment       = $env
        ADF_Name          = $name
        ResourceGroup     = $rg
        LinkedService     = $ls.Name
        LinkedServiceType = $lsType
        IntegrationRuntime= $ir
        ConnectionSummary = $masked
        Branch            = $BranchName
        AsOfUtc           = (Get-Date).ToUniversalTime().ToString('u')
      }
    }
  }
}

# ----- write artifacts -----
# overview
$csvOverview = New-StampedPath -BaseDir $OutputDir -Prefix "adf_overview_${custodian}_${env}" -Ext 'csv'
Write-CsvSafe -Rows $overview -Path $csvOverview
$htmlOverview = [System.IO.Path]::ChangeExtension($csvOverview, '.html')
Convert-CsvToHtml -CsvPath $csvOverview -HtmlPath $htmlOverview -Title "ADF Overview ($custodian / $env) $BranchName"

# linked services (detailed)
$csvLinked = New-StampedPath -BaseDir $OutputDir -Prefix "adf_linkedservices_${custodian}_${env}" -Ext 'csv'
Write-CsvSafe -Rows $linkedRows -Path $csvLinked
$htmlLinked = [System.IO.Path]::ChangeExtension($csvLinked, '.html')
Convert-CsvToHtml -CsvPath $csvLinked -HtmlPath $htmlLinked -Title "ADF Linked Services ($custodian / $env) $BranchName"

Write-Host "ADF overview  : $csvOverview"
Write-Host "ADF linked svc: $csvLinked"
