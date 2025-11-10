function Connect-ScAz {
  param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$ClientId,
    [Parameter(Mandatory)][string]$ClientSecret
  )
  $sec = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
  $cred = New-Object System.Management.Automation.PSCredential ($ClientId, $sec)
  Connect-AzAccount -ServicePrincipal -Tenant $TenantId -Credential $cred -ErrorAction Stop | Out-Null
}

function Ensure-Dir { param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path | Out-Null }
}

function New-StampedPath { param([string]$BaseDir,[string]$Prefix)
  Ensure-Dir -Path $BaseDir
  $stamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
  Join-Path $BaseDir "$Prefix`_$stamp.csv"
}

function Write-CsvSafe { param([object[]]$Rows,[string]$Path)
  $Rows | Export-Csv -NoTypeInformation -LiteralPath $Path -Encoding UTF8
}

function Convert-CsvToHtml { param([string]$CsvPath,[string]$HtmlPath,[string]$Title)
  $rows = Import-Csv -LiteralPath $CsvPath
  $html = $rows | ConvertTo-Html -Title $Title -PreContent "<h2>$Title</h2>"
  $html | Set-Content -LiteralPath $HtmlPath -Encoding UTF8
}

function Resolve-AdhSubscriptions {
  param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z]{2,}$')][string]$AdhGroup,
    [ValidateSet('nonprd','prd')][string]$Environment = 'nonprd'
  )
  $g = $AdhGroup.Trim().ToUpperInvariant()
  $envPrefix = if ($Environment -eq 'prd') { 'prd_azure_' } else { 'dev_azure_' }
  $specialMap = @{ 'KTK' = 'ADHPlatform' }
  $variants = [System.Collections.Generic.List[string]]::new()
  if ($specialMap.ContainsKey($g)) { $variants.Add($specialMap[$g]) }
  else {
    $first = $g.Substring(0,1)
    $variants.Add("ADH$g")
    $variants.Add("ADH$first$g")  # legacy
  }
  $subs = Get-AzSubscription
  foreach ($v in $variants) {
    $pattern = "$envPrefix*_*$v"
    $match = $subs | Where-Object { $_.Name -like $pattern } | Sort-Object Name | Select-Object -First 1
    if ($match) { return ,$match }
  }
  throw "No matching subscription for $g ($Environment)."
}

Export-ModuleMember -Function `
  Connect-ScAz, Ensure-Dir, New-StampedPath, Write-CsvSafe, Convert-CsvToHtml, Resolve-AdhSubscriptions
