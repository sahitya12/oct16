function Ensure-Dir {
  param([Parameter(Mandatory)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
  }
  Get-Item -LiteralPath $Path
}

function New-StampedPath {
  param(
    [Parameter(Mandatory)][string]$BaseDir,
    [Parameter(Mandatory)][string]$Prefix,
    [string]$Ext = 'csv'
  )
  Ensure-Dir -Path $BaseDir | Out-Null
  $stamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
  Join-Path $BaseDir ("{0}_{1}.{2}" -f $Prefix,$stamp,$Ext)
}

function Write-CsvSafe {
  param(
    [Parameter(Mandatory)][object[]]$Rows,
    [Parameter(Mandatory)][string]$Path
  )
  $Rows | Export-Csv -Path $Path -NoTypeInformation -Force -Encoding UTF8
  $Path
}

function Convert-CsvToHtml {
  param(
    [Parameter(Mandatory)][string]$CsvPath,
    [Parameter(Mandatory)][string]$HtmlPath,
    [string]$Title = 'Report'
  )
  $dt = Import-Csv $CsvPath
  $html = @"
<html>
<head><meta charset="utf-8"><title>$Title</title>
<style>body{font-family:Segoe UI,Arial;} table{border-collapse:collapse} th,td{border:1px solid #ddd;padding:6px}</style>
</head>
<body><h2>$Title</h2>
$($dt | ConvertTo-Html -Fragment)
</body></html>
"@
  $html | Set-Content -Path $HtmlPath -Encoding UTF8
}

# ---- Azure helpers (thin wrappers you already use in your ADF scan) ----
function Connect-ScAz {
  param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$ClientId,
    [Parameter(Mandatory)][string]$ClientSecret
  )
  $sec = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
  $creds = New-Object System.Management.Automation.PSCredential($ClientId,$sec)
  Connect-AzAccount -ServicePrincipal -Tenant $TenantId -Credential $creds | Out-Null
  $true
}

function Get-ScSubscriptions {
  param(
    [Parameter(Mandatory)][string]$AdhGroup,
    [Parameter(Mandatory)][ValidateSet('nonprd','prd')][string]$Environment
  )
  # Replace with your real resolver. For now, use all accessible subs filtered by naming convention.
  (Get-AzSubscription | Where-Object { $_.Name -match "^$AdhGroup.*$Environment" })
}

function Set-ScContext {
  param([Parameter(Mandatory)]$Subscription)
  Set-AzContext -SubscriptionId $Subscription.Id | Out-Null
}
Export-ModuleMember -Function *-*
