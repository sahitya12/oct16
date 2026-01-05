[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$TenantId,
  [Parameter(Mandatory)][string]$ClientId,
  [Parameter(Mandatory)][string]$ClientSecret,

  [Parameter(Mandatory)][string]$SubscriptionsCsvPath,

  # SAME inputs for all (as you requested)
  [Parameter(Mandatory)][string]$RgPermsNonPrdCsvPath,
  [Parameter(Mandatory)][string]$RgPermsPrdCsvPath,
  [Parameter(Mandatory)][string]$AdlsInputCsvPath,

  [Parameter(Mandatory)][string]$OutputRootDir,

  # Run toggles
  [bool]$RunRgPermissions = $true,
  [bool]$RunRgTags        = $true,
  [bool]$RunKvSecrets     = $true,
  [bool]$RunKvPermissions = $true,
  [bool]$RunKvFirewall    = $true,
  [bool]$RunVnet          = $true,
  [bool]$RunAdls          = $true,
  [bool]$RunAdf           = $true,
  [bool]$RunDatabricks    = $true,

  [string]$BranchName = ''
)

$ErrorActionPreference = 'Stop'

function Ensure-Dir([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
  (Get-Item -LiteralPath $Path).FullName
}

function Safe-Run([string]$Name, [scriptblock]$Action) {
  Write-Host ""
  Write-Host "==================== $Name ====================" -ForegroundColor Cyan
  try {
    & $Action
    Write-Host "✅ $Name : OK" -ForegroundColor Green
  } catch {
    Write-Host "❌ $Name : FAILED" -ForegroundColor Red
    Write-Host $_.Exception.Message
  }
}

# ----------------- Paths (reuse existing scripts) -----------------
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

$scanRgPerms   = Join-Path $repoRoot 'sanitychecks\scripts\Scan-RG-Permissions-ByCustodian.ps1'
$scanRgTags    = Join-Path $repoRoot 'sanitychecks\scripts\Scan-RG-Tags.ps1'
$scanKvSecrets = Join-Path $repoRoot 'sanitychecks\scripts\Scan-KV-Secrets.ps1'
$scanKvPerms   = Join-Path $repoRoot 'sanitychecks\scripts\Scan-KV-Permissions-1.ps1'
$scanKvFw      = Join-Path $repoRoot 'sanitychecks\scripts\Scan-KV-Networks-1.ps1'
$scanAdls      = Join-Path $repoRoot 'sanitychecks\scripts\Scan-ADLS-Acls.ps1'
$scanAdf       = Join-Path $repoRoot 'sanitychecks\scripts\Scan-DataFactory.ps1'
$scanDbx       = Join-Path $repoRoot 'sanitychecks\scripts\Scan-Databricks.ps1'

# New VNet scan we add
$scanVnet      = Join-Path $repoRoot 'sanitychecks\scripts\Scan-VNet-Monthly.ps1'

# ----------------- Validations -----------------
foreach ($p in @(
  $SubscriptionsCsvPath,
  $RgPermsNonPrdCsvPath, $RgPermsPrdCsvPath,
  $AdlsInputCsvPath,
  $scanRgPerms, $scanRgTags, $scanKvSecrets, $scanKvPerms, $scanKvFw,
  $scanAdls, $scanAdf, $scanDbx, $scanVnet
)) {
  if (-not (Test-Path -LiteralPath $p)) { throw "Required file not found: $p" }
}

$stamp = Get-Date -Format 'yyyyMMdd'
$outRoot = Ensure-Dir (Join-Path $OutputRootDir ("monthly_allsubs_{0}" -f $stamp))

# ----------------- Loop custodians -----------------
$rows = Import-Csv -LiteralPath $SubscriptionsCsvPath
if (-not $rows -or $rows.Count -eq 0) { throw "No rows found in SubscriptionsCsvPath: $SubscriptionsCsvPath" }

Write-Host "Monthly ALL-SUBS run starting..."
Write-Host "OutputRoot = $outRoot"
Write-Host "BranchName = $BranchName"

foreach ($r in $rows) {
  $adh_group = ("$($r.adh_group)").Trim()
  $adh_sub_group = ("$($r.adh_sub_group)").Trim()
  $env = ("$($r.adh_subscription_type)").Trim().ToLower()
  $subIdExpected = ("$($r.subscription_id)").Trim()

  if ([string]::IsNullOrWhiteSpace($adh_group) -or [string]::IsNullOrWhiteSpace($env)) {
    Write-Host "Skipping row (missing adh_group or adh_subscription_type): $($r | ConvertTo-Json -Compress)"
    continue
  }
  if ($env -notin @('nonprd','prd')) {
    Write-Host "Skipping row (invalid env '$env'): $($r | ConvertTo-Json -Compress)"
    continue
  }

  $groupForFolder = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) { $adh_group } else { "${adh_group}_${adh_sub_group}" }
  $subOut = Ensure-Dir (Join-Path $outRoot ("{0}_{1}" -f $groupForFolder, $env))

  Write-Host ""
  Write-Host "############################################################"
  Write-Host "# CUSTODIAN: $groupForFolder | ENV: $env"
  Write-Host "############################################################"

  # Optional validation: show what Resolve-ScSubscriptions would pick (based on your Common.psm1)
  # We don't block execution if mismatch; we just warn.
  Safe-Run "Subscription resolution check ($groupForFolder/$env)" {
    Import-Module Az.Accounts -ErrorAction Stop
    $sec  = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential($ClientId, $sec)
    Connect-AzAccount -ServicePrincipal -Tenant $TenantId -Credential $cred -ErrorAction Stop | Out-Null

    # Load your Common.psm1 to reuse Resolve-ScSubscriptions
    Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop
    $resolved = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $env
    Write-Host "Resolved subscription: $($resolved.Name) / $($resolved.Id)"
    if (-not [string]::IsNullOrWhiteSpace($subIdExpected) -and $resolved.Id -ne $subIdExpected) {
      Write-Host "WARNING: CSV subscription_id=$subIdExpected but resolved=$($resolved.Id). Existing scan scripts will use the resolved one." -ForegroundColor Yellow
    }
  }

  if ($RunRgPermissions) {
    Safe-Run "RG Permissions ($groupForFolder/$env)" {
      pwsh -NoProfile -File $scanRgPerms `
        -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret `
        -adh_group $adh_group -adh_sub_group $adh_sub_group -adh_subscription_type $env `
        -ProdCsvPath $RgPermsPrdCsvPath -NonProdCsvPath $RgPermsNonPrdCsvPath `
        -OutputDir $subOut -BranchName $BranchName
    }
  }

  if ($RunRgTags) {
    Safe-Run "RG Tags ($groupForFolder/$env)" {
      pwsh -NoProfile -File $scanRgTags `
        -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret `
        -adh_group $adh_group -adh_sub_group $adh_sub_group -adh_subscription_type $env `
        -OutputDir $subOut -BranchName $BranchName
    }
  }

  if ($RunKvSecrets) {
    Safe-Run "KV Secrets ($groupForFolder/$env)" {
      pwsh -NoProfile -File $scanKvSecrets `
        -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret `
        -adh_group $adh_group -adh_sub_group $adh_sub_group -adh_subscription_type $env `
        -OutputDir $subOut -BranchName $BranchName
    }
  }

  if ($RunKvPermissions) {
    Safe-Run "KV Permissions ($groupForFolder/$env)" {
      pwsh -NoProfile -File $scanKvPerms `
        -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret `
        -adh_group $adh_group -adh_sub_group $adh_sub_group -adh_subscription_type $env `
        -OutputDir $subOut -BranchName $BranchName
    }
  }

  if ($RunKvFirewall) {
    Safe-Run "KV Firewall/Networks ($groupForFolder/$env)" {
      pwsh -NoProfile -File $scanKvFw `
        -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret `
        -adh_group $adh_group -adh_sub_group $adh_sub_group -adh_subscription_type $env `
        -OutputDir $subOut -BranchName $BranchName
    }
  }

  if ($RunVnet) {
    Safe-Run "VNet ($groupForFolder/$env)" {
      pwsh -NoProfile -File $scanVnet `
        -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret `
        -adh_group $adh_group -adh_sub_group $adh_sub_group -adh_subscription_type $env `
        -OutputDir $subOut -BranchName $BranchName
    }
  }

  if ($RunAdls) {
    Safe-Run "ADLS ACL ($groupForFolder/$env)" {
      pwsh -NoProfile -File $scanAdls `
        -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret `
        -adh_group $adh_group -adh_sub_group $adh_sub_group -adh_subscription_type $env `
        -InputCsvPath $AdlsInputCsvPath `
        -OutputDir $subOut -BranchName $BranchName
    }
  }

  if ($RunAdf) {
    Safe-Run "Data Factory ($groupForFolder/$env)" {
      pwsh -NoProfile -File $scanAdf `
        -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret `
        -adh_group $adh_group -adh_subscription_type $env `
        -OutputDir $subOut -BranchName $BranchName
    }
  }

  if ($RunDatabricks) {
    Safe-Run "Databricks ($groupForFolder/$env)" {
      pwsh -NoProfile -File $scanDbx `
        -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret `
        -adh_group $adh_group -adh_sub_group $adh_sub_group -adh_subscription_type $env `
        -OutputDir $subOut -BranchName $BranchName
    }
  }
}

Write-Host ""
Write-Host "MONTHLY ALL-SUBS run completed." -ForegroundColor Green
Write-Host "OutputRoot: $outRoot"
