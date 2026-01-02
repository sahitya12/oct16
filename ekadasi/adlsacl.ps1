# sanitychecks/scripts/Scan-ADLS-Acls.ps1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$ClientId,
    [Parameter(Mandatory)][string]$ClientSecret,
    [Parameter(Mandatory)][string]$adh_group,

    [string]$adh_sub_group = '',
    [ValidateSet('nonprd','prd')][string]$adh_subscription_type = 'nonprd',

    [Parameter(Mandatory)][string]$InputCsvPath,
    [Parameter(Mandatory)][string]$OutputDir,
    [string]$BranchName = ''
)

Import-Module Az.Accounts, Az.Resources, Az.Storage -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

# ---------------------------------------------------------------------
# Normalize adh_sub_group
# ---------------------------------------------------------------------
$adh_sub_group = ($adh_sub_group ?? '').Trim()
if ([string]::IsNullOrWhiteSpace($adh_sub_group)) {
    Write-Host "DEBUG: adh_sub_group empty -> <none>"
    $adh_sub_group = ''
}

Write-Host "DEBUG: TenantId  = $TenantId"
Write-Host "DEBUG: ClientId  = $ClientId"
Write-Host "DEBUG: adh_group = $adh_group"
Write-Host "DEBUG: env       = $adh_subscription_type"
Write-Host "DEBUG: CSV       = $InputCsvPath"
Write-Host "DEBUG: OutputDir = $OutputDir"

Ensure-Dir -Path $OutputDir | Out-Null
if (-not (Test-Path $InputCsvPath)) {
    throw "CSV not found: $InputCsvPath"
}

# ---------------------------------------------------------------------
# 🔥 CRITICAL FIX: Azure login WITHOUT subscription binding
# ---------------------------------------------------------------------
try {
    Disable-AzContextAutosave -Scope Process | Out-Null
    Clear-AzContext -Scope Process -Force -ErrorAction SilentlyContinue | Out-Null

    $sec  = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
    $cred = New-Object pscredential ($ClientId, $sec)

    Connect-AzAccount `
        -ServicePrincipal `
        -Tenant $TenantId `
        -Credential $cred `
        -AllowNoSubscriptions `
        -ErrorAction Stop | Out-Null

    Write-Host "DEBUG: Azure login OK (AllowNoSubscriptions)"

    $visibleSubs = @(Get-AzSubscription -ErrorAction Stop)
    Write-Host "DEBUG: Visible subscriptions = $($visibleSubs.Count)"

    if ($visibleSubs.Count -eq 0) {
        throw "SPN authenticated but cannot enumerate subscriptions. RBAC must be at subscription or MG scope."
    }
}
catch {
    throw "Azure login failed: $($_.Exception.Message)"
}

# ---------------------------------------------------------------------
# Custodian values
# ---------------------------------------------------------------------
$BaseCustodian = $adh_group
$BaseCustLower = $adh_group.ToLower() -replace '_',''
$CustIdentity  = if ($adh_sub_group) { "$adh_group-$adh_sub_group" } else { $adh_group }

# ---------------------------------------------------------------------
# Identity resolver (cached)
# ---------------------------------------------------------------------
$script:IdentityCache = @{}
function Resolve-IdentityObjectId {
    param([Parameter(Mandatory)][string]$Identity)

    if ($script:IdentityCache[$Identity]) {
        return $script:IdentityCache[$Identity]
    }

    $objId = $null
    try { $objId = (Get-AzADGroup -DisplayName $Identity -ErrorAction Stop).Id } catch {}
    if (-not $objId) {
        try { $objId = (Get-AzADServicePrincipal -DisplayName $Identity -ErrorAction Stop).Id } catch {}
    }
    if (-not $objId) {
        try { $objId = (Get-AzADServicePrincipal -SearchString $Identity -ErrorAction Stop)[0].Id } catch {}
    }

    $script:IdentityCache[$Identity] = $objId
    return $objId
}

# ---------------------------------------------------------------------
# Load CSV + resolve subscriptions
# ---------------------------------------------------------------------
$rows = Import-Csv $InputCsvPath
$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
$subs = @($subs)

$out = @()

foreach ($sub in $subs) {
    Set-ScContext -Subscription $sub
    Write-Host "`n=== Subscription: $($sub.Name) ===" -ForegroundColor Cyan

    foreach ($r in $rows) {

        $rg   = ($r.ResourceGroupName -replace '<Custodian>', $BaseCustodian).Trim()
        $sa   = ($r.StorageAccountName -replace '<Custodian>', $BaseCustodian -replace '<Cust>', $BaseCustLower).Trim()
        $cont = ($r.ContainerName -replace '<Custodian>', $BaseCustodian -replace '<Cust>', $BaseCustLower).Trim()
        $iden = ($r.Identity -replace '<Custodian>', $CustIdentity).Trim()

        if ($adh_subscription_type -eq 'prd' -and $sa -match 'nonprd$') { continue }
        if ($adh_subscription_type -eq 'nonprd' -and $sa -match 'prd$') { continue }

        $path = ($r.AccessPath -replace '<Custodian>', $BaseCustodian -replace '<Cust>', $BaseCustLower).Trim()
        if ($path -like '/catalog*') {
            $suffix = $path.Substring('/catalog'.Length)
            $path = if ($adh_sub_group) {
                "/adh_${BaseCustLower}_${($adh_sub_group.ToLower())}$suffix"
            } else {
                "/adh_${BaseCustLower}$suffix"
            }
        }
        if ($path -eq '/') { $path = '' }

        try {
            $saObj = Get-AzStorageAccount -RG $rg -Name $sa -ErrorAction Stop
            $ctx   = $saObj.Context
            $null  = Get-AzStorageContainer -Name $cont -Context $ctx -ErrorAction Stop

            $oid = Resolve-IdentityObjectId $iden
            if (-not $oid) { throw "Identity not found" }

            $p = @{ FileSystem=$cont; Context=$ctx; ErrorAction='Stop' }
            if ($path) { $p.Path = $path.TrimStart('/') }

            $item = Get-AzDataLakeGen2Item @p
            $acl  = $item.Acl

            $match = $acl | Where-Object { $_ -like "*$oid*" -and $_ -like "*$($r.PermissionType)*" }

            $status = if ($match) { 'OK' } else { 'MISSING' }
            $notes  = if ($match) { 'ACL present' } else { 'Permission missing' }
        }
        catch {
            $status = 'ERROR'
            $notes  = $_.Exception.Message
        }

        $out += [pscustomobject]@{
            SubscriptionName = $sub.Name
            ResourceGroup    = $rg
            Storage          = $sa
            Container        = $cont
            Folder           = if ($path) { $path } else { '/' }
            Identity         = $iden
            Permission       = $r.PermissionType
            Status           = $status
            Notes            = $notes
        }
    }
}

# ---------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------
$prefix = "adls_validation_{0}_{1}" -f `
    ($(if ($adh_sub_group) { "$adh_group-$adh_sub_group" } else { $adh_group })), `
    $adh_subscription_type

$csvOut = New-StampedPath -BaseDir $OutputDir -Prefix $prefix
Write-CsvSafe -Rows $out -Path $csvOut

$htmlOut = $csvOut -replace '\.csv$','.html'
Convert-CsvToHtml -CsvPath $csvOut -HtmlPath $htmlOut `
    -Title "ADLS Validation ($prefix) $BranchName"

Write-Host "ADLS validation completed"
Write-Host "CSV : $csvOut"
Write-Host "HTML: $htmlOut"

exit 0
