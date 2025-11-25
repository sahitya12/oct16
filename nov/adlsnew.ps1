param(
    [Parameter(Mandatory = $true)][string]$TenantId,
    [Parameter(Mandatory = $true)][string]$ClientId,
    [Parameter(Mandatory = $true)][string]$ClientSecret,
    [Parameter(Mandatory = $true)][string]$adh_group,
    [string]$adh_sub_group = '',
    [ValidateSet('nonprd','prd')][string]$adh_subscription_type = 'nonprd',

    # Will auto-select prd/nonprd CSV unless passed explicitly
    [string]$InputCsvPath = '',

    [Parameter(Mandatory = $true)][string]$OutputDir,
    [string]$BranchName = ''
)


Import-Module Az.Accounts, Az.Resources, Az.Storage -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

Ensure-Dir -Path $OutputDir | Out-Null

Write-Host "==== ADLS Validation START ====" -ForegroundColor Cyan
Write-Host "adh_group       = $adh_group"
Write-Host "adh_sub_group   = $adh_sub_group"
Write-Host "subscription    = $adh_subscription_type"


# ============================================================================
# SELECT CSV FILE: adls_prd_permissions.csv OR adls_nonprd_permissions.csv
# ============================================================================
$csvFileName = if ($adh_subscription_type -eq 'prd') {
    'adls_prd_permissions.csv'
}
else {
    'adls_nonprd_permissions.csv'
}

if ([string]::IsNullOrWhiteSpace($InputCsvPath)) {
    $inputsRoot   = Join-Path (Split-Path -Parent $PSScriptRoot) 'inputs'
    $InputCsvPath = Join-Path $inputsRoot $csvFileName
}

Write-Host "Using input CSV: $InputCsvPath"


# ============================================================================
# CONNECT TO AZURE
# ============================================================================
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure login failed."
}

# ============================================================================
# CUSTODIAN LOGIC — Updated as per your requirement
# ============================================================================

# Identity = adh_group or adh_group_adh_sub_group
$IdentityCustodian = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) {
    $adh_group
} else {
    "${adh_group}_${adh_sub_group}"
}

# <Cust> = ALWAYS adh_group lower (WITHOUT subgroup)
$custLower = $adh_group.ToLower() -replace '_',''

Write-Host "Identity Replacement Custodian = $IdentityCustodian"
Write-Host "Lowercase Cust for SA/Containers = $custLower"


# ============================================================================
# LOAD CSV
# ============================================================================
$rows = Import-Csv -LiteralPath $InputCsvPath

$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
if ($subs -isnot [System.Collections.IEnumerable]) { $subs = ,$subs }


$out = @()

foreach ($sub in $subs) {

    Set-ScContext -Subscription $sub

    foreach ($r in $rows) {

        # ===========================================================
        # APPLY NEW PLACEHOLDER REPLACEMENT RULES
        # ===========================================================

        # ResourceGroupName: always adh_group
        $rgName = ($r.ResourceGroupName -replace '<Custodian>', $adh_group).Trim()

        # StorageAccountName: only <Cust> → adh_group lower
        $saName = ($r.StorageAccountName -replace '<Cust>', $custLower).Trim()
        $saName = ($saName -replace '<Custodian>', $adh_group).Trim()  # safety

        # ContainerName: only <Cust> → adh_group lower
        $cont = ($r.ContainerName -replace '<Cust>', $custLower).Trim()

        # Identity: Use IdentityCustodian
        $iden = ($r.Identity -replace '<Custodian>', $IdentityCustodian).Trim()

        # AccessPath rules
        $accessPath = $r.AccessPath.Trim()
        $accessPath = ($accessPath -replace '<Cust>', $custLower)
        $accessPath = ($accessPath -replace '<Custodian>', $IdentityCustodian)

        # Catalog rules
        if ($accessPath -like "/catalog*") {
            $suffix = $accessPath.Substring(8)
            $accessPath = "/adh_${IdentityCustodian.ToLower()}$suffix"
        }

        # "/" → empty
        $normalizedPath = if ($accessPath -eq '/') { '' } else { $accessPath }

        $folderForReport = if ($normalizedPath -eq '') { "/" } else { $normalizedPath }


        # ===========================================================
        # LOOKUP STORAGE/CONTAINER/ACL
        # ===========================================================

        try {
            $sa = Get-AzStorageAccount -ResourceGroupName $rgName -Name $saName -ErrorAction Stop
        }
        catch {
            $out += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $rgName
                Storage          = $saName
                Container        = $cont
                Folder           = $folderForReport
                Identity         = $iden
                Permission       = $r.PermissionType
                Status           = 'ERROR'
                Notes            = "Storage account not found"
            }
            continue
        }

        $ctx = $sa.Context

        try {
            $container = Get-AzStorageContainer -Name $cont -Context $ctx -ErrorAction Stop
        }
        catch {
            $out += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $rgName
                Storage          = $saName
                Container        = $cont
                Folder           = $folderForReport
                Identity         = $iden
                Permission       = $r.PermissionType
                Status           = 'ERROR'
                Notes            = "Container not found"
            }
            continue
        }


        # ===========================================================
        # ACL CHECK
        # ===========================================================
        try {
            $params = @{
                FileSystem = $cont
                Context    = $ctx
                ErrorAction = 'Stop'
            }
            if ($normalizedPath) { $params['Path'] = $normalizedPath.TrimStart('/') }

            $item      = Get-AzDataLakeGen2Item @params
            $aclString = $item.Acl
            $permType  = $r.PermissionType

            $objectId = Resolve-IdentityObjectId -IdentityName $iden

            $matchEntry = $aclString | Where-Object {
                ($_ -like "*$objectId*") -and ($_ -like "*$permType*")
            }

            $status = if ($matchEntry) { "OK" } else { "MISSING" }
            $notes  = if ($matchEntry) { "ACL contains required permission" } else { "Missing required ACL entry" }
        }
        catch {
            $status = "ERROR"
            $notes  = "ACL read failed: $($_.Exception.Message)"
        }


        $out += [pscustomobject]@{
            SubscriptionName = $sub.Name
            ResourceGroup    = $rgName
            Storage          = $saName
            Container        = $cont
            Folder           = $folderForReport
            Identity         = $iden
            Permission       = $r.PermissionType
            Status           = $status
            Notes            = $notes
        }
    }
}

# ============================================================================
# EXPORT RESULTS
# ============================================================================
$csvOut  = New-StampedPath -BaseDir $OutputDir -Prefix ("adls_validation_{0}_{1}" -f $adh_group, $adh_subscription_type)
Write-CsvSafe -Rows $out -Path $csvOut

$htmlOut = $csvOut -replace '\.csv$','.html'
Convert-CsvToHtml -CsvPath $csvOut -HtmlPath $htmlOut -Title "ADLS ACL Validation"

Write-Host "ADLS Validation Completed"
Write-Host "CSV  : $csvOut"
Write-Host "HTML : $htmlOut"
