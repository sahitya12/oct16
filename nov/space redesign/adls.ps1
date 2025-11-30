param(
    [Parameter(Mandatory = $true)][string]$TenantId,
    [Parameter(Mandatory = $true)][string]$ClientId,
    [Parameter(Mandatory = $true)][string]$ClientSecret,
    [Parameter(Mandatory = $true)][string]$adh_group,
    [string]$adh_sub_group = '',
    [ValidateSet('nonprd','prd')][string]$adh_subscription_type = 'nonprd',
    [Parameter(Mandatory = $true)][string]$InputCsvPath,
    [Parameter(Mandatory = $true)][string]$OutputDir,
    [string]$BranchName = ''
)

$ErrorActionPreference = 'Stop'

Import-Module Az.Accounts, Az.Resources, Az.Storage -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

# ----------------------------------------------------------------------
# Normalise adh_sub_group (handle " " etc.)
# ----------------------------------------------------------------------
if ($null -ne $adh_sub_group) {
    $adh_sub_group = $adh_sub_group.Trim()
}
if ([string]::IsNullOrWhiteSpace($adh_sub_group)) {
    Write-Host "DEBUG: adh_sub_group is empty/space -> treating as <none>"
    $adh_sub_group = ''
}

Write-Host "DEBUG: TenantId      = $TenantId"
Write-Host "DEBUG: ClientId      = $ClientId"
Write-Host "DEBUG: adh_group     = $adh_group"
Write-Host "DEBUG: adh_sub_group = '$adh_sub_group'"
Write-Host "DEBUG: subscription  = $adh_subscription_type"
Write-Host "DEBUG: InputCsvPath  = $InputCsvPath"
Write-Host "DEBUG: OutputDir     = $OutputDir"
Write-Host "DEBUG: BranchName    = $BranchName"

# ----------------------------------------------------------------------
# Ensure output dir
# ----------------------------------------------------------------------
Ensure-Dir -Path $OutputDir | Out-Null

if (-not (Test-Path -LiteralPath $InputCsvPath)) {
    throw "ADLS CSV not found: $InputCsvPath"
}

# ----------------------------------------------------------------------
# Connect to Azure
# ----------------------------------------------------------------------
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure connection failed."
}

# ----------------------------------------------------------------------
# Custodian helpers according to your rules
#   RG / SA / Container use adh_group only
#   Identity uses adh_group or adh_group_<subgroup> (underscore)
# ----------------------------------------------------------------------
$BaseCustodian = $adh_group
$BaseCustLower = $adh_group.ToLower() -replace '_',''

$CustIdentity = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) {
    $adh_group
}
else {
    "${adh_group}_${adh_sub_group}"
}

Write-Host "DEBUG: BaseCustodian (RG/SA/Cont)  = $BaseCustodian"
Write-Host "DEBUG: <Cust> (lower, no _)        = $BaseCustLower"
Write-Host "DEBUG: CustIdentity (for Identity) = $CustIdentity"

# ----------------------------------------------------------------------
# Identity cache + resolver
# ----------------------------------------------------------------------
$script:IdentityCache = @{ }

function Resolve-IdentityObjectId {
    param(
        [Parameter(Mandatory = $true)][string]$IdentityName
    )

    if ($script:IdentityCache.ContainsKey($IdentityName)) {
        return $script:IdentityCache[$IdentityName]
    }

    $id = $null

    try {
        $grp = Get-AzADGroup -DisplayName $IdentityName -ErrorAction Stop
        if ($grp -and $grp.Id) { $id = $grp.Id }
    } catch {}

    if (-not $id) {
        try {
            $sp = Get-AzADServicePrincipal -DisplayName $IdentityName -ErrorAction Stop
            if ($sp -and $sp.Id) { $id = $sp.Id }
        } catch {}
    }

    if (-not $id) {
        try {
            $sp2 = Get-AzADServicePrincipal -SearchString $IdentityName -ErrorAction Stop
            if ($sp2 -and $sp2.Count -ge 1) { $id = $sp2[0].Id }
        } catch {}
    }

    if (-not $id) {
        $guidRef = [ref]([Guid]::Empty)
        if ([Guid]::TryParse($IdentityName, $guidRef)) {
            $id = $IdentityName
        }
    }

    $script:IdentityCache[$IdentityName] = $id
    return $id
}

# ----------------------------------------------------------------------
# Load CSV & subscriptions
# ----------------------------------------------------------------------
$rows = Import-Csv -LiteralPath $InputCsvPath
Write-Host "DEBUG: CSV row count = $($rows.Count)"

$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
if ($subs -isnot [System.Collections.IEnumerable]) { $subs = ,$subs }

Write-Host "DEBUG: Subscriptions = $($subs.Name -join ', ')"

$out = @()

foreach ($sub in $subs) {
    Set-ScContext -Subscription $sub

    Write-Host ""
    Write-Host "=== Subscription: $($sub.Name) ===" -ForegroundColor Cyan

    foreach ($r in $rows) {

        # --- Placeholder substitution per row ---------------------------
        $rgName = ($r.ResourceGroupName -replace '<Custodian>', $BaseCustodian).Trim()

        $saName = $r.StorageAccountName
        $saName = ($saName -replace '<Custodian>', $BaseCustodian)
        $saName = ($saName -replace '<Cust>',      $BaseCustLower)
        $saName = $saName.Trim()

        $cont = $r.ContainerName
        $cont = ($cont -replace '<Custodian>', $BaseCustodian)
        $cont = ($cont -replace '<Cust>',      $BaseCustLower)
        $cont = $cont.Trim()

        $iden = ($r.Identity -replace '<Custodian>', $CustIdentity).Trim()

        # --- ENV filter between adlsnonprd / adlsprd --------------------
        if ($adh_subscription_type -eq 'prd') {
            if ($saName -match 'adlsnonprd$') {
                Write-Host "SKIP (prd run): nonprod ADLS $saName" -ForegroundColor Yellow
                continue
            }
        } else {
            if ($saName -match 'adlsprd$') {
                Write-Host "SKIP (nonprd run): prod ADLS $saName" -ForegroundColor Yellow
                continue
            }
        }

        # --- AccessPath -------------------------------------------------
        $accessPath = $r.AccessPath
        $accessPath = ($accessPath -replace '<Custodian>', $BaseCustodian)
        $accessPath = ($accessPath -replace '<Cust>',      $BaseCustLower)
        $accessPath = $accessPath.Trim()

        # /catalog → /adh_<adh_group> or /adh_<adh_group>_<adh_sub_group>
        if ($accessPath -like '/catalog*') {
            $prefixLength = '/catalog'.Length
            $suffix       = $accessPath.Substring($prefixLength)  # includes leading /

            if ([string]::IsNullOrWhiteSpace($adh_sub_group)) {
                $accessPath = "/adh_${adh_group}${suffix}"
            }
            else {
                $accessPath = "/adh_${adh_group}_${adh_sub_group}${suffix}"
            }
        }

        $normalizedPath = $accessPath
        if ($normalizedPath -eq '/') { $normalizedPath = '' }

        $folderForReport = if ([string]::IsNullOrWhiteSpace($normalizedPath)) { '/' } else { $normalizedPath }

        Write-Host "DEBUG Row:"
        Write-Host "  RG      = $rgName"
        Write-Host "  Storage = $saName"
        Write-Host "  Cont    = $cont"
        Write-Host "  Id      = $iden"
        Write-Host "  Path    = $normalizedPath"

        # --- Basic validation -------------------------------------------
        if ([string]::IsNullOrWhiteSpace($rgName) -or [string]::IsNullOrWhiteSpace($saName)) {
            $out += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $rgName
                Storage          = $saName
                Container        = $cont
                Folder           = $folderForReport
                Identity         = $iden
                Permission       = $r.PermissionType
                Status           = 'ERROR'
                Notes            = 'After placeholder replacement ResourceGroupName or StorageAccountName is empty.'
            }
            continue
        }

        # ----------------------------------------------------------------
        # Resolve storage account and container
        # ----------------------------------------------------------------
        try {
            $sa = Get-AzStorageAccount -ResourceGroupName $rgName -Name $saName -ErrorAction Stop
        } catch {
            $out += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $rgName
                Storage          = $saName
                Container        = $cont
                Folder           = $folderForReport
                Identity         = $iden
                Permission       = $r.PermissionType
                Status           = 'ERROR'
                Notes            = "Storage account error: $($_.Exception.Message)"
            }
            continue
        }

        $ctx = $sa.Context

        try {
            $container = Get-AzStorageContainer -Name $cont -Context $ctx -ErrorAction Stop
        } catch {
            $out += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $rgName
                Storage          = $saName
                Container        = $cont
                Folder           = $folderForReport
                Identity         = $iden
                Permission       = $r.PermissionType
                Status           = 'ERROR'
                Notes            = "Container fetch error: $($_.Exception.Message)"
            }
            continue
        }

        # ----------------------------------------------------------------
        # Resolve identity objectId
        # ----------------------------------------------------------------
        $objectId = Resolve-IdentityObjectId -IdentityName $iden
        if (-not $objectId) {
            $out += [pscustomobject]@{
                SubscriptionName = $sub.Name
                ResourceGroup    = $rgName
                Storage          = $saName
                Container        = $cont
                Folder           = $folderForReport
                Identity         = $iden
                Permission       = $r.PermissionType
                Status           = 'ERROR'
                Notes            = "Identity '$iden' not found in Entra ID"
            }
            continue
        }

        # ----------------------------------------------------------------
        # Read ACLs
        # ----------------------------------------------------------------
        try {
            $params = @{
                FileSystem  = $cont
                Context     = $ctx
                ErrorAction = 'Stop'
            }

            if (-not [string]::IsNullOrWhiteSpace($normalizedPath)) {
                $params['Path'] = $normalizedPath.TrimStart('/')
            }

            $item      = Get-AzDataLakeGen2Item @params
            $aclString = $item.Acl
            $permType  = $r.PermissionType

            # 1) Explicit ACL
            $matchEntry = $aclString | Where-Object {
                ($_ -like "*$objectId*") -and ($_ -like "*$permType*")
            }

            # 2) Owner / Group
            $ownerMatch = $false
            $groupMatch = $false

            if ($item.Owner) {
                if ($item.Owner -like "*$objectId*" -or $item.Owner -eq $iden) {
                    $ownerMatch = $true
                }
            }
            if ($item.Group) {
                if ($item.Group -like "*$objectId*" -or $item.Group -eq $iden) {
                    $groupMatch = $true
                }
            }

            $hasMatch = $matchEntry -or $ownerMatch -or $groupMatch

            $status = if ($hasMatch) { 'OK' } else { 'MISSING' }
            if ($matchEntry) {
                $notes = 'ACL contains required permission'
            }
            elseif ($ownerMatch -or $groupMatch) {
                $notes = 'Identity matches Owner/Group with required permission mask'
            }
            else {
                $notes = 'Permissions missing or mismatched'
            }

        } catch {
            $status = 'ERROR'
            $notes  = "ACL read error: $($_.Exception.Message)"
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

if (-not $out -or $out.Count -eq 0) {
    $out += [pscustomobject]@{
        SubscriptionName = ''
        ResourceGroup    = ''
        Storage          = ''
        Container        = ''
        Folder           = ''
        Identity         = ''
        Permission       = ''
        Status           = 'NO_RESULTS'
        Notes            = 'Nothing matched in scan'
    }
}

$groupForFile = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) {
    $adh_group
}
else {
    "${adh_group}_${adh_sub_group}"
}

$csvOut  = New-StampedPath -BaseDir $OutputDir -Prefix ("adls_validation_{0}_{1}" -f $groupForFile, $adh_subscription_type)
Write-CsvSafe -Rows $out -Path $csvOut

$htmlOut = $csvOut -replace '\.csv$','.html'
Convert-CsvToHtml -CsvPath $csvOut -HtmlPath $htmlOut -Title "ADLS Validation ($groupForFile / $adh_subscription_type) $BranchName"

Write-Host "ADLS validation completed." -ForegroundColor Green
Write-Host "CSV : $csvOut"
Write-Host "HTML: $htmlOut"

# IMPORTANT: do NOT call exit here → exit code 0 by default
