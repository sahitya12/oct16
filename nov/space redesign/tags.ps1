param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$ClientId,
    [Parameter(Mandatory)][string]$ClientSecret,
    [Parameter(Mandatory)][string]$adh_group,
    [string]$adh_sub_group = '',
    [ValidateSet('nonprd','prd')][string]$adh_subscription_type = 'nonprd',
    [Parameter(Mandatory)][string]$OutputDir,
    [string]$BranchName = ''
)

# --- NORMALIZE adh_sub_group: turn " " or "   " into empty string ---
if ($null -ne $adh_sub_group) {
    $adh_sub_group = $adh_sub_group.Trim()
}
if ([string]::IsNullOrWhiteSpace($adh_sub_group)) {
    $adh_sub_group = ''
}

Import-Module Az.Accounts, Az.Resources -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

Ensure-Dir -Path $OutputDir | Out-Null

Write-Host "DEBUG: TenantId       = $TenantId"
Write-Host "DEBUG: ClientId       = $ClientId"
Write-Host "DEBUG: adh_group      = $adh_group"
Write-Host "DEBUG: adh_sub_group  = '$adh_sub_group'"
Write-Host "DEBUG: subscription   = $adh_subscription_type"
Write-Host "DEBUG: OutputDir      = $OutputDir"
Write-Host "DEBUG: BranchName     = $BranchName"

# --------------------------------------------------------------------
# Connect to Azure
# --------------------------------------------------------------------
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure connection failed."
}

# --------------------------------------------------------------------
# Build RG search patterns
#   - If ONLY adh_group => *adh_group*
#   - If adh_sub_group also passed => *adh_group_adh_sub_group* ONLY
# --------------------------------------------------------------------
[string[]]$patterns = @()

if ([string]::IsNullOrWhiteSpace($adh_sub_group)) {
    # Only adh_group used
    $patterns = @("*$adh_group*")
}
else {
    # Only adh_group_adh_sub_group used
    $patterns = @("*${adh_group}_${adh_sub_group}*")
}

Write-Host "DEBUG: RG patterns to search:"
$patterns | ForEach-Object { Write-Host " - $_" }

# --------------------------------------------------------------------
# Resolve subscriptions
# --------------------------------------------------------------------
$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
if ($subs -isnot [System.Collections.IEnumerable]) { $subs = ,$subs }

# Collect unique tag keys
$allTagKeys = [System.Collections.Generic.HashSet[string]]::new()
$entries = @()

foreach ($sub in $subs) {
    Set-ScContext -Subscription $sub

    Write-Host ""
    Write-Host "=== Subscription: $($sub.Name) ===" -ForegroundColor Cyan

    $rgs = Get-AzResourceGroup -ErrorAction SilentlyContinue

    foreach ($rg in $rgs) {

        # If RG does NOT match any pattern, skip
        $matchesPattern = $false
        foreach ($p in $patterns) {
            if ($rg.ResourceGroupName -like $p) {
                $matchesPattern = $true
                break
            }
        }

        if (-not $matchesPattern) {
            continue
        }

        # --------------------------------------------
        # RG tags
        # --------------------------------------------
        $rgTags = @{}
        if ($rg.Tags) {
            foreach ($key in $rg.Tags.Keys) {
                $rgTags[$key] = $rg.Tags[$key]
                $allTagKeys.Add($key) | Out-Null
            }
        }

        # Record RG entry (also set ResourceName = RG name)
        $entries += [PSCustomObject]@{
            Scope         = 'ResourceGroup'
            ResourceGroup = $rg.ResourceGroupName
            ResourceName  = $rg.ResourceGroupName
            ResourceType  = 'Microsoft.Resources/resourceGroups'
            RgTags        = $rgTags
            ResTags       = @{}
        }

        # --------------------------------------------
        # Resource tags
        # --------------------------------------------
        $resources = Get-AzResource -ResourceGroupName $rg.ResourceGroupName -ErrorAction SilentlyContinue

        foreach ($res in $resources) {
            $resTags = @{}
            if ($res.Tags) {
                foreach ($k in $res.Tags.Keys) {
                    $resTags[$k] = $res.Tags[$k]
                    $allTagKeys.Add($k) | Out-Null
                }
            }

            $entries += [PSCustomObject]@{
                Scope         = 'Resource'
                ResourceGroup = $rg.ResourceGroupName
                ResourceName  = $res.Name
                ResourceType  = $res.ResourceType
                RgTags        = $rgTags
                ResTags       = $resTags
            }
        }
    }
}

# --------------------------------------------------------------------
# Build final merged tag dataset
# --------------------------------------------------------------------
$rows = foreach ($item in $entries) {

    $inheritedFlag = 'No'
    if ($item.Scope -eq 'Resource') {
        if (($item.ResTags.Count -eq 0) -and ($item.RgTags.Count -gt 0)) {
            $inheritedFlag = 'Yes'
        }
    }

    $obj = [ordered]@{
        Scope           = $item.Scope
        ResourceGroup   = $item.ResourceGroup
        ResourceName    = $item.ResourceName
        ResourceType    = $item.ResourceType
        InheritedFromRG = $inheritedFlag
    }

    foreach ($tagKey in $allTagKeys) {
        $value = $null
        if ($item.ResTags.ContainsKey($tagKey)) {
            $value = $item.ResTags[$tagKey]
        }
        elseif ($item.RgTags.ContainsKey($tagKey)) {
            $value = $item.RgTags[$tagKey]
        }
        $obj[$tagKey] = $value
    }

    [PSCustomObject]$obj
}

if (-not $rows -or $rows.Count -eq 0) {
    $rows = @(
        [PSCustomObject]@{
            Scope           = ''
            ResourceGroup   = ''
            ResourceName    = ''
            ResourceType    = ''
            InheritedFromRG = ''
        }
    )
}

# --------------------------------------------------------------------
# Export CSV + HTML
# --------------------------------------------------------------------
$csvOut = New-StampedPath -BaseDir $OutputDir -Prefix ("rg_tags_{0}_{1}" -f $adh_group, $adh_subscription_type)
Write-CsvSafe -Rows $rows -Path $csvOut

$htmlOut = $csvOut -replace '\.csv$','.html'
Convert-CsvToHtml -CsvPath $csvOut -HtmlPath $htmlOut -Title "RG & Resource Tags ($adh_group / $adh_subscription_type) $BranchName"

Write-Host "RG Tag Scan Completed." -ForegroundColor Green
Write-Host "CSV : $csvOut"
Write-Host "HTML: $htmlOut"
