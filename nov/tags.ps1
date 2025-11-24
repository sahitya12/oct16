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

Import-Module Az.Accounts, Az.Resources -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop
Ensure-Dir -Path $OutputDir | Out-Null

Write-Host "DEBUG: TenantId       = $TenantId"
Write-Host "DEBUG: ClientId       = $ClientId"
Write-Host "DEBUG: adh_group      = $adh_group"
Write-Host "DEBUG: adh_sub_group  = $adh_sub_group"
Write-Host "DEBUG: subscription   = $adh_subscription_type"
Write-Host "DEBUG: OutputDir      = $OutputDir"
Write-Host "DEBUG: BranchName     = $BranchName"

# --------------------------------------------------------------------
# Connect
# --------------------------------------------------------------------
if (-not (Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
    throw "Azure connection failed."
}

# --------------------------------------------------------------------
# RG name pattern (adh_group / adh_group_adh_sub_group)
# --------------------------------------------------------------------
$rgPattern = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) {
    "*$adh_group*"
} else {
    "*${adh_group}_${adh_sub_group}*"
}

Write-Host "Scanning Resource Groups matching pattern: $rgPattern"

# --------------------------------------------------------------------
# Resolve subscriptions
# --------------------------------------------------------------------
$subs = Resolve-ScSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
if ($subs -isnot [System.Collections.IEnumerable]) { $subs = ,$subs }

# We will collect:
# - all unique tag keys, across RGs and Resources
# - a combined list of entries (RG + Resource), each with RG tags + Resource tags
$allTagKeys = [System.Collections.Generic.HashSet[string]]::new()
$entries    = @()

foreach ($sub in $subs) {
    Set-ScContext -Subscription $sub

    Write-Host ""
    Write-Host "=== Subscription: $($sub.Name) ===" -ForegroundColor Cyan

    $rgs = Get-AzResourceGroup -ErrorAction SilentlyContinue

    foreach ($rg in $rgs) {

        if ($rg.ResourceGroupName -notlike $rgPattern) {
            continue
        }

        # ----------------------------------------------
        # 1) Resource Group tags
        # ----------------------------------------------
        $rgTags = @{}
        if ($rg.Tags) {
            foreach ($key in $rg.Tags.Keys) {
                $rgTags[$key] = $rg.Tags[$key]
                $allTagKeys.Add($key) | Out-Null
            }
        }

        # Store RG-level entry
        $entries += [PSCustomObject]@{
            Scope         = 'ResourceGroup'
            ResourceGroup = $rg.ResourceGroupName
            ResourceName  = ''
            ResourceType  = ''
            RgTags        = $rgTags
            ResTags       = @{}
        }

        # ----------------------------------------------
        # 2) Resource-level tags (inside this RG)
        # ----------------------------------------------
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
# Build final rows: RG + Resource,
# with effective tags (resource overrides RG = inherited)
# --------------------------------------------------------------------
$rows = foreach ($item in $entries) {

    # Determine if this row is effectively "inherited" (for resources)
    $inheritedFlag = 'No'
    if ($item.Scope -eq 'Resource') {
        # If resource has NO direct tags but RG has tags, consider them inherited
        if (($item.ResTags.Count -eq 0) -and ($item.RgTags.Count -gt 0)) {
            $inheritedFlag = 'Yes'
        }
    }

    $obj = [ordered]@{
        Scope          = $item.Scope                # ResourceGroup / Resource
        ResourceGroup  = $item.ResourceGroup
        ResourceName   = $item.ResourceName
        ResourceType   = $item.ResourceType
        InheritedFromRG = $inheritedFlag            # Yes/No
    }

    foreach ($tagKey in $allTagKeys) {
        $value = $null

        # Priority: resource tag wins; if missing, fall back to RG tag (inherited)
        if ($item.ResTags.ContainsKey($tagKey)) {
            $value = $item.ResTags[$tagKey]
        }
        elseif ($item.RgTags.ContainsKey($tagKey)) {
            $value = $item.RgTags[$tagKey]  # inherited
        }

        $obj[$tagKey] = $value
    }

    [PSCustomObject]$obj
}

# --------------------------------------------------------------------
# Handle no results
# --------------------------------------------------------------------
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

Write-Host "RG & Resource tag scan completed." -ForegroundColor Green
Write-Host "CSV : $csvOut"
Write-Host "HTML: $htmlOut"
