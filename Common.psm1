function Resolve-AdhSubscriptions {
    <#
    .SYNOPSIS
      Resolve ADH subscriptions for a custodian (adh_group) and environment (nonprd|prd).

    .DESCRIPTION
      Matches your naming rules:
        - nonprd  → dev_azure_*_ADH<suffix>
        - prd     → prd_azure_*_ADH<suffix>
      Suffix variants tried (in order):
        1) ADH<ADH_GROUP>
        2) ADH<FIRST_LETTER><ADH_GROUP>   (legacy/variant like ADHMMDM, ADHNNHH)
      Special cases map certain groups to a fixed suffix (e.g., KTK → ADHPlatform).

      Returns the single best match by default, or all matches with -All.

    .PARAMETER AdhGroup
      The custodian (e.g., 'KTK', 'MDM', 'NHH', 'JS', ...).

    .PARAMETER Environment
      'nonprd' (default) or 'prd'.

    .PARAMETER All
      Return all matching subscriptions instead of the single preferred one.

    .PARAMETER Loose
      Adds a final, very tolerant pattern: ADH*<ADH_GROUP>* (use only if needed).

    .OUTPUTS
      If -All is not used: Microsoft.Azure.Commands.Profile.Models.Core.PSAzureSubscription
      If -All is used:    Array of PSAzureSubscription

    .EXAMPLE
      Resolve-AdhSubscriptions -AdhGroup KTK -Environment nonprd
      # → dev_azure_20401_ADHPlatform

    .EXAMPLE
      Resolve-AdhSubscriptions -AdhGroup MDM -Environment prd -All
      # → prd_azure_20910_ADHMMDM (+ any others that match)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z]{2,}$')]
        [string]$AdhGroup,

        [Parameter()]
        [ValidateSet('nonprd','prd')]
        [string]$Environment = 'nonprd',

        [switch]$All,
        [switch]$Loose
    )

    # Normalize
    $g = $AdhGroup.Trim().ToUpperInvariant()

    # 1) Environment prefix
    $envPrefix = if ($Environment -eq 'prd') { 'prd_azure_' } else { 'dev_azure_' }

    # 2) Special case map (extend as needed)
    #    KTK must scan the Platform subscription.
    $specialMap = @{
        'KTK' = 'ADHPlatform'
    }

    # 3) Build suffix variants
    $variants = [System.Collections.Generic.List[string]]::new()
    if ($specialMap.ContainsKey($g)) {
        $variants.Add($specialMap[$g])          # e.g., ADHPlatform
    }
    else {
        $first = $g.Substring(0,1)
        $variants.Add("ADH$g")                  # ADHMDM, ADHNHH, ADHJS
        $variants.Add("ADH$first$g")            # ADHMMDM, ADHNNHH, ADHJJS
        if ($Loose) {
            $variants.Add("ADH*$g*")            # Optional very loose fallback
        }
    }

    # 4) Enumerate subscriptions and match
    try {
        $allSubs = Get-AzSubscription -ErrorAction Stop
    }
    catch {
        throw "Resolve-AdhSubscriptions: failed to call Get-AzSubscription. $($_.Exception.Message)"
    }

    $matches = @()
    foreach ($v in $variants) {
        # v can be exact (ADHNNHH) or wildcard (ADH*NNHH*)
        $pattern = "$envPrefix*_*$v"            # e.g., dev_azure_*_ADHMMDM
        $matches += $allSubs | Where-Object { $_.Name -like $pattern }
    }

    # De-duplicate and keep enabled/active ones first if possible
    $matches = $matches |
        Sort-Object Name -Unique

    if (-not $matches -or $matches.Count -eq 0) {
        $hint = $variants -join ', '
        throw "Resolve-AdhSubscriptions: No subscriptions matched for adh_group '$g' ($Environment). Tried patterns: $hint"
    }

    if ($All) {
        return $matches
    }

    # 5) Pick a single 'best' match deterministically
    function Get-Rank([string]$name) {
        # Lowest number is preferred
        if ($name -like "$envPrefix*_ADH$g")                   { return 0 } # ADH<GROUP>
        elseif ($name -like "$envPrefix*_ADH$($g.Substring(0,1))$g") { return 1 } # ADH<FIRST><GROUP>
        elseif ($name -like "$envPrefix*_ADHPlatform")         { return 2 } # Special
        else                                                   { return 9 }
    }

    $preferred = $matches |
        Sort-Object @{Expression={ Get-Rank $_.Name }}, @{Expression='Name'} |
        Select-Object -First 1

    if (-not $preferred) {
        $names = ($matches | Select-Object -ExpandProperty Name) -join '; '
        throw "Resolve-AdhSubscriptions: Could not select a preferred subscription from: $names"
    }

    return $preferred
}
