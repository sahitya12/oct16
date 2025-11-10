function Resolve-AdhSubscriptions {
    <#
      Resolves subscriptions for a given ADH custodian and environment.
      Updated mapping logic for KTK, MDM, NHH and future ADH groups.
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

    $g = $AdhGroup.Trim().ToUpperInvariant()

    # --- Prefix for environment
    $envPrefix = if ($Environment -eq 'prd') { 'prd_azure_' } else { 'dev_azure_' }

    # --- Map any special custodian to a fixed suffix
    $specialMap = @{
        'KTK' = 'ADHPlatform'   # special case: AI / Platform team
        # Add others here if you ever need fixed routing
        # 'ABC' = 'ADHCommon', etc.
    }

    # --- Build suffix variants
    $variants = [System.Collections.Generic.List[string]]::new()
    if ($specialMap.ContainsKey($g)) {
        $variants.Add($specialMap[$g])
    }
    else {
        $first = $g.Substring(0,1)
        $variants.Add("ADH$g")       # ADHMDM, ADHNHH
        $variants.Add("ADH$first$g") # ADHMMDM, ADHNNHH
        if ($Loose) { $variants.Add("ADH*$g*") }
    }

    # --- Get all subs visible to the SPN
    try {
        $allSubs = Get-AzSubscription -ErrorAction Stop
    }
    catch {
        throw "Resolve-AdhSubscriptions: failed to list subscriptions. $($_.Exception.Message)"
    }

    # --- Match subscriptions by pattern
    $matches = @()
    foreach ($v in $variants) {
        $pattern = "$envPrefix*_*$v"
        $matches += $allSubs | Where-Object { $_.Name -like $pattern }
    }

    $matches = $matches | Sort-Object Name -Unique
    if (-not $matches) {
        throw "Resolve-AdhSubscriptions: No match for adh_group '$g' ($Environment). Tried: $($variants -join ', ')"
    }

    if ($All) { return $matches }

    # --- Ranking logic: exact > first-letter variant > special map
    function Get-Rank([string]$name) {
        if ($name -like "$envPrefix*_ADH$g") { return 0 }
        elseif ($name -like "$envPrefix*_ADH$($g.Substring(0,1))$g") { return 1 }
        elseif ($name -like "$envPrefix*_ADHPlatform") { return 2 }
        else { return 9 }
    }

    $preferred = $matches |
        Sort-Object @{Expression={ Get-Rank $_.Name }}, @{Expression='Name'} |
        Select-Object -First 1

    if (-not $preferred) {
        throw "Resolve-AdhSubscriptions: could not choose preferred subscription from: $($matches.Name -join ', ')"
    }

    return $preferred
}
