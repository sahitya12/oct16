# Common.psm1
function Ensure-Dir {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
    return (Get-Item -LiteralPath $Path).FullName
}

function New-StampedPath {
    param(
        [Parameter(Mandatory)][string]$BaseDir,
        [Parameter(Mandatory)][string]$Prefix,
        [string]$Ext='csv'
    )

    $stamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
    Join-Path $BaseDir ("{0}_{1}.{2}" -f $Prefix, $stamp, $Ext)
}

function Write-CsvSafe {
    param(
        [Parameter(Mandatory)][object[]]$Rows,
        [Parameter(Mandatory)][string]$Path
    )

    if (-not $Rows -or $Rows.Count -eq 0) {
        "Info`nNo rows produced." | Out-File -FilePath $Path -Encoding UTF8
        return
    }

    $Rows | Export-Csv -NoTypeInformation -Path $Path -Encoding UTF8
}

function Convert-CsvToHtml {
    param(
        [Parameter(Mandatory)][string]$CsvPath,
        [Parameter(Mandatory)][string]$HtmlPath,
        [string]$Title="Report"
    )

    $rows = @(Import-Csv $CsvPath)
    $html = @()

    $html += "<html><head><meta charset='utf-8'><title>$Title</title>"
    $html += "<style>body{font-family:Segoe UI,Arial; font-size:12px} table{border-collapse:collapse} th,td{border:1px solid #ddd;padding:6px} th{background:#f3f3f3}</style></head><body>"
    $html += "<h3>$Title</h3>"

    if ($rows -and $rows.Count -gt 0) {

        # table header
        $html += "<table><tr>"
        foreach ($h in $rows[0].psobject.Properties.Name) {
            $html += "<th>$h</th>"
        }
        $html += "</tr>"

        # table rows
        foreach ($r in $rows) {
            $html += "<tr>"
            foreach ($h in $rows[0].psobject.Properties.Name) {
                $html += "<td>$($r.$h)</td>"
            }
            $html += "</tr>"
        }

        $html += "</table>"
    }
    else {
        $html += "<p><i>No rows.</i></p>"
    }

    $html += "</body></html>"

    # --- FIXED LINE (prevents RemainingScripts error) ---
    $content = $html -join [Environment]::NewLine
    $content | Out-File -FilePath $HtmlPath -Encoding UTF8
}

function Connect-ScAz {
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$ClientSecret
    )

    try {
        Import-Module Az.Accounts -ErrorAction Stop

        $sec  = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential($ClientId, $sec)

        Connect-AzAccount -ServicePrincipal -Tenant $TenantId -Credential $cred -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        Write-Warning "Connect-ScAz failed: $($_.Exception.Message)"
        return $false
    }
}

function Set-ScContext {
    param([Parameter(Mandatory)]$Subscription)

    try {
        Set-AzContext -SubscriptionId $Subscription.Id -ErrorAction Stop | Out-Null
    }
    catch {
        throw "Set-ScContext failed for sub '$($Subscription.Name)': $($_.Exception.Message)"
    }
}

function Resolve-ScSubscriptions {
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z]{2,}$')]
        [string]$AdhGroup,

        [Parameter()]
        [ValidateSet('nonprd','prd')]
        [string]$Environment='nonprd'
    )

    Import-Module Az.Accounts -ErrorAction Stop

    $g = $AdhGroup.Trim().ToUpperInvariant()
    $envPrefix = if ($Environment -eq 'prd') { 'prd_azure_' } else { 'dev_azure_' }

    $variants = New-Object System.Collections.Generic.List[string]

    if ($g -eq 'KTK') {
        $variants.Add('ADHPlatform')
    }
    else {
        $first = $g.Substring(0,1)
        $variants.Add("ADH$g")
        $variants.Add("ADH$first$g")
    }

    $subs = Get-AzSubscription
    $matches = @()

    foreach ($v in $variants) {
        $matches += $subs | Where-Object { $_.Name -like "$envPrefix*_*$v" }
    }

    $matches = $matches | Sort-Object Name -Unique

    if (-not $matches) {
        throw "Resolve-ScSubscriptions: no match for '$g' ($Environment)."
    }

    function Get-Rank([string]$name) {
        if ($g -eq 'KTK' -and $name -like "${envPrefix}*_ADHPlatform") { 0 }
        elseif ($name -like "${envPrefix}*_ADH$g") { 1 }
        elseif ($name -like "${envPrefix}*_ADH$($g.Substring(0,1))$g") { 2 }
        else { 9 }
    }

    $preferred = $matches |
        Sort-Object @{Expression={ Get-Rank $_.Name }}, @{Expression='Name'} |
        Select-Object -First 1

    ,$preferred
}

# Export EVERYTHING
Export-ModuleMember -Function *
