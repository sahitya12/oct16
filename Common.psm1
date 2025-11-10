# Common.psm1

function Connect-ScAz {
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$ClientSecret
    )
    $sec = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
    $cred = [pscredential]::new($ClientId, $sec)
    Connect-AzAccount -ServicePrincipal -Tenant $TenantId -Credential $cred -ErrorAction Stop | Out-Null
}

function Get-ScSubscriptions {
    <#
      .SYNOPSIS
        Returns subscriptions filtered to ADH and optionally to one custodian and environment.
      .PARAMETER AdhGroup
        Custodian short code, e.g. KTK, NHH, etc. (optional -> returns all ADH subs)
      .PARAMETER Environment
        'nonprd' or 'prd'. If omitted, both are returned.
    #>
    param(
        [string]$AdhGroup,
        [ValidateSet('nonprd','prd')][string]$Environment
    )
    $all = Get-AzSubscription | Where-Object { $_.Name -match 'ADH' }

    if ($AdhGroup) {
        $all = $all | Where-Object { $_.Name -match "(?i)ADH$AdhGroup" }
    }

    if ($Environment) {
        if ($Environment -eq 'prd') {
            $all = $all | Where-Object { $_.Name -match '(?i)(prod|prd)' }
        } else {
            $all = $all | Where-Object { $_.Name -match '(?i)(nonprod|nonprd|dev|test|qa|stg)' }
        }
    }
    return $all
}

function Ensure-Dir {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function New-StampedPath {
    param(
        [Parameter(Mandatory)][string]$BaseDir,
        [Parameter(Mandatory)][string]$Prefix,
        [string]$Ext = 'csv'
    )
    Ensure-Dir -Path $BaseDir
    $stamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
    Join-Path $BaseDir "$Prefix`_$stamp.$Ext"
}

function Write-CsvSafe {
    param(
        [Parameter(Mandatory)][object[]]$Rows,
        [Parameter(Mandatory)][string]$Path
    )
    if ($Rows -and $Rows.Count -gt 0) {
        $Rows | Export-Csv -NoTypeInformation -Path $Path -Encoding UTF8
    } else {
        # write an empty CSV with a single header to avoid artifact being empty
        "NoData" | ConvertTo-Csv -NoTypeInformation | Set-Content -Path $Path -Encoding UTF8
    }
}

function Convert-CsvToHtml {
    param(
        [Parameter(Mandatory)][string]$CsvPath,
        [Parameter(Mandatory)][string]$HtmlPath,
        [string]$Title = 'Report'
    )
    $dt = Import-Csv -Path $CsvPath
    $html = $dt | ConvertTo-Html -Title $Title -PreContent "<h2>$Title</h2>" |
        Out-String
    Set-Content -Path $HtmlPath -Value $html -Encoding UTF8
}

Export-ModuleMember -Function Connect-ScAz,Get-ScSubscriptions,Ensure-Dir,New-StampedPath,Write-CsvSafe,Convert-CsvToHtml
