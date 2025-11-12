function Ensure-Dir {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Force -Path $Path | Out-Null
    }
    return (Resolve-Path $Path).Path
}

function Write-CsvSafe {
    param(
        [Parameter(Mandatory)][array]$Rows,
        [Parameter(Mandatory)][string]$Path
    )
    if ($Rows.Count -gt 0) {
        $Rows | Export-Csv -Path $Path -NoTypeInformation -Force -Encoding UTF8
    } else {
        @() | Export-Csv -Path $Path -NoTypeInformation -Force -Encoding UTF8
    }
}

function New-StampedPath {
    param(
        [Parameter(Mandatory)][string]$BaseDir,
        [Parameter(Mandatory)][string]$Prefix,
        [string]$Ext = 'csv'
    )
    $timestamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
    return Join-Path $BaseDir "$Prefix-$timestamp.$Ext"
}

function Convert-CsvToHtml {
    param(
        [Parameter(Mandatory)][string]$CsvPath,
        [Parameter(Mandatory)][string]$HtmlPath,
        [Parameter(Mandatory)][string]$Title
    )
    $rows = Import-Csv $CsvPath
    $html = "<html><head><title>$Title</title>
    <style>table{border-collapse:collapse;width:100%;}th,td{border:1px solid #ccc;padding:5px;text-align:left;}</style>
    </head><body><h2>$Title</h2><table><tr>"
    foreach ($col in $rows[0].PSObject.Properties.Name) {
        $html += "<th>$col</th>"
    }
    $html += "</tr>"
    foreach ($row in $rows) {
        $html += "<tr>"
        foreach ($col in $rows[0].PSObject.Properties.Name) {
            $html += "<td>$($row.$col)</td>"
        }
        $html += "</tr>"
    }
    $html += "</table></body></html>"
    Set-Content -Path $HtmlPath -Value $html -Encoding UTF8
}

function Connect-ScAz {
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$ClientSecret
    )
    Write-Host "🔐 Connecting to Azure using Service Principal..."
    Connect-AzAccount -Tenant $TenantId -ServicePrincipal -Credential (New-Object System.Management.Automation.PSCredential($ClientId,(ConvertTo-SecureString $ClientSecret -AsPlainText -Force))) | Out-Null
}

function Resolve-ScSubscriptions {
    param(
        [Parameter(Mandatory)][string]$AdhGroup,
        [Parameter(Mandatory)][string]$Environment
    )
    Write-Host "Fetching subscriptions for $AdhGroup / $Environment..."
    # Replace with your logic or static mapping
    Get-AzSubscription | Where-Object { $_.Name -like "*$AdhGroup*" -and $_.Name -like "*$Environment*" }
}

function Set-ScContext {
    param([Parameter(Mandatory)][object]$Subscription)
    Set-AzContext -SubscriptionId $Subscription.Id | Out-Null
}
