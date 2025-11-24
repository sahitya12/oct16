# sanitychecks/scripts/DatabricksHelper.psm1

# --------------------------
# Subscription & name helpers
# --------------------------

function Resolve-DbSubscriptions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$AdhGroup,
        [ValidateSet('nonprd','prd')][string]$Environment = 'nonprd'
    )

    Import-Module Az.Accounts -ErrorAction Stop

    $g       = $AdhGroup.Trim().ToUpperInvariant()
    $allSubs = Get-AzSubscription

    switch ($g) {
        'KTK' {
            if ($Environment -eq 'nonprd') {
                return ,($allSubs | Where-Object { $_.Name -eq 'dev_azure_20401_ADHPlatform' })
            } else {
                throw "No PRD subscription mapping defined for KTK."
            }
        }
        'MDM' {
            if ($Environment -eq 'nonprd') {
                return ,($allSubs | Where-Object { $_.Name -eq 'dev_azure_20911_ADHMDM' })
            } else {
                return ,($allSubs | Where-Object { $_.Name -eq 'prd_azure_20910_ADHMDM' })
            }
        }
        'NHH' {
            if ($Environment -eq 'nonprd') {
                return ,($allSubs | Where-Object { $_.Name -eq 'dev_azure_21001_ADHNHH' })
            } else {
                return ,($allSubs | Where-Object { $_.Name -eq 'prd_azure_21000_ADHNHH' })
            }
        }
        Default {
            $envPrefix = if ($Environment -eq 'prd') { 'prd_azure_' } else { 'dev_azure_' }
            $suffix    = "_ADH$g"

            $subs = $allSubs | Where-Object { $_.Name -like "${envPrefix}*${suffix}" }
            if (-not $subs) {
                throw "No subscriptions found for adh_group '$g' with default pattern."
            }
            return ,$subs
        }
    }
}

function Get-DbWorkspaceNames {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$AdhGroup,
        [ValidateSet('nonprd','prd')][string]$Environment = 'nonprd'
    )

    $g    = $AdhGroup.Trim().ToUpperInvariant()
    $base = "ADH_$g"

    if ($Environment -eq 'prd') {
        return @("${base}_prd")
    } else {
        return @("${base}_dev", "${base}_tst", "${base}_stg")
    }
}

function Get-DbEnvsForType {
    [CmdletBinding()]
    param(
        [ValidateSet('nonprd','prd')][string]$Environment = 'nonprd'
    )

    if ($Environment -eq 'prd') {
        @('prd')
    } else {
        @('dev','tst','stg')
    }
}

# --------------------------
# Databricks REST helpers (AAD token)
# --------------------------

function Invoke-DbApi {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WorkspaceUrl,
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$Path,
        [object]$Body = $null,
        [Parameter(Mandatory)][string]$AccessToken
    )

    if ([string]::IsNullOrWhiteSpace($WorkspaceUrl)) {
        throw "WorkspaceUrl is null or empty in Invoke-DbApi."
    }

    # Normalise URL (no trailing slash)
    $baseUrl = $WorkspaceUrl.TrimEnd('/')

    $uri     = "$baseUrl/api/2.0/$Path"
    $headers = @{
        Authorization = "Bearer $AccessToken"
    }

    if ($Body -ne $null) {
        $json = $Body | ConvertTo-Json -Depth 10
        return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers -Body $json -ContentType 'application/json'
    } else {
        return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers
    }
}

# Workspace permissions
function Get-DbWorkspacePermissions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WorkspaceUrl,
        [Parameter(Mandatory)][string]$AccessToken
    )
    Invoke-DbApi -WorkspaceUrl $WorkspaceUrl -Method GET -Path 'permissions/workspace' -Body $null -AccessToken $AccessToken
}

# (Clusters kept for future use)
function Get-DbClusters {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WorkspaceUrl,
        [Parameter(Mandatory)][string]$AccessToken
    )
    Invoke-DbApi -WorkspaceUrl $WorkspaceUrl -Method GET -Path 'clusters/list' -Body $null -AccessToken $AccessToken
}

function Get-DbClusterPermissions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WorkspaceUrl,
        [Parameter(Mandatory)][string]$ClusterId,
        [Parameter(Mandatory)][string]$AccessToken
    )
    $path = "permissions/clusters/$ClusterId"
    Invoke-DbApi -WorkspaceUrl $WorkspaceUrl -Method GET -Path $path -Body $null -AccessToken $AccessToken
}

# SQL warehouses
function Get-DbWarehouses {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WorkspaceUrl,
        [Parameter(Mandatory)][string]$AccessToken
    )
    Invoke-DbApi -WorkspaceUrl $WorkspaceUrl -Method GET -Path 'sql/warehouses' -Body $null -AccessToken $AccessToken
}

function Get-DbWarehousePermissions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WorkspaceUrl,
        [Parameter(Mandatory)][string]$WarehouseId,
        [Parameter(Mandatory)][string]$AccessToken
    )
    $path = "permissions/sql/warehouses/$WarehouseId"
    Invoke-DbApi -WorkspaceUrl $WorkspaceUrl -Method GET -Path $path -Body $null -AccessToken $AccessToken
}

# Unity Catalog – catalog list + permissions
function Get-DbCatalogsList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WorkspaceUrl,
        [Parameter(Mandatory)][string]$AccessToken
    )
    Invoke-DbApi -WorkspaceUrl $WorkspaceUrl -Method GET -Path 'unity-catalog/catalogs' -Body $null -AccessToken $AccessToken
}

function Get-DbCatalogPermissions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WorkspaceUrl,
        [Parameter(Mandatory)][string]$CatalogName,
        [Parameter(Mandatory)][string]$AccessToken
    )
    $path = "unity-catalog/permissions/catalogs/$CatalogName"
    Invoke-DbApi -WorkspaceUrl $WorkspaceUrl -Method GET -Path $path -Body $null -AccessToken $AccessToken
}

# External locations list + permissions
function Get-DbExternalLocationsList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WorkspaceUrl,
        [Parameter(Mandatory)][string]$AccessToken
    )
    Invoke-DbApi -WorkspaceUrl $WorkspaceUrl -Method GET -Path 'unity-catalog/external-locations' -Body $null -AccessToken $AccessToken
}

function Get-DbExternalLocationPermissions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WorkspaceUrl,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$AccessToken
    )
    $path = "unity-catalog/permissions/external-locations/$Name"
    Invoke-DbApi -WorkspaceUrl $WorkspaceUrl -Method GET -Path $path -Body $null -AccessToken $AccessToken
}

Export-ModuleMember -Function *
