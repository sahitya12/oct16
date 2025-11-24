# sanitychecks/scripts/Scan-Databricks.ps1

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$TenantId,

    # IMPORTANT:
    # This parameter accepts BOTH -ClientId and -ApplicationId
    # because of the Alias. So any caller passing -ApplicationId
    # will still bind correctly and avoid NamedParameterNotFound.
    [Parameter(Mandatory)]
    [Alias('ApplicationId')]
    [string]$ClientId,

    [Parameter(Mandatory)]
    [string]$ClientSecret,

    [Parameter(Mandatory)]
    [string]$adh_group,

    [string]$adh_sub_group = '',

    [ValidateSet('nonprd','prd')]
    [string]$adh_subscription_type = 'nonprd',

    [Parameter(Mandatory)]
    [string]$OutputDir,

    [string]$BranchName = ''
)

# Normalise to one variable
$EffectiveClientId = $ClientId

Write-Host "INFO : Using EffectiveClientId = $EffectiveClientId" -ForegroundColor Cyan
Write-Host "DEBUG: Bound params = $($PSBoundParameters.Keys -join ', ')" -ForegroundColor Yellow

# -------------------------------------------------------
# Imports
# -------------------------------------------------------
Import-Module Az.Accounts, Az.Resources, Az.Databricks, Az.KeyVault -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'DatabricksHelper.psm1') -Force -ErrorAction Stop

# -------------------------------------------------------
# Prep: connect & derived values
# -------------------------------------------------------
$OutputDir = Ensure-Dir -Path $OutputDir

if (-not (Connect-ScAz -TenantId $TenantId -ClientId $EffectiveClientId -ClientSecret $ClientSecret)) {
    throw "Azure connection failed."
}

# Get SPN object id (info only)
$sp = Get-AzADServicePrincipal -ApplicationId $EffectiveClientId -ErrorAction Stop
$spObjectId = $sp.Id
Write-Host "INFO: Pipeline SPN ObjectId: $spObjectId" -ForegroundColor Cyan

# Custodian:
#   If adh_sub_group empty => Custodian = adh_group
#   Else                  => Custodian = adh_group_adh_sub_group
$Custodian = if ([string]::IsNullOrWhiteSpace($adh_sub_group)) {
    $adh_group
} else {
    "${adh_group}_${adh_sub_group}"
}

$envsToCheck = Get-DbEnvsForType -Environment $adh_subscription_type
$subs        = Resolve-DbSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type

Write-Host "INFO: Custodian = $Custodian" -ForegroundColor Cyan
Write-Host "INFO: Envs      = $($envsToCheck -join ', ')" -ForegroundColor Cyan
Write-Host "INFO: Subs      = $($subs.Name -join ', ')" -ForegroundColor Cyan

# -------------------------------------------------------
# Databricks AAD token (pipeline SPN)
# -------------------------------------------------------
# Azure Databricks resource ID (multi-tenant AAD app)
$databricksResourceId = "2ff814a6-3304-4ab8-85cb-cd0e6f879c1d"

# We call this $DatabricksPat to stay compatible with DatabricksHelper.psm1,
# but the value is actually an AAD access token.
$DatabricksPat = (Get-AzAccessToken -TenantId $TenantId `
                                   -ApplicationId $EffectiveClientId `
                                   -ResourceUrl $databricksResourceId).Token

if (-not $DatabricksPat) {
    throw "Failed to acquire Databricks AAD token for resource $databricksResourceId."
}

Write-Host "INFO: Databricks AAD token acquired (length: $($DatabricksPat.Length))" -ForegroundColor Cyan

# -------------------------------------------------------
# Result containers
# -------------------------------------------------------
$workspaceResults     = @()
$workspacePermResults = @()
$sqlWhResults         = @()
$sqlWhPermResults     = @()
$catalogListResults   = @()
$catalogPermResults   = @()
$extLocResults        = @()
$extLocPermResults    = @()

# -------------------------------------------------------
# Main scan
# -------------------------------------------------------
foreach ($sub in $subs) {

    Set-ScContext -Subscription $sub

    foreach ($env in $envsToCheck) {

        # KV names
        $keyVaultNameInfra = "ADH-$Custodian-Infra-KV-$env"
        $keyVaultNameCust  = "ADH-$Custodian-KV-$env"

        $workspaceName      = "ADH_${Custodian}_${env}"
        $workspaceUrl       = $null
        $workspaceId        = $null
        $DbSpnClientId      = $null
        $DbSpnClientSecret  = $null

        # -----------------------------------------------
        # Gen_SPN info from Custodian KV (for reporting)
        #   Secret name:        ADH_<Custodian>_Gen_SPN_<env>
        #   Secret name (pass): ADH_<Custodian>_Gen_SPN_<env>-Secret
        # -----------------------------------------------
        $genSpnBaseName = "ADH_{0}_Gen_SPN_{1}" -f $Custodian, $env

        try {
            $genSpnIdSecret = Get-AzKeyVaultSecret -VaultName $keyVaultNameCust -Name $genSpnBaseName -ErrorAction Stop
            $DbSpnClientId  = $genSpnIdSecret.SecretValueText
            Write-Host "INFO: Gen_SPN ClientId from '$keyVaultNameCust' ($env) name '$genSpnBaseName'" -ForegroundColor Cyan
        } catch {
            Write-Warning "Gen_SPN ClientId '$genSpnBaseName' not found in '$keyVaultNameCust' ($env): $_"
        }

        try {
            $genSpnSecretName = $genSpnBaseName + "-Secret"
            $genSpnSecret     = Get-AzKeyVaultSecret -VaultName $keyVaultNameCust -Name $genSpnSecretName -ErrorAction Stop
            $DbSpnClientSecret = $genSpnSecret.SecretValueText
            Write-Host ("INFO: Gen_SPN ClientSecret from '{0}' ({1}) name '{2}' (len={3})" -f $keyVaultNameCust, $env, $genSpnSecretName, $DbSpnClientSecret.Length) -ForegroundColor Cyan
        } catch {
            Write-Warning "Gen_SPN ClientSecret '$genSpnSecretName' not found in '$keyVaultNameCust' ($env): $_"
        }

        # -----------------------------------------------
        # Workspace URL and ID from Infra KV
        #   URL secret (correct):  DATABRICKS-WORKSPACE-URL
        #   URL secret (typo):     DATABRICKS-WORKSAPCE-URL
        #   ID secret (correct):   DATABRICKS-WORKSPACE-ID
        #   ID secret (typo):      DATABRICKS-WORKSAPCE-ID
        # -----------------------------------------------
        $urlSecretNameTidy   = "DATABRICKS-WORKSPACE-URL"
        $urlSecretNameTypos  = "DATABRICKS-WORKSAPCE-URL"
        $idSecretNameTidy    = "DATABRICKS-WORKSPACE-ID"
        $idSecretNameTypos   = "DATABRICKS-WORKSAPCE-ID"

        # URL
        try {
            $wsUrlSecret  = Get-AzKeyVaultSecret -VaultName $keyVaultNameInfra -Name $urlSecretNameTidy -ErrorAction Stop
            $workspaceUrl = $wsUrlSecret.SecretValueText
            if ($workspaceUrl) {
                Write-Host "DEBUG: URL from '$keyVaultNameInfra' ($env) using '$urlSecretNameTidy' -> [$workspaceUrl]" -ForegroundColor Yellow
            }
        } catch {
            Write-Warning "URL secret '$urlSecretNameTidy' not found in '$keyVaultNameInfra' ($env): $_"
            try {
                $wsUrlSecret  = Get-AzKeyVaultSecret -VaultName $keyVaultNameInfra -Name $urlSecretNameTypos -ErrorAction Stop
                $workspaceUrl = $wsUrlSecret.SecretValueText
                if ($workspaceUrl) {
                    Write-Host "DEBUG: URL from '$keyVaultNameInfra' ($env) using '$urlSecretNameTypos' -> [$workspaceUrl]" -ForegroundColor Yellow
                }
            } catch {
                Write-Warning "URL secret '$urlSecretNameTypos' not found in '$keyVaultNameInfra' ($env) as well: $_"
            }
        }

        # ID
        try {
            $wsIdSecret  = Get-AzKeyVaultSecret -VaultName $keyVaultNameInfra -Name $idSecretNameTidy -ErrorAction Stop
            $workspaceId = $wsIdSecret.SecretValueText
        } catch {
            Write-Warning "ID secret '$idSecretNameTidy' not found in '$keyVaultNameInfra' ($env): $_"
            try {
                $wsIdSecret  = Get-AzKeyVaultSecret -VaultName $keyVaultNameInfra -Name $idSecretNameTypos -ErrorAction Stop
                $workspaceId = $wsIdSecret.SecretValueText
            } catch {
                Write-Warning "ID secret '$idSecretNameTypos' not found in '$keyVaultNameInfra' ($env) as well: $_"
            }
        }

        # -----------------------------------------------
        # Workspace state rows
        # -----------------------------------------------
        if ($null -eq $wsUrlSecret) {
            # Secret never found at all
            $workspaceResults += [pscustomobject]@{
                SubscriptionName   = $sub.Name
                SubscriptionId     = $sub.Id
                Env                = $env
                WorkspaceName      = $workspaceName
                WorkspaceId        = $workspaceId
                WorkspaceUrl       = ''
                State              = 'UrlSecretNotFound'
                KeyVaultNameInfra  = $keyVaultNameInfra
                KeyVaultNameCust   = $keyVaultNameCust
                GenSpnClientId     = $DbSpnClientId
                adh_group          = $adh_group
                adh_sub_group      = $adh_sub_group
                BranchName         = $BranchName
            }
            Write-Warning "Workspace URL secret not found for '$workspaceName' ($env) in '$keyVaultNameInfra' – skipping Databricks API calls."
            continue
        }

        if ([string]::IsNullOrWhiteSpace($workspaceUrl)) {
            # Secret exists but empty / whitespace
            $workspaceResults += [pscustomobject]@{
                SubscriptionName   = $sub.Name
                SubscriptionId     = $sub.Id
                Env                = $env
                WorkspaceName      = $workspaceName
                WorkspaceId        = $workspaceId
                WorkspaceUrl       = ''
                State              = 'EmptyUrlInKeyVault'
                KeyVaultNameInfra  = $keyVaultNameInfra
                KeyVaultNameCust   = $keyVaultNameCust
                GenSpnClientId     = $DbSpnClientId
                adh_group          = $adh_group
                adh_sub_group      = $adh_sub_group
                BranchName         = $BranchName
            }
            Write-Warning "Workspace URL is empty/whitespace for '$workspaceName' ($env) in '$keyVaultNameInfra' – skipping Databricks API calls."
            continue
        }

        # Non-empty URL => configured, proceed with Databricks API
        $workspaceResults += [pscustomobject]@{
            SubscriptionName   = $sub.Name
            SubscriptionId     = $sub.Id
            Env                = $env
            WorkspaceName      = $workspaceName
            WorkspaceId        = $workspaceId
            WorkspaceUrl       = $workspaceUrl
            State              = 'ConfiguredInKeyVault'
            KeyVaultNameInfra  = $keyVaultNameInfra
            KeyVaultNameCust   = $keyVaultNameCust
            GenSpnClientId     = $DbSpnClientId
            adh_group          = $adh_group
            adh_sub_group      = $adh_sub_group
            BranchName         = $BranchName
        }

        # ---------------------------------------------------
        # Databricks Workspace Permissions
        # ---------------------------------------------------
        try {
            $perm = Get-DbWorkspacePermissions -WorkspaceUrl $workspaceUrl -DatabricksPat $DatabricksPat
            foreach ($ace in $perm.access_control_list) {
                $principalName = $ace.user_name ?? $ace.group_name ?? $ace.service_principal_name
                $principalType = if ($ace.user_name) { 'user' }
                                 elseif ($ace.group_name) { 'group' }
                                 else { 'service_principal' }
                foreach ($p in $ace.all_permissions) {
                    $workspacePermResults += [pscustomobject]@{
                        SubscriptionName = $sub.Name
                        SubscriptionId   = $sub.Id
                        Env              = $env
                        WorkspaceName    = $workspaceName
                        PrincipalType    = $principalType
                        PrincipalName    = $principalName
                        PermissionLevel  = $p.permission_level
                        Inherited        = $p.inherited
                        adh_group        = $adh_group
                        adh_sub_group    = $adh_sub_group
                    }
                }
            }
        } catch {
            Write-Warning "Failed to fetch workspace permissions for '$workspaceName' ($env): $_"
        }

        # ---------------------------------------------------
        # SQL Warehouses & Permissions
        # ---------------------------------------------------
        try {
            $whs = Get-DbWarehouses -WorkspaceUrl $workspaceUrl -DatabricksPat $DatabricksPat
            foreach ($wh in $whs.warehouses) {
                $sqlWhResults += [pscustomobject]@{
                    SubscriptionName = $sub.Name
                    SubscriptionId   = $sub.Id
                    Env              = $env
                    WorkspaceName    = $workspaceName
                    WarehouseId      = $wh.id
                    WarehouseName    = $wh.name
                    ClusterSize      = $wh.cluster_size
                    State            = $wh.state
                    AutoStopMinutes  = $wh.auto_stop_mins
                    Tags             = ($wh.tags | ConvertTo-Json -Compress)
                    adh_group        = $adh_group
                    adh_sub_group    = $adh_sub_group
                }

                try {
                    $permWh = Get-DbWarehousePermissions -WorkspaceUrl $workspaceUrl -WarehouseId $wh.id -DatabricksPat $DatabricksPat
                    foreach ($ace in $permWh.access_control_list) {
                        $principalName = $ace.user_name ?? $ace.group_name ?? $ace.service_principal_name
                        $principalType = if ($ace.user_name) { 'user' }
                                         elseif ($ace.group_name) { 'group' }
                                         else { 'service_principal' }
                        foreach ($p in $ace.all_permissions) {
                            $sqlWhPermResults += [pscustomobject]@{
                                SubscriptionName = $sub.Name
                                SubscriptionId   = $sub.Id
                                Env              = $env
                                WorkspaceName    = $workspaceName
                                WarehouseId      = $wh.id
                                WarehouseName    = $wh.name
                                PrincipalType    = $principalType
                                PrincipalName    = $principalName
                                PermissionLevel  = $p.permission_level
                                Inherited        = $p.inherited
                                adh_group        = $adh_group
                                adh_sub_group    = $adh_sub_group
                            }
                        }
                    }
                } catch {
                    Write-Warning "Failed to fetch warehouse permissions for '$($wh.name)' ($env): $_"
                }
            }
        } catch {
            Write-Warning "Failed to list SQL warehouses for '$workspaceName' ($env): $_"
        }

        # ---------------------------------------------------
        # Catalogs & Permissions
        # ---------------------------------------------------
        try {
            $cats = Get-DbCatalogsList -WorkspaceUrl $workspaceUrl -DatabricksPat $DatabricksPat
            foreach ($cat in $cats.catalogs) {
                $catalogListResults += [pscustomobject]@{
                    SubscriptionName = $sub.Name
                    SubscriptionId   = $sub.Id
                    Env              = $env
                    WorkspaceName    = $workspaceName
                    CatalogName      = $cat.name
                    CatalogType      = $cat.catalog_type
                    Comment          = $cat.comment
                    Properties       = ($cat.properties | ConvertTo-Json -Compress)
                    adh_group        = $adh_group
                    adh_sub_group    = $adh_sub_group
                }

                try {
                    $permCat = Get-DbCatalogPermissions -WorkspaceUrl $workspaceUrl -CatalogName $cat.name -DatabricksPat $DatabricksPat
                    foreach ($entry in $permCat.privilege_assignments) {
                        $catalogPermResults += [pscustomobject]@{
                            SubscriptionName = $sub.Name
                            SubscriptionId   = $sub.Id
                            Env              = $env
                            WorkspaceName    = $workspaceName
                            CatalogName      = $cat.name
                            PrincipalName    = $entry.principal
                            Privileges       = ($entry.privileges -join ',')
                            adh_group        = $adh_group
                            adh_sub_group    = $adh_sub_group
                        }
                    }
                } catch {
                    Write-Warning "Failed to fetch catalog permissions for '$($cat.name)' ($env): $_"
                }
            }
        } catch {
            Write-Warning "Failed to list catalogs for '$workspaceName' ($env): $_"
        }

        # ---------------------------------------------------
        # External Locations & Permissions
        # ---------------------------------------------------
        try {
            $extLocs = Get-DbExternalLocationsList -WorkspaceUrl $workspaceUrl -DatabricksPat $DatabricksPat
            foreach ($loc in $extLocs.external_locations) {
                $extLocResults += [pscustomobject]@{
                    SubscriptionName = $sub.Name
                    SubscriptionId   = $sub.Id
                    Env              = $env
                    WorkspaceName    = $workspaceName
                    ExternalLocation = $loc.name
                    Url              = $loc.url
                    CredentialName   = $loc.credential_name
                    Comment          = $loc.comment
                    adh_group        = $adh_group
                    adh_sub_group    = $adh_sub_group
                }

                try {
                    $permLoc = Get-DbExternalLocationPermissions -WorkspaceUrl $workspaceUrl -Name $loc.name -DatabricksPat $DatabricksPat
                    foreach ($entry in $permLoc.privilege_assignments) {
                        $extLocPermResults += [pscustomobject]@{
                            SubscriptionName  = $sub.Name
                            SubscriptionId    = $sub.Id
                            Env               = $env
                            WorkspaceName     = $workspaceName
                            ExternalLocation  = $loc.name
                            PrincipalName     = $entry.principal
                            Privileges        = ($entry.privileges -join ',')
                            adh_group         = $adh_group
                            adh_sub_group     = $adh_sub_group
                        }
                    }
                } catch {
                    Write-Warning "Failed to fetch external location permissions for '$($loc.name)' ($env): $_"
                }
            }
        } catch {
            Write-Warning "Failed to list external locations for '$workspaceName' ($env): $_"
        }
    }
}

# -------------------------------------------------------
# Export Data
# -------------------------------------------------------
$csvWs       = $null
$csvWsPerm   = $null
$csvWh       = $null
$csvWhPerm   = $null
$csvCatList  = $null
$csvCatPerm  = $null
$csvExt      = $null
$csvExtPerm  = $null

if ($workspaceResults.Count -gt 0) {
    $csvWs = New-StampedPath -BaseDir $OutputDir -Prefix ("db_ws_{0}_{1}" -f $adh_group, $adh_subscription_type)
    Write-CsvSafe -Rows $workspaceResults -Path $csvWs
    Convert-CsvToHtml -CsvPath $csvWs -HtmlPath ($csvWs -replace '.csv$', '.html') -Title "Databricks Workspaces ($adh_group / $adh_subscription_type) $BranchName"
} else {
    Write-Warning "No workspace results collected – skipping workspace CSV export."
}

if ($workspacePermResults.Count -gt 0) {
    $csvWsPerm = New-StampedPath -BaseDir $OutputDir -Prefix ("db_ws_perms_{0}_{1}" -f $adh_group, $adh_subscription_type)
    Write-CsvSafe -Rows $workspacePermResults -Path $csvWsPerm
}

if ($sqlWhResults.Count -gt 0) {
    $csvWh = New-StampedPath -BaseDir $OutputDir -Prefix ("db_sqlwh_{0}_{1}" -f $adh_group, $adh_subscription_type)
    Write-CsvSafe -Rows $sqlWhResults -Path $csvWh
}

if ($sqlWhPermResults.Count -gt 0) {
    $csvWhPerm = New-StampedPath -BaseDir $OutputDir -Prefix ("db_sqlwh_perms_{0}_{1}" -f $adh_group, $adh_subscription_type)
    Write-CsvSafe -Rows $sqlWhPermResults -Path $csvWhPerm
}

if ($catalogListResults.Count -gt 0) {
    $csvCatList = New-StampedPath -BaseDir $OutputDir -Prefix ("db_catalogs_{0}_{1}" -f $adh_group, $adh_subscription_type)
    Write-CsvSafe -Rows $catalogListResults -Path $csvCatList
}

if ($catalogPermResults.Count -gt 0) {
    $csvCatPerm = New-StampedPath -BaseDir $OutputDir -Prefix ("db_catalog_perms_{0}_{1}" -f $adh_group, $adh_subscription_type)
    Write-CsvSafe -Rows $catalogPermResults -Path $csvCatPerm
}

if ($extLocResults.Count -gt 0) {
    $csvExt = New-StampedPath -BaseDir $OutputDir -Prefix ("db_extloc_{0}_{1}" -f $adh_group, $adh_subscription_type)
    Write-CsvSafe -Rows $extLocResults -Path $csvExt
}

if ($extLocPermResults.Count -gt 0) {
    $csvExtPerm = New-StampedPath -BaseDir $OutputDir -Prefix ("db_extloc_perms_{0}_{1}" -f $adh_group, $adh_subscription_type)
    Write-CsvSafe -Rows $extLocPermResults -Path $csvExtPerm
}

Write-Host "Databricks inventory scan completed." -ForegroundColor Green

if ($csvWs)      { Write-Host "Workspace CSV           : $csvWs" }
if ($csvWsPerm)  { Write-Host "Workspace perms CSV     : $csvWsPerm" }
if ($csvWh)      { Write-Host "SQL Warehouses CSV      : $csvWh" }
if ($csvWhPerm)  { Write-Host "SQL Warehouse perms CSV : $csvWhPerm" }
if ($csvCatList) { Write-Host "Catalog list CSV        : $csvCatList" }
if ($csvCatPerm) { Write-Host "Catalog perms CSV       : $csvCatPerm" }
if ($csvExt)     { Write-Host "External locations CSV  : $csvExt" }
if ($csvExtPerm) { Write-Host "Ext loc perms CSV       : $csvExtPerm" }
