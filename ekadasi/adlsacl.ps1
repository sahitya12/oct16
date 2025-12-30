# =====================================================================
# Scan-ADLS-Acls.ps1
# ADLS Gen2 ACL validator (pipeline-safe, production-ready)
# =====================================================================

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$ClientId,
    [Parameter(Mandatory)][string]$ClientSecret,

    [Parameter(Mandatory)][string]$adh_group,
    [string]$adh_sub_group = '',

    [ValidateSet('nonprd','prd')]
    [string]$adh_subscription_type = 'nonprd',

    [Parameter(Mandatory)][string]$InputCsvPath,
    [Parameter(Mandatory)][string]$OutputDir,

    # 👇 Needed ONLY because ADO pipeline passes it
    [string]$BranchName = '',

    [switch]$DebugAcls
)

# ===================== Modules =====================
Import-Module Az.Accounts, Az.Resources, Az.Storage -ErrorAction Stop

# ===================== Helpers =====================
function Ensure-Dir($p) {
    if (-not (Test-Path $p)) {
        New-Item -ItemType Directory -Path $p -Force | Out-Null
    }
}

function Write-CsvSafe($rows, $path) {
    Ensure-Dir (Split-Path $path -Parent)
    $rows | Export-Csv -NoTypeInformation -Encoding UTF8 -Force -Path $path
}

function Connect-Azure {
    $sec  = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
    $cred = New-Object pscredential($ClientId,$sec)
    Connect-AzAccount -ServicePrincipal -Tenant $TenantId -Credential $cred -ErrorAction Stop | Out-Null
}

function Get-GraphToken {
    $body = @{
        client_id     = $ClientId
        client_secret = $ClientSecret
        grant_type    = "client_credentials"
        scope         = "https://graph.microsoft.com/.default"
    }
    (Invoke-RestMethod -Method Post `
        -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
        -Body $body `
        -ContentType "application/x-www-form-urlencoded").access_token
}

function Resolve-IdentityObjectId {
    param($Name)

    # Accept GUID directly
    $g=[ref]([guid]::Empty)
    if ([guid]::TryParse($Name,$g)) { return $Name }

    if (-not $script:GraphToken) { return $null }

    # Service Principal
    $spUri="https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=displayName eq '$Name'&`$select=id"
    try {
        $r=Invoke-RestMethod -Headers @{Authorization="Bearer $script:GraphToken"} -Uri $spUri
        if ($r.value.Count -eq 1) { return $r.value[0].id }
    } catch {}

    # Group
    $gUri="https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$Name'&`$select=id"
    try {
        $r=Invoke-RestMethod -Headers @{Authorization="Bearer $script:GraphToken"} -Uri $gUri
        if ($r.value.Count -eq 1) { return $r.value[0].id }
    } catch {}

    return $null
}

function Perm-Ok($acePerm,$want) {
    switch ($want) {
        'r-x' { $acePerm -in @('r-x','rwx') }
        'rwx' { $acePerm -eq 'rwx' }
        'r--' { $acePerm[0] -eq 'r' }
        default { $acePerm -eq $want }
    }
}

function Get-PathsToCheck($p) {
    if (-not $p -or $p -eq '/') { return @('') }
    $p=$p.Trim('/'); $parts=$p.Split('/')
    $list=@()
    for($i=$parts.Count;$i-ge 1;$i--){ $list+=($parts[0..($i-1)] -join '/') }
    $list+=''
    return $list
}

function Read-Acls($fs,$ctx,$path) {
    $h=@{FileSystem=$fs;Context=$ctx;ErrorAction='Stop'}
    if ($path) { $h.Path=$path }
    $i=Get-AzDataLakeGen2Item @h
    @($i.Acl + $i.DefaultAcl)
}

# ===================== Start =====================
Write-Host "BranchName = $BranchName"
Ensure-Dir $OutputDir
Connect-Azure
$script:GraphToken = Get-GraphToken

$rows = Import-Csv $InputCsvPath
$out  = @()

$subs = Get-AzSubscription
foreach ($sub in $subs) {

    Set-AzContext -SubscriptionId $sub.Id | Out-Null

    foreach ($r in $rows) {

        $rg  = $r.ResourceGroupName.Replace('<Custodian>',$adh_group)
        $sa  = $r.StorageAccountName.Replace('<Custodian>',$adh_group)
        $ct  = $r.ContainerName
        $ids = $r.Identity.Split(',') | %{$_.Trim()}
        $perm= $r.PermissionType
        $path= $r.AccessPath.Trim('/')
        $paths = Get-PathsToCheck $path

        try {
            $ctx=(Get-AzStorageAccount -RG $rg -Name $sa).Context
            Get-AzStorageContainer -Name $ct -Context $ctx | Out-Null
        } catch { continue }

        foreach ($idn in $ids) {

            $oid = Resolve-IdentityObjectId $idn
            if (-not $oid) {
                $out+=[pscustomobject]@{
                    Subscription=$sub.Name;ResourceGroup=$rg;Storage=$sa;Container=$ct
                    Folder="/$path";Identity=$idn;Permission=$perm
                    Status='UNRESOLVED_IDENTITY';Notes='Cannot resolve Entra objectId'
                }
                continue
            }

            $found=$false
            foreach ($p in $paths) {
                foreach ($ace in Read-Acls $ct $ctx $p) {
                    if ($ace.EntityId -eq $oid -and (Perm-Ok $ace.Permissions $perm)) {
                        $found=$true; break
                    }
                }
                if ($found) { break }
            }

            $out+=[pscustomobject]@{
                Subscription=$sub.Name;ResourceGroup=$rg;Storage=$sa;Container=$ct
                Folder="/$path";Identity=$idn;Permission=$perm
                Status=($(if($found){'OK'}else{'MISSING'}))
                Notes=($(if($found){'ACL satisfied'}else{'No matching ACL entry found on folder, parents, or root'}))
            }
        }
    }
}

$csv = Join-Path $OutputDir ("adls_acl_{0}_{1}_{2}.csv" -f $adh_group,$adh_subscription_type,(Get-Date -f yyyyMMdd))
Write-CsvSafe $out $csv
Write-Host "ACL validation completed: $csv"
exit 0
