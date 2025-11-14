param(
  [Parameter(Mandatory)][string]$TenantId,
  [Parameter(Mandatory)][string]$ClientId,
  [Parameter(Mandatory)][string]$ClientSecret,
  [Parameter(Mandatory)][string]$adh_group,
  [ValidateSet('nonprd','prd')][string]$adh_subscription_type = 'nonprd',
  [Parameter(Mandatory)][string]$InputCsvPath,
  [Parameter(Mandatory)][string]$OutputDir,
  [string]$BranchName = ''
)

Import-Module Az.Accounts, Az.Resources, Az.Storage -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -ErrorAction Stop

Ensure-Dir -Path $OutputDir | Out-Null

if (-not (Test-Path -LiteralPath $InputCsvPath)) {
  throw "ADLS CSV not found: $InputCsvPath"
}

$rows = Import-Csv -LiteralPath $InputCsvPath

# Connect using your helper
try {
  Connect-ScAz -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
} catch {
  throw "Azure connection failed: $($_.Exception.Message)"
}

# ---------------------------------------------------------
# Local helper: cache + resolve CSV Identity name -> ObjectId
# ---------------------------------------------------------
$script:IdentityCache = @{}

function Resolve-IdentityObjectId {
  param(
    [Parameter(Mandatory)][string]$IdentityName
  )

  if ($script:IdentityCache.ContainsKey($IdentityName)) {
    return $script:IdentityCache[$IdentityName]
  }

  $id = $null

  # Try as group display name
  try {
    $grp = Get-AzADGroup -DisplayName $IdentityName -ErrorAction Stop
    if ($grp -and $grp.Id) { $id = $grp.Id }
  } catch {}

  # Try as service principal display name
  if (-not $id) {
    try {
      $sp = Get-AzADServicePrincipal -DisplayName $IdentityName -ErrorAction Stop
      if ($sp -and $sp.Id) { $id = $sp.Id }
    } catch {}
  }

  # Try as service principal search string (fallback)
  if (-not $id) {
    try {
      $sp2 = Get-AzADServicePrincipal -SearchString $IdentityName -ErrorAction Stop
      if ($sp2 -and $sp2.Count -ge 1) { $id = $sp2[0].Id }
    } catch {}
  }

  # If IdentityName is already a GUID, accept it
  if (-not $id) {
    $guidRef = [ref]([Guid]::Empty)
    if ([Guid]::TryParse($IdentityName, $guidRef)) {
      $id = $IdentityName
    }
  }

  $script:IdentityCache[$IdentityName] = $id
  return $id
}

# ---------------------------------------------------------
# Resolve subscriptions using your Resolve-AdhSubscriptions
# ---------------------------------------------------------
$subs = Resolve-AdhSubscriptions -AdhGroup $adh_group -Environment $adh_subscription_type
if ($subs -isnot [System.Collections.IEnumerable]) { $subs = ,$subs }

$out = @()

foreach ($sub in $subs) {

  Set-AzContext -SubscriptionId $sub.Id -ErrorAction Stop | Out-Null

  foreach ($r in $rows) {

    # INPUT CSV must have:
    #   ResourceGroupName, ContainerName, AccessPath, Identity, PermissionType
    $rgNameRaw    = $r.ResourceGroupName
    $contRaw      = $r.ContainerName
    $accessPath   = $r.AccessPath
    $identityName = $r.Identity
    $permType     = $r.PermissionType   # e.g. r-x, rwx

    # Expand placeholders if present
    $rgName        = ($rgNameRaw    -replace '<Custodian>', $adh_group)
    $cont          = ($contRaw      -replace '<Cust>',      $adh_group.ToLower())
    $identityName  = ($identityName -replace '<Custodian>', $adh_group)

    # Storage account naming pattern as you used earlier
    $saName = "adh$($adh_group.ToLower())adls$($adh_subscription_type.ToLower())"

    # --------------------------------
    # 1. Storage Account existence
    # --------------------------------
    try {
      $sa = Get-AzStorageAccount -ResourceGroupName $rgName -Name $saName -ErrorAction Stop
    }
    catch {
      $out += [pscustomobject]@{
        SubscriptionName = $sub.Name
        ResourceGroup    = $rgName
        Storage          = $saName
        Container        = $cont
        AccessPath       = $accessPath
        Identity         = $identityName
        PermissionType   = $permType
        Check            = 'StorageAccount'
        Status           = 'ERROR'
        Notes            = "Storage Account error: $($_.Exception.Message)"
      }
      continue
    }

    $ctx = $sa.Context

    # ----------------------------
    # 2. Container existence
    # ----------------------------
    try {
      $container = Get-AzStorageContainer -Name $cont -Context $ctx -ErrorAction Stop
    }
    catch {
      $out += [pscustomobject]@{
        SubscriptionName = $sub.Name
        ResourceGroup    = $rgName
        Storage          = $saName
        Container        = $cont
        AccessPath       = $accessPath
        Identity         = $identityName
        PermissionType   = $permType
        Check            = 'Container'
        Status           = 'ERROR'
        Notes            = "Container fetch error: $($_.Exception.Message)"
      }
      continue
    }

    if (-not $container) {
      $out += [pscustomobject]@{
        SubscriptionName = $sub.Name
        ResourceGroup    = $rgName
        Storage          = $saName
        Container        = $cont
        AccessPath       = $accessPath
        Identity         = $identityName
        PermissionType   = $permType
        Check            = 'Container'
        Status           = 'MISSING'
        Notes            = "Container not found"
      }
      continue
    }

    # ----------------------------------
    # 3. ACL validation (with ObjectId)
    # ----------------------------------
    if ($accessPath -and $identityName -and $permType) {

      # Resolve name -> ObjectId
      $objectId = Resolve-IdentityObjectId -IdentityName $identityName

      if (-not $objectId) {
        $out += [pscustomobject]@{
          SubscriptionName = $sub.Name
          ResourceGroup    = $rgName
          Storage          = $saName
          Container        = $cont
          AccessPath       = $accessPath
          Identity         = $identityName
          PermissionType   = $permType
          Check            = 'ACL'
          Status           = 'ERROR'
          Notes            = "Identity '$identityName' not found in Entra ID"
        }
        continue
      }

      try {
        # Normalize path: root is '', others trim leading '/'
        $normPath = if ($accessPath -eq '/' -or [string]::IsNullOrWhiteSpace($accessPath)) {
          ''
        } else {
          $accessPath.TrimStart('/')
        }

        # Get ADLS Gen2 item + ACL
        $item = Get-AzDataLakeGen2Item -FileSystem $cont -Path $normPath -Context $ctx -ErrorAction Stop

        # ACL strings: "user::rwx", "user:<objectId>:r-x", "group:<objectId>:r-x"
        $aclEntries = $item.Acl
        $matchEntry = $null

        foreach ($entry in $aclEntries) {
          $parts = $entry -split ':'
          if ($parts.Count -lt 3) { continue }

          $entryId   = $parts[1]
          $entryPerm = $parts[2]

          if ($entryId -eq $objectId -and $entryPerm -eq $permType) {
            $matchEntry = $entry
            break
          }
        }

        if ($matchEntry) {
          $permStatus = 'OK'
          $permNotes  = "Found ACL entry for ObjectId '$objectId' with perms '$permType'."
        } else {
          $permStatus = 'MISSING'
          $permNotes  = "No ACL entry for ObjectId '$objectId' with perms '$permType'."
        }
      }
      catch {
        $permStatus = "ERROR"
        $permNotes  = "ACL read error: $($_.Exception.Message)"
      }

      $out += [pscustomobject]@{
        SubscriptionName = $sub.Name
        ResourceGroup    = $rgName
        Storage          = $saName
        Container        = $cont
        AccessPath       = $accessPath
        Identity         = $identityName
        PermissionType   = $permType
        Check            = 'ACL'
        Status           = $permStatus
        Notes            = $permNotes
      }

    }
    else {
      # Not enough info to check ACL
      $out += [pscustomobject]@{
        SubscriptionName = $sub.Name
        ResourceGroup    = $rgName
        Storage          = $saName
        Container        = $cont
        AccessPath       = $accessPath
        Identity         = $identityName
        PermissionType   = $permType
        Check            = 'ACL'
        Status           = 'SKIPPED'
        Notes            = 'Missing AccessPath, Identity or PermissionType'
      }
    }
  }
}

if (-not $out) {
  $out += [pscustomobject]@{
    SubscriptionName = ''
    ResourceGroup    = ''
    Storage          = ''
    Container        = ''
    AccessPath       = ''
    Identity         = ''
    PermissionType   = ''
    Check            = ''
    Status           = 'NO_RESULTS'
    Notes            = 'Nothing matched in scan'
  }
}

$csvOut  = New-StampedPath -BaseDir $OutputDir -Prefix ("adls_validation_{0}_{1}" -f $adh_group, $adh_subscription_type)
Write-CsvSafe -Rows $out -Path $csvOut

$htmlOut = $csvOut -replace '\.csv$','.html'
Convert-CsvToHtml -CsvPath $csvOut -HtmlPath $htmlOut -Title "ADLS Validation ($adh_group / $adh_subscription_type) $BranchName"

Write-Host "ADLS validation completed." -ForegroundColor Green
Write-Host "CSV : $csvOut"
Write-Host "HTML: $htmlOut"
