# ------------------------------------------------------------
# 1) Write standard_tags.json (for your Databricks scripts)
# ------------------------------------------------------------
resource "local_file" "standard_tags_json" {
  filename = "${path.module}/standard_tags.json"

  content = jsonencode({
    tags_to_be_added           = local.tags_to_be_added
    sql_warehouse_desired_tags = local.sql_warehouse_desired_tags
    databricks_compute_tags    = local.databricks_compute_tags
  })
}

# ------------------------------------------------------------
# 2) Write per-resource tags JSON files (safe input)
# ------------------------------------------------------------
resource "local_file" "resource_tags_json" {
  for_each = local.tags_to_be_added

  filename = "${path.module}/tags_${replace(each.key, "/", "_")}.json"
  content  = jsonencode(each.value)
}

# ------------------------------------------------------------
# 3) Create a helper PowerShell script file (NO inline -Command)
# ------------------------------------------------------------
resource "local_file" "azure_tag_script" {
  filename = "${path.module}/tag_azure_resource.ps1"

  content = <<-PS1
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Rid,
    [Parameter(Mandatory)][string]$TagsFile,
    [Parameter(Mandatory)][int]$SleepSeconds
  )

  $ErrorActionPreference = "Stop"

  Write-Host "Loading tags from: $TagsFile"
  if (-not (Test-Path -LiteralPath $TagsFile)) {
    throw "Tags file not found: $TagsFile"
  }

  $tagsMap = Get-Content -LiteralPath $TagsFile -Raw | ConvertFrom-Json

  $tags = @()
  foreach ($prop in $tagsMap.PSObject.Properties) {
    # sanitize values (avoid newlines breaking CLI args)
    $val = [string]$prop.Value
    $val = $val -replace "`r|`n", " "

    $tags += ("{0}={1}" -f $prop.Name, $val)
  }

  Write-Host "Tagging Azure resource: $Rid"
  az resource tag --ids $Rid --tags $tags | Out-Host

  Start-Sleep -Seconds $SleepSeconds
  PS1
}

# ------------------------------------------------------------
# 4) Add/update tags on Azure resources (stable execution)
# ------------------------------------------------------------
resource "null_resource" "add_tags" {
  for_each = local.tags_to_be_added

  triggers = {
    resource_id = each.key
    tags_hash   = sha1(jsonencode(each.value))
  }

  provisioner "local-exec" {
    working_dir = path.module
    on_failure  = fail

    # IMPORTANT: prevents cmd.exe from breaking quotes for -File
    interpreter = ["pwsh", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File"]

    # Because working_dir = path.module, use relative paths
    command = format(
      ".\\tag_azure_resource.ps1 -Rid \"%s\" -TagsFile \".\\tags_%s.json\" -SleepSeconds %d",
      each.key,
      replace(each.key, "/", "_"),
      var.adh_standard_tags_update_delay_in_seconds
    )
  }

  depends_on = [
    local_file.azure_tag_script,
    local_file.resource_tags_json
  ]
}

# ------------------------------------------------------------
# 5) Databricks SQL Warehouse tags
# ------------------------------------------------------------
resource "null_resource" "sql_warehouse_tags" {
  triggers = {
    tags_hash = sha1(jsonencode(local.sql_warehouse_desired_tags))
  }

  provisioner "local-exec" {
    working_dir = path.module
    on_failure  = fail

    interpreter = ["pwsh", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File"]
    command     = ".\\tag_sql_warehouse.ps1"
  }

  depends_on = [
    local_file.standard_tags_json,
    null_resource.add_tags
  ]
}

# ------------------------------------------------------------
# 6) Databricks Compute tags
# ------------------------------------------------------------
resource "null_resource" "compute_tags" {
  for_each = local.tags_to_be_added

  triggers = {
    tags_hash = sha1(jsonencode(local.databricks_compute_tags))
    mode      = var.databricks_compute_tags_use_json_file_as_source_of_truth
  }

  provisioner "local-exec" {
    working_dir = path.module
    on_failure  = fail

    interpreter = ["pwsh", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File"]

    # NOTE:
    # Your original code calls tag_azure_resource.ps1 again (same as #4).
    # If you truly want Databricks compute tagging, replace this with your compute tagging script
    # (example: .\\tag_databricks_compute.ps1) and read standard_tags.json.
    command = format(
      ".\\tag_azure_resource.ps1 -Rid \"%s\" -TagsFile \".\\tags_%s.json\" -SleepSeconds %d",
      each.key,
      replace(each.key, "/", "_"),
      var.adh_standard_tags_update_delay_in_seconds
    )
  }

  depends_on = [
    local_file.standard_tags_json,
    null_resource.add_tags,
    local_file.resource_tags_json
  ]
}
