terraform {
  required_providers {
    azurerm = {
      source = "hashicorp/azurerm"
    }
    null = {
      source = "hashicorp/null"
    }
    local = {
      source = "hashicorp/local"
    }
  }
}

# Ensure standard_tags.json exists for your PowerShell scripts
resource "local_file" "standard_tags_json" {
  filename = "${path.module}/standard_tags.json"
  content = jsonencode({
    tags_to_be_added           = local.tags_to_be_added
    sql_warehouse_desired_tags = local.sql_warehouse_desired_tags
    databricks_compute_tags    = local.databricks_compute_tags
  })
}

# Add new tags to azure resources
resource "null_resource" "add_tags" {
  for_each = {
    for id, tags in local.tags_to_be_added : id =>
    join(" ", [for key, value in tags : "${key}=\"${value}\""])
  }

  triggers = {
    always_run = timestamp()
  }

  provisioner "local-exec" {
    interpreter = ["PowerShell", "-Command"]
    working_dir = path.module
    command     = each.value != "" ? "Start-Sleep -Seconds ${var.adh_standard_tags_update_delay_in_seconds}; az tag update --resource-id ${each.key} --operation Merge --tags ${each.value}" : "echo done"
    on_failure  = fail
  }

  depends_on = [local_file.standard_tags_json]
}

# Update tags on the Databricks SQL Warehouse
resource "null_resource" "sql_warehouse_tags" {
  triggers = {
    always_run = timestamp()
  }

  provisioner "local-exec" {
    interpreter = ["PowerShell", "-Command"]
    working_dir = path.module
    command     = "${path.module}/tag_sql_warehouse.ps1"
    on_failure  = fail
  }

  depends_on = [
    local_file.standard_tags_json,
    null_resource.add_tags
  ]
}

# Update tags on the Databricks Compute
resource "null_resource" "compute_tags" {
  triggers = {
    always_run = timestamp()
  }

  provisioner "local-exec" {
    interpreter = ["PowerShell", "-Command"]
    working_dir = path.module
    command     = var.databricks_compute_tags_use_json_file_as_source_of_truth == "true" ? "${path.module}/tag_compute.ps1 -run_idempotent $true" : "${path.module}/tag_compute.ps1 -run_idempotent $false"
    on_failure  = fail
  }

  depends_on = [
    local_file.standard_tags_json,
    null_resource.add_tags
  ]
}
