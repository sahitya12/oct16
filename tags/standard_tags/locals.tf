locals {
  _json_inputs = (
    var.adh_standard_tags_json_file != null && trim(var.adh_standard_tags_json_file) != ""
  ) ? jsondecode(file(var.adh_standard_tags_json_file)) : null

  tags_to_be_added = local._json_inputs != null
    ? lookup(local._json_inputs, "tags_to_be_added", {})
    : var.tags_to_be_added

  sql_warehouse_desired_tags = local._json_inputs != null
    ? lookup(local._json_inputs, "sql_warehouse_desired_tags", {})
    : var.sql_warehouse_desired_tags

  databricks_compute_tags = local._json_inputs != null
    ? lookup(local._json_inputs, "databricks_compute_tags", {})
    : var.databricks_compute_tags
}
