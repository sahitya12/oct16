module "adh_standard_tags" {
  source = "../../Modules/standard_tags"

  # pass structures directly from tfvars (HCL)
  tags_to_be_added           = var.tags_to_be_added
  sql_warehouse_desired_tags = var.sql_warehouse_desired_tags
  databricks_compute_tags    = var.databricks_compute_tags

  adh_standard_tags_update_delay_in_seconds                = var.adh_standard_tags_update_delay_in_seconds
  databricks_compute_tags_use_json_file_as_source_of_truth = var.databricks_compute_tags_use_json_file_as_source_of_truth
}
