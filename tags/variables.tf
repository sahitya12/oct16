variable "tags_to_be_added" {
  description = "Map of Azure resourceId => map(tags)"
  type        = map(map(string))
}

variable "sql_warehouse_desired_tags" {
  description = "Host URL => list of { warehouse_id => { tagK = tagV } }"
  type        = map(list(map(map(string))))
  default     = {}
}

variable "databricks_compute_tags" {
  description = "Compute tag inputs for clusters"
  type = map(object({
    databricks_workspace_name      = string
    databricks_resource_group_name = string
    cluster_id                     = string
    tags                           = map(string)
  }))
  default = {}
}

variable "adh_standard_tags_update_delay_in_seconds" {
  type        = number
  description = "Delay in seconds between two succesing tag updates"
  default     = 15
}

variable "databricks_compute_tags_use_json_file_as_source_of_truth" {
  type        = string
  description = "If true, only tags in inputs remain on compute; others are removed."
  default     = "false"
}
