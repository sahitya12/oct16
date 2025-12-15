# Replace with your real subscription id
# Example: "/subscriptions/c8f9e452-f4bd-41a8-bb6d-7daa12c6f323"
tags_to_be_added = {
  "/subscriptions/<SUBSCRIPTION_ID>" = {
    group                                   = "SAB"
    environment                             = "nonprd"
    cost_center                             = "807111015271"
    costcenter                              = "807111015271"
    adh_subscription_point_of_contact_email_id = "DataAnalyticsITPlatformServices@amerisourebergen.com"
    adh_custodian_owner_email_id            = "Hannah.Kelly@cencora.com"
    applicationname                         = "Analytics Data Hub (ADH) Custodian - SAB"
    application_code                        = "SAB"
    servicename                             = "Analytics Data Hub (ADH): Service Offering"
    service_code                            = "ADH"
  }
}

# Keep empty if not needed for this run
sql_warehouse_desired_tags = {}
databricks_compute_tags    = {}

sql_warehouse_desired_tags = {
  "https://adb-123456789012.5.azuredatabricks.net" = [
    {
      "warehouse-abc123" = {
        "CostCenter" = "807111015271"
        "Environment" = "nonprd"
        "Owner" = "ADH-Team"
      }
    },
    {
      "warehouse-def456" = {
        "CostCenter" = "807111015271"
        "Environment" = "nonprd"
        "Owner" = "ADH-Team"
      }
    }
  ]
}

databricks_compute_tags = {
  "cluster01" = {
    databricks_workspace_name      = "adh-dbx-nonprd-weu"
    databricks_resource_group_name = "rg-adh-dbx-nonprd-weu"
    cluster_id                     = "0708-123456-abcd123"
    tags = {
      "CostCenter" = "807111015271"
      "Environment" = "nonprd"
      "Owner" = "ADH-Team"
    }
  }

  "cluster02" = {
    databricks_workspace_name      = "adh-dbx-nonprd-weu"
    databricks_resource_group_name = "rg-adh-dbx-nonprd-weu"
    cluster_id                     = "0708-654321-efgh456"
    tags = {
      "CostCenter" = "807111015271"
      "Environment" = "nonprd"
      "Owner" = "ADH-Team"
    }
  }
}



adh_standard_tags_update_delay_in_seconds                = 15
databricks_compute_tags_use_json_file_as_source_of_truth = "false"
