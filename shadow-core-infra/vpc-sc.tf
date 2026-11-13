resource "google_access_context_manager_access_policy" "shadow_policy" {
  parent = "organizations/${var.org_id}"
  title  = "shadow-core-policy"
}

resource "google_access_context_manager_service_perimeter" "shadow_perimeter" {
  parent = google_access_context_manager_access_policy.shadow_policy.name
  name   = "${google_access_context_manager_access_policy.shadow_policy.name}/servicePerimeters/shadow-core-prod"
  title  = "shadow-core-prod"
  use_explicit_dry_run_spec = true

  spec {
    restricted_services = [
      "aiplatform.googleapis.com",
      "bigquery.googleapis.com",
      "storage.googleapis.com",
      "cloudkms.googleapis.com",
    ]
    resources = ["projects/${var.project_id}"]
  }
}
