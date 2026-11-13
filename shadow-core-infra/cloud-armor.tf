resource "google_service_account" "sa_shadow_api" {
  account_id   = "sa-shadow-api"
  display_name = "Shadow Core API"
}

resource "google_project_iam_member" "api_vertex" {
  project = var.project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.sa_shadow_api.email}"
}

resource "google_project_iam_member" "api_kms_encrypt" {
  project = var.project_id
  role    = "roles/cloudkms.signerVerifier"
  member  = "serviceAccount:${google_service_account.sa_shadow_api.email}"
}

resource "google_project_iam_member" "auditor_bq" {
  project = var.project_id
  role    = "roles/bigquery.dataViewer"
  member  = "group:auditoria@shadowcore.dev"
}
