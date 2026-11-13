resource "google_cloud_run_v2_service" "dashboard" {
  name     = "shadow-core-dashboard"
  location = "us-central1"
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    containers {
      image = "gcr.io/shadow-core-prod/dashboard:latest"
      ports {
        container_port = 8080
      }
    }
    service_account = "sa-shadow-api@shadow-core-prod.iam.gserviceaccount.com"
  }
}
