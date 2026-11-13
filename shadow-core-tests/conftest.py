resource "google_storage_bucket" "evidence" {
  name                        = "shadow-evidence-prod"
  location                    = var.region
  versioning {
    enabled = true
  }
  uniform_bucket_level_access = true
}
