resource "google_storage_bucket" "evidence" {
  name                        = "${var.project_id}-shadow-evidence"
  location                    = var.region
  uniform_bucket_level_access = true
  force_destroy               = false

  versioning { enabled = true }
}
