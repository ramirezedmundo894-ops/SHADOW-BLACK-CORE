variable "project_id" {
  type        = string
  description = "Existing GCP project ID. Set explicitly for your environment."
}

variable "region" {
  type    = string
  default = "us-central1"
}

variable "org_id" {
  type        = string
  description = "GCP organization ID; required only for the Access Context Manager policy."
}
