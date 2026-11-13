variable "project_id" {
  type    = string
  default = "shadow-core-prod"
}

variable "region" {
  type    = string
  default = "us-central1"
}

variable "org_id" {
  type        = string
  description = "Organization ID for VPC Service Controls"
}
