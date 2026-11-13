resource "google_compute_security_policy" "shadow_armor" {
  name = "shadow-core-armor"

  rule {
    action   = "rate_based_ban"
    priority = 100
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    rate_limit_options {
      conform_action = "allow"
      exceed_action  = "deny(429)"
      enforce_on_key = "IP"
      rate_limit_threshold {
        count        = 100
        interval_sec = 60
      }
    }
  }

  rule {
    action   = "deny(403)"
    priority = 200
    match {
      expr {
        expression = "origin.region_code != 'MX' && origin.region_code != 'US'"
      }
    }
    description = "Shadow Core: Solo MX y US"
  }

  rule {
    action   = "allow"
    priority = 2147483647
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
  }
}
