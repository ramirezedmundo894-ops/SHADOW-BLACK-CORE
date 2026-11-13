resource "google_vertex_ai_endpoint" "shadow_risk" {
  name       = "shadow-risk"
  display_name = "shadow-risk"
  location   = var.region
}
