resource "google_container_cluster" "shadow_gke" {
  name       = "shadow-core-gke"
  location   = var.region
  enable_autopilot = true

  private_cluster_config {
    enable_private_nodes    = true
    master_ipv4_cidr_block = "172.16.0.0/28"
  }

  network    = google_compute_network.vpc_shadow_prod.name
  subnetwork = google_compute_subnetwork.subnet_gke.name
}
