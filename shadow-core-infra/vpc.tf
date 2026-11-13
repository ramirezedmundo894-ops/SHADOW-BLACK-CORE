resource "google_compute_network" "vpc_shadow_prod" {
  name                    = "vpc-shadow-prod"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "subnet_gke" {
  name                     = "subnet-gke"
  ip_cidr_range            = "10.0.0.0/20"
  region                   = var.region
  network                  = google_compute_network.vpc_shadow_prod.id
  private_ip_google_access = true
}

resource "google_compute_subnetwork" "subnet_vertex" {
  name                     = "subnet-vertex"
  ip_cidr_range            = "10.0.16.0/20"
  region                   = var.region
  network                  = google_compute_network.vpc_shadow_prod.id
  private_ip_google_access = true
}

resource "google_compute_subnetwork" "subnet_data" {
  name                     = "subnet-data"
  ip_cidr_range            = "10.0.32.0/20"
  region                   = var.region
  network                  = google_compute_network.vpc_shadow_prod.id
  private_ip_google_access = true
}

# GCP firewall rules are additive. This deny rule is not a VPC-wide default deny.
resource "google_compute_firewall" "deny_all_ingress" {
  name      = "shadow-deny-all-ingress"
  network   = google_compute_network.vpc_shadow_prod.name
  direction = "INGRESS"
  priority  = 65535
  source_ranges = ["0.0.0.0/0"]
  deny { protocol = "all" }
}

resource "google_compute_firewall" "allow_internal_grpc" {
  name      = "shadow-allow-internal-grpc"
  network   = google_compute_network.vpc_shadow_prod.name
  direction = "INGRESS"
  priority  = 1000
  source_ranges = ["10.0.0.0/20"]
  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}
