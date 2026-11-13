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

resource "google_compute_firewall" "deny_all" {
  name    = "shadow-deny-all"
  network = google_compute_network.vpc_shadow_prod.name

  deny {
    protocol = "all"
  }

  source_ranges = ["0.0.0.0/0"]
  priority      = 65535
}

resource "google_compute_firewall" "allow_grpc" {
  name    = "shadow-allow-grpc"
  network = google_compute_network.vpc_shadow_prod.name

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }

  source_ranges = ["10.0.0.0/20"]
  priority      = 1000
}
