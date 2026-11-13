resource "google_kms_key_ring" "kr_shadow" {
  name     = "kr-shadow-core"
  location = var.region
}

resource "google_kms_crypto_key" "key_merkle" {
  name            = "key-merkle-root"
  key_ring        = google_kms_key_ring.kr_shadow.id
  rotation_period = "7776000s"
  purpose         = "ASYMMETRIC_SIGN"

  version_template {
    algorithm = "EC_SIGN_P256_SHA256"
  }
}

resource "google_kms_crypto_key" "key_jwt" {
  name            = "key-jwt-signing"
  key_ring        = google_kms_key_ring.kr_shadow.id
  rotation_period = "7776000s"
  purpose         = "ASYMMETRIC_SIGN"

  version_template {
    algorithm = "EC_SIGN_P256_SHA256"
  }
}
