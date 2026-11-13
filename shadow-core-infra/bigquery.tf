resource "google_bigquery_dataset" "evidence" {
  dataset_id = "dataset_evidence"
  location   = var.region
}

resource "google_bigquery_table" "merkle_logs" {
  dataset_id = google_bigquery_dataset.evidence.dataset_id
  table_id   = "merkle_logs"
  schema = jsonencode([
    { name = "timestamp", type = "TIMESTAMP" },
    { name = "test_id", type = "STRING" },
    { name = "sha256", type = "STRING" },
    { name = "risk_score", type = "FLOAT" },
    { name = "pomp_decision", type = "STRING" },
  ])
}
