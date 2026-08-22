output "cloud_run_uri" {
  value       = google_cloud_run_v2_service.api_service.uri
  description = "URI of deployed Cloud Run API service"
}

output "service_account_email" {
  value       = google_service_account.api_sa.email
  description = "Service Account email with Vertex AI user permissions"
}
