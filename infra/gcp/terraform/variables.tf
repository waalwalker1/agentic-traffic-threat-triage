variable "project_id" {
  type        = string
  description = "GCP Project ID"
  default     = "example-threat-triage-project"
}

variable "region" {
  type        = string
  description = "GCP Region for Cloud Run and Vertex AI"
  default     = "us-central1"
}

variable "container_image" {
  type        = string
  description = "Container image URI for Cloud Run API service"
  default     = "gcr.io/example-threat-triage-project/api:latest"
}
