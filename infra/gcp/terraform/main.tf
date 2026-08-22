terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# Service Account for Cloud Run API
resource "google_service_account" "api_sa" {
  account_id   = "threat-triage-api-sa"
  display_name = "Agentic Traffic Threat Triage API Service Account"
}

# Grant Vertex AI User role for optional cloud reasoning
resource "google_project_iam_member" "vertex_ai_user" {
  project = var.project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.api_sa.email}"
}

# Cloud Run Service (Reference Deployment)
resource "google_cloud_run_v2_service" "api_service" {
  name     = "traffic-threat-triage-api"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = google_service_account.api_sa.email
    containers {
      image = var.container_image
      resources {
        limits = {
          cpu    = "2"
          memory = "4Gi"
        }
      }
      env {
        name  = "ENVIRONMENT"
        value = "production"
      }
      env {
        name  = "GCP_PROJECT_ID"
        value = var.project_id
      }
    }
  }
}
