# ============================================================
# Shadow AI Sentinel — GCP Infrastructure
# Usage: cd infra/terraform/gcp && terraform init && terraform plan
# ============================================================

terraform {
  required_version = ">= 1.5"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }

  # Uncomment for remote state (recommended for team use)
  # backend "gcs" {
  #   bucket = "sentinel-terraform-state"
  #   prefix = "terraform/state"
  # }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# --- Variables ---
variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "region" {
  description = "GCP region"
  type        = string
  default     = "us-central1"
}

variable "environment" {
  description = "Environment (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "db_password" {
  description = "PostgreSQL password"
  type        = string
  sensitive   = true
}

variable "redis_password" {
  description = "Redis password"
  type        = string
  sensitive   = true
}

# --- Enable required APIs ---
resource "google_project_service" "services" {
  for_each = toset([
    "run.googleapis.com",
    "sqladmin.googleapis.com",
    "redis.googleapis.com",
    "artifactregistry.googleapis.com",
    "secretmanager.googleapis.com",
    "cloudresourcemanager.googleapis.com",
  ])
  service            = each.value
  disable_on_destroy = false
}

# --- Artifact Registry (Docker images) ---
resource "google_artifact_registry_repository" "sentinel" {
  location      = var.region
  repository_id = "sentinel-${var.environment}"
  format        = "DOCKER"
  depends_on    = [google_project_service.services]
}

# --- Cloud SQL (PostgreSQL) ---
resource "google_sql_database_instance" "sentinel" {
  name             = "sentinel-${var.environment}"
  database_version = "POSTGRES_16"
  region           = var.region

  settings {
    tier              = var.environment == "prod" ? "db-custom-2-4096" : "db-f1-micro"
    availability_type = var.environment == "prod" ? "REGIONAL" : "ZONAL"

    ip_configuration {
      ipv4_enabled = true
      # In production, use private IP + VPC connector
    }

    backup_configuration {
      enabled                        = var.environment == "prod"
      point_in_time_recovery_enabled = var.environment == "prod"
    }
  }

  deletion_protection = var.environment == "prod"
  depends_on          = [google_project_service.services]
}

resource "google_sql_database" "sentinel" {
  name     = "sentinel"
  instance = google_sql_database_instance.sentinel.name
}

resource "google_sql_user" "sentinel" {
  name     = "sentinel"
  instance = google_sql_database_instance.sentinel.name
  password = var.db_password
}

# --- Memorystore (Redis) ---
resource "google_redis_instance" "sentinel" {
  name           = "sentinel-${var.environment}"
  tier           = var.environment == "prod" ? "STANDARD_HA" : "BASIC"
  memory_size_gb = var.environment == "prod" ? 2 : 1
  region         = var.region
  redis_version  = "REDIS_7_0"

  auth_enabled = true

  depends_on = [google_project_service.services]
}

# --- Secret Manager ---
resource "google_secret_manager_secret" "db_password" {
  secret_id = "sentinel-db-password-${var.environment}"

  replication {
    auto {}
  }

  depends_on = [google_project_service.services]
}

resource "google_secret_manager_secret_version" "db_password" {
  secret      = google_secret_manager_secret.db_password.id
  secret_data = var.db_password
}

resource "google_secret_manager_secret" "jwt_secret" {
  secret_id = "sentinel-jwt-secret-${var.environment}"

  replication {
    auto {}
  }

  depends_on = [google_project_service.services]
}

# --- Cloud Run: Proxy Service (Phase 2) ---
# Uncomment when proxy Docker image is ready
# resource "google_cloud_run_v2_service" "proxy" {
#   name     = "sentinel-proxy-${var.environment}"
#   location = var.region
#
#   template {
#     containers {
#       image = "${var.region}-docker.pkg.dev/${var.project_id}/sentinel-${var.environment}/proxy-service:latest"
#
#       env {
#         name  = "DATABASE_URL"
#         value = "postgres://sentinel:${var.db_password}@${google_sql_database_instance.sentinel.public_ip_address}/sentinel"
#       }
#       env {
#         name  = "REDIS_URL"
#         value = "redis://:${var.redis_password}@${google_redis_instance.sentinel.host}:${google_redis_instance.sentinel.port}"
#       }
#       env {
#         name  = "ENVIRONMENT"
#         value = var.environment
#       }
#
#       resources {
#         limits = {
#           cpu    = "2"
#           memory = "1Gi"
#         }
#       }
#     }
#
#     scaling {
#       min_instance_count = var.environment == "prod" ? 1 : 0
#       max_instance_count = var.environment == "prod" ? 10 : 3
#     }
#   }
# }

# --- Cloud Run: ML Service (Phase 2) ---
# Similar pattern to proxy service above

# --- Outputs ---
output "db_connection_name" {
  value = google_sql_database_instance.sentinel.connection_name
}

output "db_public_ip" {
  value = google_sql_database_instance.sentinel.public_ip_address
}

output "redis_host" {
  value = google_redis_instance.sentinel.host
}

output "artifact_registry" {
  value = "${var.region}-docker.pkg.dev/${var.project_id}/sentinel-${var.environment}"
}
