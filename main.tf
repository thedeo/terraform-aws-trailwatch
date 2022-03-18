# This Terraform creates a low cost AWS event monitor for organizations.
# It includes a summary email and web dashboard for viewing events.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.5"
    }
  }

  required_version = ">= 0.14.9"
}

provider "aws" {
  profile = var.profile
  region  = var.region
}

module "org_bootstrap" {
  source = "./org_bootstrap"
}

module "org_resources" {
  # Supporting event monitor resources.
  source     = "./org_resources"
  depends_on = [module.org_bootstrap]

  project_name             = var.project_name
  region                   = var.region
  ses_identity_arn         = var.ses_identity_arn
  dashboard_domain         = var.dashboard_domain
  email_summary_frequency  = var.email_summary_frequency
  alert_sender             = var.alert_sender
  alert_recipients         = var.alert_recipients
  ignored_iam_principals   = var.ignored_iam_principals
  create_cf_stackset_roles = var.create_cf_stackset_roles
  org_account_id           = module.org_bootstrap.org_account_id
  org_root_id              = module.org_bootstrap.org_root_id
  org_id                   = module.org_bootstrap.org_id
  available_regions        = module.org_bootstrap.available_regions
}

# module "dashboard" {
#   # Set up web dashboard with CodePipeline
#   source = "./dashboard"
#   depends_on = [module.org_resources]

#   project_name        = var.project_name
#   region              = var.region
#   alb_tls_cert_arn    = var.alb_tls_cert_arn
#   trusted_cidrs       = var.trusted_cidrs
#   dashboard_domain    = var.dashboard_domain
#   dockerhub_username  = var.dockerhub_username
#   dockerhub_password  = var.dockerhub_password
#   org_account_id      = module.org_bootstrap.org_account_id
# }

# output "dashboard_domain" {
#   value = module.dashboard.domain
# }