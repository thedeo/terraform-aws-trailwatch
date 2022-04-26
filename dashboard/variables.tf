variable "project_name" {}
variable "region" {}
variable "org_account_id" {}
variable "alb_tls_cert_arn" {}
variable "trusted_cidrs" {}
variable "dashboard_domain" {}
variable "dockerhub_username" {}
variable "dockerhub_password" {}
variable "dynamodb_key_arn" {}

variable "cidr" {
  default = "172.31.0.0/16"
}

variable "public_subnets" {
  default = [
    "172.31.0.0/17",
    "172.31.128.0/17",
  ]
}

variable "availability_zones" {
  default = [
    "us-east-1a",
    "us-east-1b",
  ]
}

variable "container_port" {
  default = "8000" # also manually set in ecs.tf for container_definitions
}