# Overall name of the project/solution used to name resources in AWS.
variable "project_name" {
  default = "trailwatch"
}

# AWS Provider Vars
variable "region" {
  default = "us-east-1" # Do not change. Must be set to us-east-1 to capture global events.
}

variable "profile" {
  default = "default"
}

# Dashboard Settings
variable "trusted_cidrs" {
  description = "WARNING: Used to allow network access via Security Group to dashboard web interface. Only allow trusted networks."
}

variable "dashboard_domain" {
  #default     = "ZONE_ID"
  description = "Hosted Zone ID for the dashboard. An Alias for dashboard.example.com will be created and pointed at the ALB."
}

variable "alb_tls_cert_arn" {
  #default = "arn:aws:acm:REGION:ACCOUNTID:certificate/xxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxx"
  description = "ARN for an existing ACM Certificate in us-east-1. This will be for the dashboard that displays event details."
}

variable "dockerhub_username" {
  #default     = "username"
  description = "Used in AWS Codebuild."
}

variable "dockerhub_password" {
  #default     = ""
  description = "Used in AWS Codebuild. Stored in Secrets Manager."
  sensitive   = true
}

variable "dashboard_report_frequency" {
  default     = "cron(0 * * * ? *)"
  description = "How often to run the built in reports [account, ami, securitygroup, user]."
}


# Email Settings
variable "ses_identity_arn" {
  #default = "arn:aws:ses:REGION:ACCOUNTID:identity/example.com"
  description = "ARN for your existing SES domain identity. Ensure that 'alert_sender' matches the SES identity domain."
}

variable "email_summary_frequency" {
  default     = "60"
  description = "In minutes."
}

variable "alert_sender" {
  #default = "alerts@example.com"
}

variable "alert_recipients" {
  type = list
  default = [
              "noc@example.com",
            ]
}

variable "ignored_iam_principals" {
  type = list
  description = "You can use this to omit certain principals from the reoccurring email summaries."
  default = [
              "SA_Automation",
              "AmazonSSMRoleForAutomationAssumeQuickSetup",
              "rundeck",
              "AWSServiceRoleForApplicationAutoScaling_RDSCluster",
            ]
}


# Toggle AWSCloudFormationStackSetAdministrationRole & AWSCloudFormationStackSetExecutionRole role creation
variable "create_cf_stackset_roles" {
  default = true
}