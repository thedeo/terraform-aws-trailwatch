variable "project_name" {
  type = string
  description = "This will be used "
  default = "Overall name of the project/solution used to name resources in AWS."
}

# AWS Provider Vars
variable "region" {
  type = string
  description = "Do not change. Must be set to us-east-1 to capture global events. Changing this will break the deployment."
  default = "us-east-1"
}

variable "profile" {
  type = string
  description = "Name of local AWS profile that will be used to deploy resources via AWS APIs."
  default = "default"
}

# Dashboard Settings
variable "trusted_cidr" {
  type = string
  description = "WARNING: Used to allow network access via Security Group to dashboard web interface. Only allow trusted networks. Example: 42.42.42.0/24"
}

variable "dashboard_domain" {
  type = string
  description = "Hosted Zone ID for the dashboard. An Alias for dashboard.example.com will be created and pointed at the ALB."
}

variable "alb_tls_cert_arn" {
  type = string
  description = "ARN for an existing ACM Certificate in us-east-1. This will be for the dashboard that displays event details."
}

variable "dockerhub_username" {
  type = string
  description = "Used in AWS Codebuild."
}

variable "dockerhub_password" {
  type = string
  description = "Used in AWS Codebuild. Stored in Secrets Manager."
  sensitive   = true
}

variable "dashboard_report_frequency" {
  type = string
  description = "How often to run the built in reports [account, ami, securitygroup, user]."
  default     = "cron(0 * * * ? *)"
}


# Email Settings
variable "ses_identity_arn" {
  type = string
  description = "ARN for your existing SES domain identity. Ensure that 'alert_sender' matches the SES identity domain."
  #default = "arn:aws:ses:REGION:ACCOUNTID:identity/example.com"
}

variable "email_summary_frequency" {
  type = string
  description = "In minutes."
  default     = "60"
}

variable "alert_sender" {
  type = string
  description = "Email address to send alerts from. This domain should match the ses_identity_arn's associated domain."
}

variable "alert_recipients" {
  type = list
  description = "List of email addresses that will receive all related emails for the solution."
  default = [
              "noc@example.com",
            ]
}

variable "ignored_iam_principals" {
  type = list
  description = "List of principals that will be omitted from the reoccurring email summaries."
  default = [
              "SA_Automation",
              "AmazonSSMRoleForAutomationAssumeQuickSetup",
              "rundeck",
              "AWSServiceRoleForApplicationAutoScaling_RDSCluster",
            ]
}


# Toggle AWSCloudFormationStackSetAdministrationRole & AWSCloudFormationStackSetExecutionRole role creation
variable "create_cf_stackset_roles" {
  type = bool
  description = "Only toggle this to false if you've already created the roles AWSCloudFormationStackSetAdministrationRole & AWSCloudFormationStackSetExecutionRole in your Org master account."
  default = true
}