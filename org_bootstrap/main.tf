# The purpose of the below code is to add some verification that the account is an AWS
# Organizations Management account. In addition we gather some values to be used later.

data "aws_organizations_organization" "org" {}
data "aws_caller_identity" "current" {}
data "aws_regions" "current" {}

output "available_regions" {
  value = data.aws_regions.current.names
}

output "org_account_id" {
  value = data.aws_caller_identity.current.account_id
}

output "org_root_id" {
  value = data.aws_organizations_organization.org.roots[0].id
}

output "org_id" {
  value = data.aws_organizations_organization.org.id
}

output "org_accounts" {
  value = data.aws_organizations_organization.org.accounts
  description = "If this account is not the org management account, this output will error."
}