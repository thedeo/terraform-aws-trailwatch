resource "aws_cloudwatch_event_permission" "org_access" {
  principal    = "*"
  statement_id = "OrganizationAccess"

  condition {
    key   = "aws:PrincipalOrgID"
    type  = "StringEquals"
    value = var.org_id
  }
}