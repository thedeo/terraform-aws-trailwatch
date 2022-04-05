# Reports
resource "aws_cloudwatch_event_rule" "reports" {
  depends_on = [
    aws_cloudformation_stack_set.iam_roles,
    aws_iam_role.report_automation_master,
    aws_iam_role.report_automation,
    aws_sfn_state_machine.report_account,
    aws_sfn_state_machine.report_ami,
    aws_sfn_state_machine.report_securitygroup,
    aws_sfn_state_machine.report_user,
    aws_lambda_invocation.start_state_machines
  ]
  for_each = var.reports

  name                = "${var.project_name}-report-${each.value}"
  description         = "Reoccurring ${each.value} report execution."
  schedule_expression = var.dashboard_report_frequency
}

resource "aws_cloudwatch_event_target" "reports" {
  depends_on = [aws_cloudwatch_event_rule.reports]
  for_each = var.reports

  rule       = "${var.project_name}-report-${each.value}"
  target_id  = "${var.project_name}-report-${each.value}"
  arn        = "arn:aws:states:${var.region}:${var.org_account_id}:stateMachine:${var.project_name}-report-${each.value}"
  role_arn   = aws_iam_role.report_scheduled_event.arn
}

# Email Summary
resource "aws_cloudwatch_event_rule" "email_summary" {
  name                = "${var.project_name}-email-summary"
  description         = "Reoccurring email summary."
  schedule_expression = "rate(${var.email_summary_frequency} minutes)"
}

resource "aws_cloudwatch_event_target" "email_summary" {
  depends_on = [aws_cloudwatch_event_rule.email_summary]

  rule       = "${var.project_name}-email-summary"
  target_id  = "${var.project_name}-email-summary"
  arn        = aws_lambda_function.email_summary.arn
}

# Global rules
resource "aws_cloudwatch_event_rule" "global_event_rules" {
  for_each = var.global_event_rule_type_map

  name          = "${var.project_name}-${each.key}"
  description   = "Router for ${each.key} events."
  event_pattern = each.value
}

resource "aws_cloudwatch_event_target" "global_event_rules" {
  depends_on = [aws_cloudwatch_event_rule.global_event_rules]
  for_each   = var.global_event_rule_type_map

  rule       = "${var.project_name}-${each.key}"
  target_id  = "${var.project_name}-event-parse"
  arn        = aws_lambda_function.event_parse.arn
}

# Regional rules for us-east-1 only, other regions are handled in org_cf_stacks.tf
resource "aws_cloudwatch_event_rule" "regional_event_rules" {
  for_each = var.regional_event_rule_type_map

  name          = "${var.project_name}-${each.key}"
  description   = "Router for ${each.key} events."
  event_pattern = each.value
}

resource "aws_cloudwatch_event_target" "regional_event_rules" {
  depends_on = [aws_cloudwatch_event_rule.regional_event_rules]
  for_each   = var.regional_event_rule_type_map

  rule       = "${var.project_name}-${each.key}"
  target_id  = "${var.project_name}-event-parse"
  arn        = aws_lambda_function.event_parse.arn
}

#==================================================================
# All other regional rules had to be done in org_cf_stacks.tf.
# At this time, you cannot use use interpolation with tf providers.
# I tried, but doesn't work.
#==================================================================