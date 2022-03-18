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
# All other regional rules had to be done in org_cf_stacks.tf,
# you cannot use use interpolation with tf providers.
# I tried, but doesn't work.
#==================================================================