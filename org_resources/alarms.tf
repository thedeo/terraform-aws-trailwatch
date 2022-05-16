resource "aws_cloudwatch_metric_alarm" "event_parse" {
  alarm_name          = "${var.project_name}-event-parse"
  alarm_description   = "${var.project_name} event parse errors."
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Maximum"
  threshold           = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = [
    "${aws_sns_topic.alarms.arn}",
  ]

  dimensions = {
    FunctionName = "${aws_lambda_function.event_parse.function_name}"
    Resource     = "${aws_lambda_function.event_parse.function_name}"
  }
}

resource "aws_cloudwatch_metric_alarm" "email_summary" {
  alarm_name          = "${var.project_name}-email-summary"
  alarm_description   = "${var.project_name} email summary errors."
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Maximum"
  threshold           = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = [
    "${aws_sns_topic.alarms.arn}",
  ]

  dimensions = {
    FunctionName = "${aws_lambda_function.email_summary.function_name}"
    Resource     = "${aws_lambda_function.email_summary.function_name}"
  }
}

resource "aws_cloudwatch_metric_alarm" "automation_security_groups" {
  alarm_name          = "${var.project_name}-automation-security-groups"
  alarm_description   = "${var.project_name} security group automation errors."
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Maximum"
  threshold           = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = [
    "${aws_sns_topic.alarms.arn}",
  ]

  dimensions = {
    FunctionName = "${aws_lambda_function.automation_security_groups.function_name}"
    Resource     = "${aws_lambda_function.automation_security_groups.function_name}"
  }
}


resource "aws_cloudwatch_metric_alarm" "reports" {
  for_each = var.reports

  alarm_name = "${var.project_name}-report-${each.value}"
  alarm_description   = "${var.project_name}-${each.value} report state machine errors."
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods = "1"
  metric_name = "ExecutionsFailed"
  namespace = "AWS/States"
  period = "300"
  statistic = "Maximum"
  threshold = 1
  treat_missing_data = "notBreaching"

  dimensions = {
    StateMachineArn = "arn:aws:states:${var.region}:${var.org_account_id}:stateMachine:${var.project_name}-report-${each.value}"
  }

  alarm_actions = [
    "${aws_sns_topic.alarms.arn}",
  ]
}