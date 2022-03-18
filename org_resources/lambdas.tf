locals {
  ses_region = element(split(":", "${var.ses_identity_arn}"), 3)
}

data "aws_route53_zone" "selected" {
  zone_id = var.dashboard_domain
}

# Lambda to parse events from AWS EventBridge
data "archive_file" "event_parse" {
  type        = "zip"
  source_dir = "${path.module}/lambdas/source/event_parse/"
  output_path = "${path.module}/lambdas/zipped/event_parse.zip"
}

resource "aws_lambda_function" "event_parse" {
  function_name = "${var.project_name}-event-parse"
  role          = aws_iam_role.event_parse.arn
  handler       = "lambda_function.lambda_handler"
  timeout       = 300
  runtime       = "python3.9"

  filename         = "${data.archive_file.event_parse.output_path}"
  source_code_hash = "${data.archive_file.event_parse.output_base64sha256}"

  environment {
    variables = {
      project_name      = "${var.project_name}"
      region            = "${var.region}"
      ses_region        = "${local.ses_region}"
      dynamodb_table    = "${aws_dynamodb_table.events.name}"
      alert_sender      = "${var.alert_sender}"
      alert_recipients  = "${jsonencode(var.alert_recipients)}"
    }
  }
}

resource "aws_lambda_permission" "global_event_parse" {
  for_each      = var.global_event_rule_type_map

  statement_id  = "AllowExecutionFromEvents-${each.key}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.event_parse.function_name
  principal     = "events.amazonaws.com"
  source_arn    = "arn:aws:events:${var.region}:${var.org_account_id}:rule/${var.project_name}-${each.key}"
}

resource "aws_lambda_permission" "regional_event_parse" {
  for_each      = var.regional_event_rule_type_map

  statement_id  = "AllowExecutionFromEvents-${each.key}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.event_parse.function_name
  principal     = "events.amazonaws.com"
  source_arn    = "arn:aws:events:${var.region}:${var.org_account_id}:rule/${var.project_name}-${each.key}"
}

# Lambda to send event summary emails.
data "archive_file" "email_summary" {
  type        = "zip"
  source_dir = "${path.module}/lambdas/source/email_summary/"
  output_path = "${path.module}/lambdas/zipped/email_summary.zip"
}

resource "aws_lambda_function" "email_summary" {
  function_name = "${var.project_name}-email-summary"
  role          = aws_iam_role.email_summary.arn
  handler       = "lambda_function.lambda_handler"
  timeout       = 300
  runtime       = "python3.9"

  filename         = "${data.archive_file.email_summary.output_path}"
  source_code_hash = "${data.archive_file.email_summary.output_base64sha256}"

  environment {
    variables = {
      project_name            = "${var.project_name}"
      region                  = "${var.region}"
      ses_region              = "${local.ses_region}"
      dynamodb_table          = "${aws_dynamodb_table.events.name}"
      email_summary_frequency = "${var.email_summary_frequency}"
      alert_sender            = "${var.alert_sender}"
      alert_recipients        = "${jsonencode(var.alert_recipients)}"
      ignored_iam_principals  = "${jsonencode(var.ignored_iam_principals)}"
      dashboard_domain        = join(".", ["dashboard", data.aws_route53_zone.selected.name])
    }
  }
}

resource "aws_lambda_permission" "email_summary" {
  statement_id  = "AllowExecutionFromEvents"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.email_summary.function_name
  principal     = "events.amazonaws.com"
  source_arn    = "arn:aws:events:${var.region}:${var.org_account_id}:rule/${var.project_name}-email-summary"
}
