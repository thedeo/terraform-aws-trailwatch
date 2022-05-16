############################
# Security Group Automation
############################
data "archive_file" "automation_security_groups" {
  type        = "zip"
  source_dir  = "${path.module}/lambdas/source/automation_security_groups/"
  output_path = "${path.module}/lambdas/zipped/automation_security_groups.zip"
}

resource "aws_lambda_function" "automation_security_groups" {
  function_name    = "${var.project_name}-automation-security-groups"
  role             = aws_iam_role.automation_master.arn
  handler          = "lambda_function.lambda_handler"
  timeout          = 900
  runtime          = "python3.9"

  filename         = "${data.archive_file.automation_security_groups.output_path}"
  source_code_hash = "${data.archive_file.automation_security_groups.output_base64sha256}"

  environment {
    variables = {
      project_name         = "${var.project_name}"
      region               = "${var.region}"
      org_account_id       = "${var.org_account_id}"
      member_role_name     = "${aws_iam_role.automation.name}"
      ses_region           = "${local.ses_region}"
      alert_sender         = "${var.alert_sender}"
      alert_recipients     = "${jsonencode(var.alert_recipients)}"
      principal_exceptions = "${jsonencode(var.secgroup_automation_principal_exceptions)}"
      monitored_ports      = "${jsonencode(var.secgroup_automation_monitored_ports)}"
    }
  }
}

resource "aws_lambda_permission" "automation_event_rules" {
  statement_id  = "AllowExecutionFromEvents"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.automation_security_groups.function_name
  principal     = "events.amazonaws.com"
  source_arn    = "arn:aws:events:${var.region}:${var.org_account_id}:rule/${var.project_name}-automation-security-groups"
}

resource "aws_cloudwatch_event_rule" "automation_event_rules" {
  name          = "${var.project_name}-automation-security-groups"
  description   = "Security Group Automation"
  is_enabled    = false
  event_pattern = <<EOF
{
  "source": [
    "aws.ec2"
  ],
  "detail-type": [
    "AWS API Call via CloudTrail"
  ],
  "detail": {
    "eventSource": [
      "ec2.amazonaws.com"
    ],
    "eventName": [
      "AuthorizeSecurityGroupIngress"
    ]
  }
}
EOF
}

resource "aws_cloudwatch_event_target" "automation_event_rules" {
  depends_on = [aws_cloudwatch_event_rule.automation_event_rules]

  rule       = "${var.project_name}-automation-security-groups"
  target_id  = "${var.project_name}-automation-security-groups"
  arn        = aws_lambda_function.automation_security_groups.arn
}

