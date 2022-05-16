#########################################################################
# Conditionally create StackSet Roles using var.create_cf_stackset_roles
#########################################################################
resource "aws_iam_role" "AWSCloudFormationStackSetAdministrationRole" {
  count = var.create_cf_stackset_roles ? 1 : 0 # toggle in root variables.tf
  name = "AWSCloudFormationStackSetAdministrationRole"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudformation.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "AWSCloudFormationStackSetAdministrationRole" {
  count = var.create_cf_stackset_roles ? 1 : 0 # toggle in root variables.tf
  name = "AWSCloudFormationStackSetAdministrationRole"
  role = aws_iam_role.AWSCloudFormationStackSetAdministrationRole[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "sts:AssumeRole",
        ]
        Effect   = "Allow"
        Resource = [
                "arn:aws:iam::*:role/AWSCloudFormationStackSetExecutionRole",
            ]
      },
    ]
  })
}

resource "aws_iam_role" "AWSCloudFormationStackSetExecutionRole" {
  count = var.create_cf_stackset_roles ? 1 : 0 # toggle in root variables.tf
  name = "AWSCloudFormationStackSetExecutionRole"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${var.org_account_id}:root"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "AWSCloudFormationStackSetExecutionRole" {
  count = var.create_cf_stackset_roles ? 1 : 0 # toggle in root variables.tf
  name = "AWSCloudFormationStackSetExecutionRole"
  role = aws_iam_role.AWSCloudFormationStackSetExecutionRole[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "cloudformation:*",
          "s3:*",
          "sns:*",
          "events:*",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
      {
        Action = [
          "iam:PassRole",
        ]
        Effect   = "Allow"
        Resource = "arn:aws:iam::${var.org_account_id}:role/${var.project_name}-event-bus-sender"
      },
    ]
  })
}

#############################
# Event Bus Role
#############################
resource "aws_iam_role" "event_bus_sender" {
  name = "${var.project_name}-event-bus-sender"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "events.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "event_bus_sender" {
  name = "${var.project_name}-event-bus-sender"
  role = aws_iam_role.event_bus_sender.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "events:PutEvents",
        ]
        Effect   = "Allow"
        Resource = [
                "arn:aws:events:us-east-1:${var.org_account_id}:event-bus/default",
            ]
      },
    ]
  })
}

#############################
# Event Parse Role Resources
#############################
resource "aws_iam_role" "event_parse" {
  name = "${var.project_name}-event-parse"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "event_parse" {
  name = "${var.project_name}-event-parse"
  role = aws_iam_role.event_parse.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem"
        ]
        Effect   = "Allow"
        Resource = [
                "arn:aws:dynamodb:us-east-1:${var.org_account_id}:table/${var.project_name}-events"
            ]
      },
      {
        Action = [
          "ses:SendEmail"
        ]
        Effect   = "Allow"
        Resource = "*"
      },
      {
        Action = [
          "organizations:DescribeAccount"
        ]
        Effect   = "Allow"
        Resource = "*"
      },
      {
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Effect   = "Allow"
        Resource = "${aws_kms_key.dynamodb.arn}"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "event_parse_AWSLambdaBasicExecutionRole" {
  role       = aws_iam_role.event_parse.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

##############################
# Email Summary Role Resources
##############################
resource "aws_iam_role" "email_summary" {
  name = "${var.project_name}-email-summary"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "email_summary" {
  name = "${var.project_name}-email-summary"
  role = aws_iam_role.email_summary.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "dynamodb:Scan"
        ]
        Effect   = "Allow"
        Resource = [
                "arn:aws:dynamodb:us-east-1:${var.org_account_id}:table/${var.project_name}-events"
            ]
      },
      {
        Action = [
          "ses:SendEmail"
        ]
        Effect   = "Allow"
        Resource = "*"
      },
      {
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Effect   = "Allow"
        Resource = "${aws_kms_key.dynamodb.arn}"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "email_summary_AWSLambdaBasicExecutionRole" {
  role       = aws_iam_role.email_summary.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

##############################
# EventBridge to Lambda
##############################
resource "aws_iam_role" "eventbridge_lambda" {
  name = "${var.project_name}-eventbridge-lambda"

  assume_role_policy = <<DOC
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "events.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
DOC
}

data "aws_iam_policy_document" "eventbridge_lambda" {
  statement {
    # Allow EventBridge to invoke lambda parse
    actions = [
      "lambda:InvokeFunction"
    ]
    resources = [
      aws_lambda_function.event_parse.arn
    ]
  }
}

resource "aws_iam_policy" "eventbridge_lambda" {
  name = "${var.project_name}-eventbridge-lambda"
  policy = data.aws_iam_policy_document.eventbridge_lambda.json
}

resource "aws_iam_role_policy_attachment" "eventbridge_lambda" {
  policy_arn = aws_iam_policy.eventbridge_lambda.arn
  role = aws_iam_role.eventbridge_lambda.name
}

##############################
# Report Automation Master
##############################
resource "aws_iam_role" "report_automation_master" {
  name = "${var.project_name}-report-automation-master"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "report_automation_master" {
  name = "${var.project_name}-report-automation-master"
  role = aws_iam_role.report_automation_master.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "dynamodb:Scan",
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
          "dynamodb:BatchWriteItem",
          "dynamodb:CreateTable",
          "dynamodb:DeleteTable",
          "dynamodb:DescribeTable"
        ]
        Effect   = "Allow"
        Resource = [
            "arn:aws:dynamodb:us-east-1:${var.org_account_id}:table/${var.project_name}-report-*"
        ]
      },
      {
        Action = [
          "sts:AssumeRole"
        ]
        Effect   = "Allow"
        Resource = [
            "arn:aws:iam::*:role/${var.project_name}-report-automation"
        ]
      },
      {
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
          "kms:CreateGrant"
        ]
        Effect   = "Allow"
        Resource = "${aws_kms_key.dynamodb.arn}"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "report_automation_master_AWSLambdaBasicExecutionRole" {
  role       = aws_iam_role.report_automation_master.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

##############################
# Report Automation
##############################
resource "aws_iam_role" "report_automation" {
  name = "${var.project_name}-report-automation"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "AWS": "${aws_iam_role.report_automation_master.arn}"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "report_automation" {
  name = "${var.project_name}-report-automation"
  role = aws_iam_role.report_automation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "iam:ListUsers",
          "iam:ListUserPolicies",
          "iam:ListAttachedUserPolicies",
          "iam:GetUserPolicy",
          "iam:GetPolicy",
          "iam:GetPolicyVersion",
          "iam:ListGroupsForUser",
          "iam:ListGroupPolicies",
          "iam:ListAttachedGroupPolicies",
          "iam:GetGroupPolicy",
          "iam:ListAccessKeys",
          "iam:GetAccessKeyLastUsed",
          "iam:GetLoginProfile",
          "iam:ListMFADevices",
          "ec2:DescribeRegions",
          "ec2:DescribeInstances",
          "ec2:DescribeImages",
          "ec2:DescribeSecurityGroups",
          "rds:DescribeDBSecurityGroups",
          "ce:GetCostAndUsage"
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}


###################################
# Automation Master
# *Used for config type automation
###################################
resource "aws_iam_role" "automation_master" {
  name = "${var.project_name}-automation-master"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "automation_master" {
  name = "${var.project_name}-automation-master"
  role = aws_iam_role.automation_master.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "sts:AssumeRole"
        ]
        Effect   = "Allow"
        Resource = [
            "arn:aws:iam::*:role/${var.project_name}-automation"
        ]
      },
      {
        Action = [
          "organizations:DescribeAccount"
        ]
        Effect   = "Allow"
        Resource = "*"
      },
      {
        Action = [
          "ses:SendEmail"
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "automation_master_AWSLambdaBasicExecutionRole" {
  role       = aws_iam_role.automation_master.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

##############################
# Automation member role
##############################
resource "aws_iam_role" "automation" {
  name = "${var.project_name}-automation"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "AWS": "${aws_iam_role.automation_master.arn}"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "automation" {
  name = "${var.project_name}-automation"
  role = aws_iam_role.automation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ec2:DescribeSecurityGroups",
          "ec2:RevokeSecurityGroupIngress"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}



################################
# Report Schedule Event
################################
resource "aws_iam_role" "report_scheduled_event" {
  name = "${var.project_name}-report-scheduled-event"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": [
          "events.amazonaws.com",
          "lambda.amazonaws.com"
        ]
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "report_scheduled_event" {
  name = "${var.project_name}-report-scheduled-event"
  role = aws_iam_role.report_scheduled_event.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "states:StartExecution"
        ]
        Effect   = "Allow"
        Resource = "arn:aws:states:${var.region}:${var.org_account_id}:stateMachine:${var.project_name}-report-*"
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "report_scheduled_event_AWSLambdaBasicExecutionRole" {
  role       = aws_iam_role.report_scheduled_event.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}




################################
# Report States (Step Functions)
################################
resource "aws_iam_role" "report_states" {
  name = "${var.project_name}-report-states"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "states.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "report_states" {
  name = "${var.project_name}-report-states"
  role = aws_iam_role.report_states.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "lambda:InvokeFunction"
        ]
        Effect   = "Allow"
        Resource = [
        "${aws_lambda_function.reports.arn}:$LATEST"
        ]
      },
      {
        Action = [
          "organizations:ListAccounts"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "report_state_AWSLambdaBasicExecutionRole" {
  role       = aws_iam_role.report_states.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}