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
          "ses:SendEmail",
          "dynamodb:PutItem",
          "dynamodb:GetItem"
        ]
        Effect   = "Allow"
        Resource = [
                "${var.ses_identity_arn}",
                "arn:aws:dynamodb:us-east-1:${var.org_account_id}:table/${var.project_name}-events"
            ]
      },
      {
        Action = [
          "organizations:DescribeAccount"
        ]
        Effect   = "Allow"
        Resource = "*"
      },
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
        Resource = [
                "*" # you may want to limit this if you have multiple domains
            ]
      },
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
    actions = [
      "iam:PassRole"
    ]
    resources = [
      "*"
    ]
  }
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