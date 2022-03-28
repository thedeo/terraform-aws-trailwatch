##################
# Lambda
##################
data "archive_file" "reports" {
  type        = "zip"
  source_dir = "${path.module}/lambdas/source/reports/"
  output_path = "${path.module}/lambdas/zipped/reports.zip"
}

resource "aws_lambda_function" "reports" {
  function_name = "${var.project_name}-reports"
  role          = aws_iam_role.report_automation_master.arn
  handler       = "lambda_function.lambda_handler"
  timeout       = 900
  runtime       = "python3.9"

  filename         = "${data.archive_file.reports.output_path}"
  source_code_hash = "${data.archive_file.reports.output_base64sha256}"

  environment {
    variables = {
      project_name      = "${var.project_name}"
      region            = "${var.region}"
      org_account_id    = "${var.org_account_id}"
      member_role_name  = "${aws_iam_role.report_automation.name}"
    }
  }
}

##################
# Step Functions
##################
resource "aws_sfn_state_machine" "report_account" {
  name     = "${var.project_name}-report-account"
  role_arn = aws_iam_role.report_states.arn

  tags = {
    friendly_name = "Account Report"
    description = "Simple report showing all AWS accounts in an Organization along with the services they are utilizing according to billing."
  }

  definition = <<EOF
{
  "Comment": "A description of my state machine",
  "StartAt": "ListAccounts",
  "States": {
    "ListAccounts": {
      "Type": "Task",
      "Parameters": {},
      "Resource": "arn:aws:states:::aws-sdk:organizations:listAccounts",
      "Next": "Iterate Accounts"
    },
    "Iterate Accounts": {
      "Type": "Map",
      "Iterator": {
        "StartAt": "Inject Report Type",
        "States": {
          "Inject Report Type": {
            "Type": "Pass",
            "Next": "Lambda Invoke",
            "Parameters": {
              "payload.$": "$",
              "report_type": "account"
            }
          },
          "Lambda Invoke": {
            "Type": "Task",
            "Resource": "arn:aws:states:::lambda:invoke",
            "OutputPath": "$.Payload",
            "Parameters": {
              "Payload.$": "$",
              "FunctionName": "${aws_lambda_function.reports.arn}:$LATEST"
            },
            "Retry": [
              {
                "ErrorEquals": [
                  "Lambda.ServiceException",
                  "Lambda.AWSLambdaException",
                  "Lambda.SdkClientException"
                ],
                "IntervalSeconds": 2,
                "MaxAttempts": 3,
                "BackoffRate": 2
              }
            ],
            "End": true
          }
        }
      },
      "End": true,
      "InputPath": "$.Accounts"
    }
  }
}
EOF
}