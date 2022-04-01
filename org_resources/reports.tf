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
  "Comment": "AWS Account Report State Machine",
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

resource "aws_sfn_state_machine" "report_user" {
  name     = "${var.project_name}-report-user"
  role_arn = aws_iam_role.report_states.arn

  tags = {
    friendly_name = "IAM User Report"
    description = "Report of all IAM users showing at-a-glance permissions and key/password ages across the entire AWS Org."
  }

  definition = <<EOF
{
  "Comment": "AWS Account Report State Machine",
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
            "Next": "Get User Lists",
            "Parameters": {
              "payload.$": "$",
              "report_type": "user",
              "mode": "a"
            }
          },
          "Get User Lists": {
            "Type": "Task",
            "Resource": "arn:aws:states:::lambda:invoke",
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
            "Next": "Distribute User Lists Among Lambdas"
          },
          "Distribute User Lists Among Lambdas": {
            "Type": "Map",
            "End": true,
            "Iterator": {
              "StartAt": "Analyze and store user data",
              "States": {
                "Analyze and store user data": {
                  "Type": "Task",
                  "Resource": "arn:aws:states:::lambda:invoke",
                  "Parameters": {
                    "FunctionName": "${aws_lambda_function.reports.arn}:$LATEST",
                    "Payload.$": "$"
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
            "ItemsPath": "$.Payload.user_lists",
            "Parameters": {
              "account_id.$": "$.Payload.account_id",
              "account_name.$": "$.Payload.account_name",
              "account_alias.$": "$.Payload.account_alias",
              "report_type.$": "$.Payload.report_type",
              "mode.$": "$.Payload.mode",
              "user_list.$": "$$.Map.Item.Value"
            }
          }
        }
      },
      "InputPath": "$.Accounts",
      "End": true
    }
  }
}
EOF
}