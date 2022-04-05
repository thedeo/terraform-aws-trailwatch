###################
# Run Reports Once
###################
resource "aws_lambda_invocation" "start_state_machines" {
  for_each = var.reports

  function_name = aws_lambda_function.start_state_machines.function_name
  input = jsonencode({
    report_type = each.value
    state_machine_arn = "arn:aws:states:${var.region}:${var.org_account_id}:stateMachine:${var.project_name}-report-${each.value}"
  })

  lifecycle {
    ignore_changes = all
  }
}


##################
# Lambda
##################
data "archive_file" "reports" {
  type        = "zip"
  source_dir  = "${path.module}/lambdas/source/reports/"
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

# The following will only run once during the first tf apply.
data "archive_file" "start_state_machines" {
  type        = "zip"
  source_dir  = "${path.module}/lambdas/source/start_state_machines/"
  output_path = "${path.module}/lambdas/zipped/start_state_machines.zip"
}

resource "aws_lambda_function" "start_state_machines" {
  function_name = "${var.project_name}-start-state-machines"
  role          = aws_iam_role.report_scheduled_event.arn
  handler       = "lambda_function.lambda_handler"
  timeout       = 900
  runtime       = "python3.9"

  filename         = "${data.archive_file.start_state_machines.output_path}"
  source_code_hash = "${data.archive_file.start_state_machines.output_base64sha256}"

  environment {
    variables = {
      project_name      = "${var.project_name}"
      region            = "${var.region}"
      org_account_id    = "${var.org_account_id}"
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
  "StartAt": "Bootstrap Report",
  "States": {
    "Bootstrap Report": {
      "Type": "Task",
      "Resource": "arn:aws:states:::lambda:invoke",
      "Parameters": {
        "FunctionName": "${aws_lambda_function.reports.arn}:$LATEST",
        "Payload": {
          "report_type": "account",
          "mode": "bootstrap"
        }
      },
      "Retry": [
        {
          "ErrorEquals": [
            "Lambda.ServiceException",
            "Lambda.AWSLambdaException",
            "Lambda.SdkClientException"
          ],
          "IntervalSeconds": 2,
          "MaxAttempts": 6,
          "BackoffRate": 2
        }
      ],
      "Next": "ListAccounts",
      "OutputPath": "$.Payload"
    },
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
            "Next": "Analyze Accounts",
            "Parameters": {
              "payload.$": "$",
              "report_type": "account",
              "mode": "a"
            }
          },
          "Analyze Accounts": {
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
      "InputPath": "$.Accounts",
      "Next": "Perform Cleanup"
    },
    "Perform Cleanup": {
      "Type": "Task",
      "Resource": "arn:aws:states:::lambda:invoke",
      "OutputPath": "$.Payload",
      "Parameters": {
        "Payload": {
          "report_type": "account",
          "mode": "cleanup"
        },
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
          "MaxAttempts": 6,
          "BackoffRate": 2
        }
      ],
      "End": true
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
  "Comment": "AWS User Report State Machine",
  "StartAt": "Bootstrap Report",
  "States": {
    "Bootstrap Report": {
      "Type": "Task",
      "Resource": "arn:aws:states:::lambda:invoke",
      "Parameters": {
        "FunctionName": "${aws_lambda_function.reports.arn}:$LATEST",
        "Payload": {
          "report_type": "user",
          "mode": "bootstrap"
        }
      },
      "Retry": [
        {
          "ErrorEquals": [
            "Lambda.ServiceException",
            "Lambda.AWSLambdaException",
            "Lambda.SdkClientException"
          ],
          "IntervalSeconds": 2,
          "MaxAttempts": 6,
          "BackoffRate": 2
        }
      ],
      "Next": "ListAccounts",
      "OutputPath": "$.Payload"
    },
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
              "report_table.$": "$.Payload.report_table",
              "mode.$": "$.Payload.mode",
              "user_list.$": "$$.Map.Item.Value"
            }
          }
        }
      },
      "InputPath": "$.Accounts",
      "Next": "Perform Cleanup"
    },
    "Perform Cleanup": {
      "Type": "Task",
      "Resource": "arn:aws:states:::lambda:invoke",
      "OutputPath": "$.Payload",
      "Parameters": {
        "FunctionName": "${aws_lambda_function.reports.arn}:$LATEST",
        "Payload": {
          "report_type": "user",
          "mode": "cleanup"
        }
      },
      "Retry": [
        {
          "ErrorEquals": [
            "Lambda.ServiceException",
            "Lambda.AWSLambdaException",
            "Lambda.SdkClientException"
          ],
          "IntervalSeconds": 2,
          "MaxAttempts": 6,
          "BackoffRate": 2
        }
      ],
      "End": true
    }
  }
}
EOF
}

resource "aws_sfn_state_machine" "report_ami" {
  name     = "${var.project_name}-report-ami"
  role_arn = aws_iam_role.report_states.arn

  tags = {
    friendly_name = "EC2 AMI Usage Report"
    description = "Report of all AMIs that are in use by instances across the entire AWS Org."
  }

  definition = <<EOF
{
  "Comment": "AWS AMI Report State Machine",
  "StartAt": "Bootstrap Report",
  "States": {
    "Bootstrap Report": {
      "Type": "Task",
      "Resource": "arn:aws:states:::lambda:invoke",
      "Parameters": {
        "FunctionName": "${aws_lambda_function.reports.arn}:$LATEST",
        "Payload": {
          "report_type": "ami",
          "mode": "bootstrap"
        }
      },
      "Retry": [
        {
          "ErrorEquals": [
            "Lambda.ServiceException",
            "Lambda.AWSLambdaException",
            "Lambda.SdkClientException"
          ],
          "IntervalSeconds": 2,
          "MaxAttempts": 6,
          "BackoffRate": 2
        }
      ],
      "Next": "ListAccounts",
      "OutputPath": "$.Payload"
    },
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
            "Next": "Get EC2 Region List",
            "Parameters": {
              "payload.$": "$",
              "report_type": "ami",
              "mode": "a"
            }
          },
          "Get EC2 Region List": {
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
            "Next": "Distribute Region List Among Lambdas"
          },
          "Distribute Region List Among Lambdas": {
            "Type": "Map",
            "End": true,
            "Iterator": {
              "StartAt": "Analyze and store ami data per region",
              "States": {
                "Analyze and store ami data per region": {
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
            "ItemsPath": "$.Payload.region_list",
            "Parameters": {
              "account_id.$": "$.Payload.account_id",
              "account_name.$": "$.Payload.account_name",
              "account_alias.$": "$.Payload.account_alias",
              "report_type.$": "$.Payload.report_type",
              "mode.$": "$.Payload.mode",
              "region.$": "$$.Map.Item.Value"
            }
          }
        }
      },
      "InputPath": "$.Accounts",
      "Next": "Perform Cleanup"
    },
    "Perform Cleanup": {
      "Type": "Task",
      "Resource": "arn:aws:states:::lambda:invoke",
      "OutputPath": "$.Payload",
      "Parameters": {
        "FunctionName": "${aws_lambda_function.reports.arn}:$LATEST",
        "Payload": {
          "report_type": "ami",
          "mode": "cleanup"
        }
      },
      "Retry": [
        {
          "ErrorEquals": [
            "Lambda.ServiceException",
            "Lambda.AWSLambdaException",
            "Lambda.SdkClientException"
          ],
          "IntervalSeconds": 2,
          "MaxAttempts": 6,
          "BackoffRate": 2
        }
      ],
      "End": true
    }
  }
}
EOF
}


resource "aws_sfn_state_machine" "report_securitygroup" {
  name     = "${var.project_name}-report-securitygroup"
  role_arn = aws_iam_role.report_states.arn

  tags = {
    friendly_name = "Security Group Report"
    description = "Report of all Security Group rules across the entire AWS Org."
  }

  definition = <<EOF
{
  "Comment": "Security Group Report State Machine",
  "StartAt": "Bootstrap Report",
  "States": {
    "Bootstrap Report": {
      "Type": "Task",
      "Resource": "arn:aws:states:::lambda:invoke",
      "Parameters": {
        "FunctionName": "${aws_lambda_function.reports.arn}:$LATEST",
        "Payload": {
          "report_type": "securitygroup",
          "mode": "bootstrap"
        }
      },
      "Retry": [
        {
          "ErrorEquals": [
            "Lambda.ServiceException",
            "Lambda.AWSLambdaException",
            "Lambda.SdkClientException"
          ],
          "IntervalSeconds": 2,
          "MaxAttempts": 6,
          "BackoffRate": 2
        }
      ],
      "Next": "ListAccounts",
      "OutputPath": "$.Payload"
    },
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
            "Next": "Get EC2 Region List",
            "Parameters": {
              "payload.$": "$",
              "report_type": "securitygroup",
              "mode": "a"
            }
          },
          "Get EC2 Region List": {
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
            "Next": "Distribute Region List Among Lambdas"
          },
          "Distribute Region List Among Lambdas": {
            "Type": "Map",
            "End": true,
            "Iterator": {
              "StartAt": "Get security group data per region",
              "States": {
                "Get security group data per region": {
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
                  "Next": "Distribute Security Groups Among Lambdas"
                },
                "Distribute Security Groups Among Lambdas": {
                  "Type": "Map",
                  "End": true,
                  "Iterator": {
                    "StartAt": "Analyze security group data",
                    "States": {
                      "Analyze security group data": {
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
                            "MaxAttempts": 6,
                            "BackoffRate": 2
                          }
                        ],
                        "End": true
                      }
                    }
                  },
                  "ItemsPath": "$.Payload.group_lists"
                }
              }
            },
            "ItemsPath": "$.Payload.region_list",
            "Parameters": {
              "account_id.$": "$.Payload.account_id",
              "account_name.$": "$.Payload.account_name",
              "account_alias.$": "$.Payload.account_alias",
              "report_type.$": "$.Payload.report_type",
              "mode.$": "$.Payload.mode",
              "region.$": "$$.Map.Item.Value"
            }
          }
        }
      },
      "InputPath": "$.Accounts",
      "Next": "Perform Cleanup"
    },
    "Perform Cleanup": {
      "Type": "Task",
      "Resource": "arn:aws:states:::lambda:invoke",
      "OutputPath": "$.Payload",
      "Parameters": {
        "FunctionName": "${aws_lambda_function.reports.arn}:$LATEST",
        "Payload": {
          "report_type": "securitygroup",
          "mode": "cleanup"
        }
      },
      "Retry": [
        {
          "ErrorEquals": [
            "Lambda.ServiceException",
            "Lambda.AWSLambdaException",
            "Lambda.SdkClientException"
          ],
          "IntervalSeconds": 2,
          "MaxAttempts": 6,
          "BackoffRate": 2
        }
      ],
      "End": true
    }
  }
}
EOF
}