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
  role          = aws_iam_role.reports.arn
  handler       = "lambda_function.lambda_handler"
  timeout       = 900
  runtime       = "python3.9"

  filename         = "${data.archive_file.reports.output_path}"
  source_code_hash = "${data.archive_file.reports.output_base64sha256}"

  environment {
    variables = {
      project_name      = "${var.project_name}"
      region            = "${var.region}"
      ses_region        = "${local.ses_region}"
      dynamodb_table    = "${aws_dynamodb_table.reports.name}"
    }
  }
}

##################
# Step Functions
##################
