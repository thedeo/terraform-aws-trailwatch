resource "aws_dynamodb_table" "events" {
  name           = "${var.project_name}-events"
  hash_key       = "account_id"
  range_key      = "event_id"
  billing_mode   = "PAY_PER_REQUEST"

  attribute {
    name = "account_id"
    type = "S"
  }

  attribute {
    name = "event_id"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  server_side_encryption {
    enabled = true
    kms_key_arn = aws_kms_key.dynamodb.arn
  }

  lifecycle {
    prevent_destroy = false
  }
}

resource "aws_dynamodb_table" "active_reports" {

  name           = "${var.project_name}-report-active-tables"
  hash_key       = "report_type"
  billing_mode   = "PAY_PER_REQUEST"

  attribute {
    name = "report_type"
    type = "S"
  }

  server_side_encryption {
    enabled = true
    kms_key_arn = aws_kms_key.dynamodb.arn
  }

  lifecycle {
    prevent_destroy = false
  }
}

