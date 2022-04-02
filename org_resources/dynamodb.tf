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

  lifecycle {
    prevent_destroy = true
  }
}


locals {
  report_sort_keys = {
    account       = "account_alias"
    user          = "user_arn"
    ami           = "instance_id"
    securitygroup = "rule_id"
  }
}

resource "aws_dynamodb_table" "active_reports" {

  name           = "${var.project_name}-report-active-table"
  hash_key       = "report_type"
  billing_mode   = "PAY_PER_REQUEST"

  attribute {
    name = "report_type"
    type = "S"
  }

  lifecycle {
    prevent_destroy = true
  }
}