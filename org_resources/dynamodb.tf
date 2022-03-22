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

resource "aws_dynamodb_table" "reports" {
  for_each       = local.report_sort_keys

  name           = "${var.project_name}-${each.key}"
  hash_key       = "account_id"
  range_key      = each.value
  billing_mode   = "PAY_PER_REQUEST"

  attribute {
    name = "account_id"
    type = "S"
  }

  attribute {
    name = each.value
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