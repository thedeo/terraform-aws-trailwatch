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
  report_types = [
    {
     report_type = "account"
     sort_key = "account_alias"
    },
    {
     report_type = "user"
     sort_key = "user_arn"
    },
    {
     report_type = "ami"
     sort_key = "instance_id"
    },
    {
     report_type = "securitygroup"
     sort_key = "rule_id"
    }
  ]
}

resource "aws_dynamodb_table" "reports" {
  for_each       = local.report_types

  name           = "${var.project_name}-${each.value.report_type}"
  hash_key       = "account_id"
  range_key      = each.sort_key
  billing_mode   = "PAY_PER_REQUEST"

  attribute {
    name = "account_id"
    type = "S"
  }

  attribute {
    name = each.value.sort_key
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