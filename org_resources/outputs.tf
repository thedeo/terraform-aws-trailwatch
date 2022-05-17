output "dynamodb_key_arn" {
  value = aws_kms_key.dynamodb.arn
}

output "automations" {
  value = var.automations
}