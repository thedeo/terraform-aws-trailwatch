resource "aws_kms_key" "dynamodb" {
  description             = "${var.project_name}-dynamodb"
  deletion_window_in_days = 7
}

resource "aws_kms_alias" "dynamodb" {
  name          = "alias/${var.project_name}-dynamodb"
  target_key_id = aws_kms_key.dynamodb.key_id
}