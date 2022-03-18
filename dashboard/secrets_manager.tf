resource "aws_secretsmanager_secret" "dockerhub_password" {
  name = "${var.project_name}-dockerhub-password"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "dockerhub_password" {
  secret_id     = aws_secretsmanager_secret.dockerhub_password.id
  secret_string = "${var.dockerhub_password}"
}