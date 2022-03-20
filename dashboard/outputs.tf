output "dashboard_url" {
  value = join(".", ["dashboard", data.aws_route53_zone.selected.name])
}

output "dashboard_vpc_id" {
  value = aws_vpc.main.id
}

output "dashboard_cluster_arn" {
  value = aws_ecs_cluster.main.arn
}


output "dashboard_codepipeline_arn" {
  value = aws_codepipeline.codepipeline.arn
}