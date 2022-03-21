output "dashboard_url" {
  value = module.dashboard.dashboard_url
}

output "dashboard_vpc_id" {
  value = module.dashboard.dashboard_vpc_id
}

output "dashboard_ecs_cluster_arn" {
  value = module.dashboard.dashboard_ecs_cluster_arn
}

output "dashboard_codepipeline_arn" {
  value = module.dashboard.dashboard_codepipeline_arn
}