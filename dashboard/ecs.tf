resource "aws_ecs_cluster" "main" {
  name = "${var.project_name}-cluster"
}

resource "aws_ecs_task_definition" "main" {
  depends_on               = [aws_ecr_repository.main]
  family                   = "${var.project_name}-service"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_role.arn
  container_definitions = jsonencode([{
    name        = "${var.project_name}-container"
    image       = "${var.org_account_id}.dkr.ecr.${var.region}.amazonaws.com/${var.project_name}-dashboard:latest"
    essential   = true
    environment = [{
        name  = "PROJECT_NAME"
        value = "${var.project_name}"
      },
      {
        name  = "ACCOUNT_ID"
        value = "${var.org_account_id}"
      },
      {
        name  = "REGION"
        value = "${var.region}"
      },
      {
        name  = "DASHBOARD_DOMAIN"
        value = join(".", ["dashboard", data.aws_route53_zone.selected.name])
      },
      {
        name  = "STATIC_FILES_DOMAIN"
        value = aws_cloudfront_distribution.static_files.domain_name
      }
    ]
    logConfiguration = {
      "logDriver" = "awslogs"
      "options" = {
        "awslogs-group"         = "${var.project_name}-dashboard-container"
        "awslogs-region"        = "${var.region}"
        "awslogs-stream-prefix" = "streaming"
        "awslogs-create-group"  = "true"
      }
    }
   portMappings = [{
     protocol      = "tcp"
     containerPort = 8000
     hostPort      = 8000
    }]
  }])

 lifecycle {
   ignore_changes = [id,arn,revision,container_definitions,tags_all]
 }
}

resource "aws_ecs_service" "main" {
 name                               = "${var.project_name}-service"
 cluster                            = aws_ecs_cluster.main.id
 task_definition                    = aws_ecs_task_definition.main.arn
 desired_count                      = 2
 deployment_minimum_healthy_percent = 50
 deployment_maximum_percent         = 200
 launch_type                        = "FARGATE"
 scheduling_strategy                = "REPLICA"
 
 network_configuration {
    subnets          = aws_subnet.public.*.id
    security_groups  = [aws_security_group.ecs_tasks.id]
    assign_public_ip = true
 }
 
 load_balancer {
   target_group_arn = aws_alb_target_group.main.arn
   container_name   = "${var.project_name}-container"
   container_port   = var.container_port
 }
 
 lifecycle {
   ignore_changes = [task_definition,desired_count]
 }
}

resource "aws_iam_role" "ecs_task_role" {
  name = "${var.project_name}-ecs-task"
 
  assume_role_policy = <<EOF
{
 "Version": "2012-10-17",
 "Statement": [
   {
     "Action": "sts:AssumeRole",
     "Principal": {
       "Service": "ecs-tasks.amazonaws.com"
     },
     "Effect": "Allow",
     "Sid": ""
   }
 ]
}
EOF
}
 
resource "aws_iam_role_policy" "ecs_task_role" {
  name        = "${var.project_name}-task-policy"
  role = aws_iam_role.ecs_task_role.id
 
 policy = <<EOF
{
   "Version": "2012-10-17",
   "Statement": [
      {
        "Effect": "Allow",
        "Resource": [
          "*"
        ],
        "Action": [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
      },
      {
        "Effect": "Allow",
        "Resource": [
          "arn:aws:dynamodb:${var.region}:${var.org_account_id}:table/${var.project_name}-events",
          "arn:aws:dynamodb:${var.region}:${var.org_account_id}:table/${var.project_name}-report-*"
        ],
        "Action": [
          "dynamodb:Scan",
          "dynamodb:GetItem"
        ]
      },
      {
        "Effect": "Allow",
        "Resource": [
          "arn:aws:states:${var.region}:${var.org_account_id}:stateMachine:${var.project_name}-report-*"
        ],
        "Action": [
          "states:ListExecutions",
          "states:StartExecution"
        ]
      },
      {
        "Action": [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ],
        "Effect": "Allow",
        "Resource": "${var.dynamodb_key_arn}"
      }
   ]
}
EOF
}


resource "aws_iam_role" "ecs_task_execution_role" {
  name = "${var.project_name}-ecs-task-execution"
 
  assume_role_policy = <<EOF
{
 "Version": "2012-10-17",
 "Statement": [
   {
     "Action": "sts:AssumeRole",
     "Principal": {
       "Service": "ecs-tasks.amazonaws.com"
     },
     "Effect": "Allow",
     "Sid": ""
   }
 ]
}
EOF
}

resource "aws_iam_role_policy" "ecs_task_execution" {
  name        = "${var.project_name}-task-execution-policy"
  role = aws_iam_role.ecs_task_execution_role.id
 
 policy = <<EOF
{
   "Version": "2012-10-17",
   "Statement": [
      {
        "Effect": "Allow",
        "Resource": [
          "*"
        ],
        "Action": [
          "logs:CreateLogGroup"
        ]
      }
   ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "ecs-task-execution-role-policy-attachment" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}