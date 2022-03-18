resource "aws_codebuild_project" "project" {
  depends_on    = [aws_iam_role.codebuild,aws_iam_role_policy.codebuild]

  name          = "${var.project_name}-dashboard"
  description   = "Build docker image for ${var.project_name} and push to ecr."
  build_timeout = "15" # minutes
  service_role  = aws_iam_role.codebuild.arn

  source {
    type = "CODEPIPELINE"
  }

  artifacts {
    type = "CODEPIPELINE"
  }

  environment {
    privileged_mode             = true
    compute_type                = "BUILD_GENERAL1_SMALL"
    image                       = "aws/codebuild/standard:5.0"
    type                        = "LINUX_CONTAINER"
    image_pull_credentials_type = "CODEBUILD"

    environment_variable {
      name  = "DOCKERHUB_USERNAME"
      value = "${var.dockerhub_username}"
    }

    environment_variable {
      name  = "DOCKERHUB_PASSWORD"
      value = "${var.project_name}-dockerhub-password"
      type  = "SECRETS_MANAGER"
    }

    environment_variable {
      name  = "PROJECT_NAME"
      value = "${var.project_name}"
    }

    environment_variable {
      name  = "ORG_ACCOUNT_ID"
      value = "${var.org_account_id}"
    }

    environment_variable {
      name  = "REGION"
      value = "${var.region}"
    }

    environment_variable {
      name  = "REPOSITORY_URL"
      value = "${aws_ecr_repository.main.repository_url}"
    }
  }

  logs_config {
    cloudwatch_logs {
      group_name  = "${var.project_name}-dashboard"
      stream_name = "build"
    }
  }

  # vpc_config {
  #   vpc_id             = aws_vpc.main.id
  #   subnets            = aws_subnet.public.*.id
  #   security_group_ids = aws_security_group.codebuild.*.id
  # }
}

resource "aws_iam_role" "codebuild" {
  name = "${var.project_name}-codebuild"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "codebuild.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "codebuild" {
  role = aws_iam_role.codebuild.name

  policy = <<POLICY
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
        "logs:PutLogEvents"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "ec2:CreateNetworkInterface",
        "ec2:DescribeDhcpOptions",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DeleteNetworkInterface",
        "ec2:DescribeSubnets",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVpcs"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ec2:CreateNetworkInterfacePermission"
      ],
      "Resource": [
        "arn:aws:ec2:${var.region}:${var.org_account_id}:network-interface/*"
      ],
      "Condition": {
        "StringEquals": {
          "ec2:Subnet": [
            "${aws_subnet.public[0].arn}",
            "${aws_subnet.public[1].arn}"
          ],
          "ec2:AuthorizedService": "codebuild.amazonaws.com"
        }
      }
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:GetBucketVersioning",
        "s3:PutObjectAcl",
        "s3:PutObject"
      ],
      "Resource": [
        "${aws_s3_bucket.codepipeline_bucket.arn}",
        "${aws_s3_bucket.codepipeline_bucket.arn}/*",
        "${aws_s3_bucket.resources.arn}",
        "${aws_s3_bucket.resources.arn}/*"
      ]
    },
    {
      "Action": [
        "ecr:BatchCheckLayerAvailability",
        "ecr:CompleteLayerUpload",
        "ecr:GetAuthorizationToken",
        "ecr:InitiateLayerUpload",
        "ecr:PutImage",
        "ecr:UploadLayerPart"
      ],
      "Effect": "Allow",
      "Resource": ["arn:aws:ecr:${var.region}:${var.org_account_id}:repository/${var.project_name}-dashboard"]
    },
    {
      "Action": [
        "ecr:GetAuthorizationToken"
      ],
      "Effect": "Allow",
      "Resource": "*"
    },
    {
        "Effect": "Allow",
        "Action": [
            "secretsmanager:GetSecretValue"
        ],
        "Resource": [
            "${aws_secretsmanager_secret.dockerhub_password.arn}"
        ]
    }
  ]
}
POLICY
}