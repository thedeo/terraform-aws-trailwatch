resource "aws_codepipeline" "codepipeline" {
  depends_on = [
    aws_iam_role_policy.codepipeline_policy,
    aws_iam_role.codepipeline_role
  ]

  name     = "${var.project_name}-dashboard"
  role_arn = aws_iam_role.codepipeline_role.arn

  artifact_store {
    location = aws_s3_bucket.codepipeline_bucket.bucket
    type     = "S3"

    # encryption_key {
    #   id   = aws_kms_key.key.arn
    #   type = "KMS"
    # }
  }

  stage {
    name = "Source"

    action {
      name             = "Source"
      category         = "Source"
      owner            = "AWS"
      provider         = "S3"
      version          = "1"
      output_artifacts = ["source_output"]

      configuration = {
        S3Bucket                   = "${var.project_name}-resources"
        S3ObjectKey                = "${aws_s3_object.source_code.id}"
        PollForSourceChanges       = false
      }
    }
  }

  stage {
    name = "Build"

    action {
      name             = "Build"
      category         = "Build"
      owner            = "AWS"
      provider         = "CodeBuild"
      input_artifacts  = ["source_output"]
      output_artifacts = ["build_output"]
      version          = "1"

      configuration = {
        ProjectName = "${var.project_name}-dashboard"
      }
    }
  }

  stage {
    name = "Deploy"

    action {
      name            = "Deploy"
      category        = "Deploy"
      owner           = "AWS"
      provider        = "ECS"
      input_artifacts = ["build_output"]
      version         = "1"

      configuration = {
        ClusterName   = "${var.project_name}-cluster"
        ServiceName   = "${var.project_name}-service"
        FileName      = "imagedefinitions.json"
      }
    }
  }
}

# Code changes in s3 start code pipeline
resource "aws_cloudwatch_event_rule" "codepipeline" {
  name          = "${var.project_name}-dashboard-codepipeline"
  description   = "When s3 source code is uploaded, start codepipeline."
  event_pattern = <<EOF
{
  "source": ["aws.s3"],
  "detail-type": ["Object Created"],
  "detail": {
    "bucket": {
      "name": ["${var.project_name}-resources"]
    }
  }
}
EOF
}

resource "aws_cloudwatch_event_target" "codepipeline" {
  depends_on = [aws_cloudwatch_event_rule.codepipeline]

  rule       = "${var.project_name}-dashboard-codepipeline"
  target_id  = "${var.project_name}-dashboard-codepipeline"
  arn        = aws_codepipeline.codepipeline.arn
  role_arn  = aws_iam_role.eventbridge_codepipeline.arn
}

resource "aws_kms_key" "key" {
  description             = "${var.project_name}-codepipeline"
  deletion_window_in_days = 10
}

resource "aws_iam_role" "codepipeline_role" {
  name = "${var.project_name}-codepipeline"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "codepipeline.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "codepipeline_policy" {
  name = "${var.project_name}-codepipeline"
  role = aws_iam_role.codepipeline_role.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect":"Allow",
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
      "Effect": "Allow",
      "Action": [
        "codebuild:BatchGetBuilds",
        "codebuild:StartBuild"
      ],
      "Resource": "*"
    },
    {
      "Action": "ecs:*",
      "Resource": "*",
      "Effect": "Allow"
    },
    {
      "Action": [
        "iam:PassRole"
      ],
      "Resource": [
        "${aws_iam_role.ecs_task_role.arn}",
        "${aws_iam_role.ecs_task_execution_role.arn}",
        "*"
      ],
      "Effect": "Allow"
    }
  ]
}
EOF
}

# Allows the EventBridge event to assume roles
resource "aws_iam_role" "eventbridge_codepipeline" {
  name = "${var.project_name}-eventbridge-codepipeline"

  assume_role_policy = <<DOC
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "events.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
DOC
}
data "aws_iam_policy_document" "eventbridge_codepipeline" {
  statement {
    actions = [
      "iam:PassRole"
    ]
    resources = [
      "*"
    ]
  }
  statement {
    # Allow EventBridge to start the Pipeline
    actions = [
      "codepipeline:StartPipelineExecution"
    ]
    resources = [
      aws_codepipeline.codepipeline.arn
    ]
  }
}
resource "aws_iam_policy" "eventbridge_codepipeline" {
  name = "${var.project_name}-eventbridge-codepipeline"
  policy = data.aws_iam_policy_document.eventbridge_codepipeline.json
}
resource "aws_iam_role_policy_attachment" "eventbridge_codepipeline" {
  policy_arn = aws_iam_policy.eventbridge_codepipeline.arn
  role = aws_iam_role.eventbridge_codepipeline.name
}