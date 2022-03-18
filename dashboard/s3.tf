data "archive_file" "source_code" {
  type        = "zip"
  source_dir = "${path.module}/code/dashboard/"
  output_path = "${path.module}/code/zipped/dashboard_source_code.zip"
}

resource "aws_s3_bucket" "resources" {
  bucket = "${var.project_name}-resources"
  
}

resource "aws_s3_bucket_notification" "resources" {
  bucket = aws_s3_bucket.resources.id
  eventbridge = true
}

resource "aws_s3_bucket" "dashboard" {
  bucket = "${var.project_name}-dashboard"
}

resource "aws_s3_bucket" "codepipeline_bucket" {
  bucket        = "${var.project_name}-codepipeline"
  force_destroy = true
}

resource "aws_s3_bucket_versioning" "resources" {
  bucket = aws_s3_bucket.resources.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_object" "source_code" {
  depends_on = [
    aws_s3_bucket.resources,
    data.archive_file.source_code,
    aws_ecs_task_definition.main
  ]
  bucket     = aws_s3_bucket.resources.id
  key        = "${var.project_name}_dashboard_source_code.zip"
  source     = "${path.module}/code/zipped/dashboard_source_code.zip"

  # update if file changes
  etag = filemd5("${path.module}/code/zipped/dashboard_source_code.zip")
}

locals {
  upload_directory = "${path.module}/code/dashboard/static/"
  mime_types = {
    htm      = "text/html"
    html     = "text/html"
    css      = "text/css"
    ttf      = "font/ttf"
    js       = "application/javascript"
    map      = "application/javascript"
    json     = "application/json"
    png      = "image/png"
    svg      = "image/svg+xml"
    ico      = "image/x-icon"
    woff     = "font/woff"
    txt      = "text/plain"
    md       = "text/markdown"
    DS_Store = "text/plain"
  }
}

resource "aws_s3_object" "static_files" {
  for_each      = fileset(local.upload_directory, "**/*.*")
  bucket        = aws_s3_bucket.dashboard.bucket
  key           = "static/${replace(each.value, local.upload_directory, "")}"
  source        = "${local.upload_directory}${each.value}"
  etag          = filemd5("${local.upload_directory}${each.value}")
  content_type  = lookup(local.mime_types, split(".", each.value)[length(split(".", each.value)) - 1])
}

resource "aws_cloudfront_distribution" "static_files" {
  origin {
      domain_name = aws_s3_bucket.dashboard.bucket_regional_domain_name
      origin_id = "S3-${aws_s3_bucket.dashboard.bucket}"
      s3_origin_config {
        origin_access_identity = aws_cloudfront_origin_access_identity.dashboard.cloudfront_access_identity_path
      }
  }
  enabled = true
  # If there is a 404, return index.html with a HTTP 200 Response
  custom_error_response {
      error_caching_min_ttl = 3000
      error_code = 404
      response_code = 200
      response_page_path = "/index.html"
  }
  default_cache_behavior {
    allowed_methods = ["GET", "HEAD"]
    cached_methods = ["GET", "HEAD"]
    target_origin_id = "S3-${aws_s3_bucket.dashboard.bucket}"
    # Forward all query strings, cookies and headers
    viewer_protocol_policy = "allow-all"
    min_ttl = 0
    default_ttl = 3600
    max_ttl = 86400

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }
  }
  # SSL certificate for the service.
  viewer_certificate {
      cloudfront_default_certificate = true
  }

  restrictions {
    geo_restriction {
      restriction_type = "whitelist"
      locations        = ["US", "CA", "GB", "DE"]
    }
  }
}

resource "aws_cloudfront_origin_access_identity" "dashboard" {
  comment = "Used for ${var.project_name} dashboard."
}

data "aws_iam_policy_document" "dashboard" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.dashboard.arn}/*"]

    principals {
      type        = "AWS"
      identifiers = [aws_cloudfront_origin_access_identity.dashboard.iam_arn]
    }
  }
}

resource "aws_s3_bucket_policy" "dashboard" {
  bucket = aws_s3_bucket.dashboard.id
  policy = data.aws_iam_policy_document.dashboard.json

  lifecycle {
    ignore_changes = all
  }
}