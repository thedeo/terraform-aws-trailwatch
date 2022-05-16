locals {
  ses_region = element(split(":", "${var.ses_identity_arn}"), 3)
}