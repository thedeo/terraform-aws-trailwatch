# In order for the protections to be applied you have to manually enable SCPs
# for the AWS Organization since the APIs do not enable SCPs at the account level.
# For not it appears that this can only be enabled in the console manually.
resource "aws_organizations_policy" "protections" {
  name = "${var.project_name}-protections"

  content = <<CONTENT
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyStacks",
      "Effect": "Deny",
      "Action": [
        "cloudformation:*"
      ],
      "Resource": [
        "arn:aws:cloudformation:*:*:stack/StackSet-${var.project_name}*",
        "arn:aws:cloudformation:*:*:stack/${var.project_name}*"
      ],
      "Condition": {
        "ForAnyValue:StringNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::*:role/AWSCloudFormationStackSetExecutionRole",
            "arn:aws:iam::*:role/${var.project_name}-automation",
            "arn:aws:iam::*:role/stacksets-exec-*",
            "arn:aws:iam::*:role/OrganizationAccountAccessRole"
          ]
        }
      }
    },
    {
      "Sid": "DenyDisableEventRules",
      "Effect": "Deny",
      "Action": [
        "events:DeleteRule",
        "events:DisableRule",
        "events:RemoveTargets"
      ],
      "Resource": [
        "arn:aws:events:*:*:rule/StackSet-${var.project_name}*",
        "arn:aws:events:*:*:rule/${var.project_name}-*"
      ],
      "Condition": {
        "StringNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::*:role/AWSCloudFormationStackSetExecutionRole",
            "arn:aws:iam::*:role/${var.project_name}-automation",
            "arn:aws:iam::*:role/stacksets-exec-*",
            "arn:aws:iam::*:role/OrganizationAccountAccessRole"
          ]
        }
      }
    }
  ]
}
CONTENT
}

resource "aws_organizations_policy_attachment" "root" {
  policy_id = aws_organizations_policy.protections.id
  target_id = var.org_root_id
}