resource "aws_cloudformation_stack_set_instance" "iam_roles" {
  deployment_targets {
    organizational_unit_ids = [var.org_root_id]
  }

  region         = "us-east-1"
  stack_set_name = aws_cloudformation_stack_set.iam_roles.name
}

resource "aws_cloudformation_stack_set_instance" "global_resources" {
  depends_on     = [aws_cloudformation_stack_set_instance.iam_roles]

  deployment_targets {
    organizational_unit_ids = [var.org_root_id]
  }

  region         = "us-east-1"
  stack_set_name = aws_cloudformation_stack_set.global_resources.name
}

resource "aws_cloudformation_stack_set_instance" "regional_resources" {
  depends_on     = [aws_cloudformation_stack_set_instance.iam_roles]
  for_each       = var.available_regions

  deployment_targets {
    organizational_unit_ids = [var.org_root_id]
  }

  region         = each.key
  stack_set_name = aws_cloudformation_stack_set.regional_resources.name
}


resource "aws_cloudformation_stack_set" "iam_roles" {
  name                    = "${var.project_name}-iam-roles"
  description             = "IAM roles for the ${var.project_name} event monitor."
  capabilities            = ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"]
  permission_model        = "SERVICE_MANAGED"

  lifecycle {
    ignore_changes = [administration_role_arn,call_as]
  }

  auto_deployment {
    enabled = true
    retain_stacks_on_account_removal = false
  }

  template_body = <<TEMPLATE
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "EventBusSenderRole": {
      "Type": "AWS::IAM::Role",
      "Properties": {
        "AssumeRolePolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Principal": {
                "Service": [
                  "events.amazonaws.com"
                ]
              },
              "Action": [
                "sts:AssumeRole"
              ]
            }
          ]
        },
        "Path": "/",
        "MaxSessionDuration": 3600,
        "RoleName": "${var.project_name}-event-bus-sender"
      }
    },
    "EventBusSenderPolicy": {
      "Type": "AWS::IAM::ManagedPolicy",
      "DependsOn": "EventBusSenderRole",
      "Properties": {
        "Description": "Permissions to send events to the organization management account.",
        "ManagedPolicyName": "${var.project_name}-event-bus-sender",
        "Path": "/",
        "Roles": [
          "${var.project_name}-event-bus-sender"
        ],
        "PolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": [
                "events:PutEvents"
              ],
              "Resource": [
                "arn:aws:events:us-east-1:${var.org_account_id}:event-bus/default"
              ]
            }
          ]
        }
      }
    },
    "ReportAutomationRole": {
      "Type": "AWS::IAM::Role",
      "Properties": {
        "AssumeRolePolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Principal": {
                "AWS": [
                  "${aws_iam_role.report_automation_master.arn}"
                ]
              },
              "Action": [
                "sts:AssumeRole"
              ]
            }
          ]
        },
        "Path": "/",
        "MaxSessionDuration": 3600,
        "RoleName": "${aws_iam_role.report_automation.name}"
      }
    },
    "ReportAutomationPolicy": {
      "Type": "AWS::IAM::ManagedPolicy",
      "DependsOn": "ReportAutomationRole",
      "Properties": {
        "Description": "Permissions to pull report data.",
        "ManagedPolicyName": "${aws_iam_role.report_automation.name}",
        "Path": "/",
        "Roles": [
          "${aws_iam_role.report_automation.name}"
        ],
        "PolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": [
                "iam:ListUsers",
                "iam:ListUserPolicies",
                "iam:ListAttachedUserPolicies",
                "iam:GetUserPolicy",
                "iam:GetPolicy",
                "iam:GetPolicyVersion",
                "iam:ListGroupsForUser",
                "iam:ListGroupPolicies",
                "iam:ListAttachedGroupPolicies",
                "iam:GetGroupPolicy",
                "iam:ListAccessKeys",
                "iam:GetAccessKeyLastUsed",
                "iam:GetLoginProfile",
                "iam:ListMFADevices",
                "ec2:DescribeRegions",
                "ec2:DescribeInstances",
                "ec2:DescribeImages",
                "ec2:DescribeSecurityGroups",
                "rds:DescribeDBSecurityGroups",
                "ce:GetCostAndUsage"
              ],
              "Resource": [
                "*"
              ]
            }
          ]
        }
      }
    },
    "AutomationRole": {
      "Type": "AWS::IAM::Role",
      "Properties": {
        "AssumeRolePolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Principal": {
                "AWS": [
                  "${aws_iam_role.automation_master.arn}"
                ]
              },
              "Action": [
                "sts:AssumeRole"
              ]
            }
          ]
        },
        "Path": "/",
        "MaxSessionDuration": 3600,
        "RoleName": "${var.project_name}-automation"
      }
    },
    "AutomationRolePolicy": {
      "Type": "AWS::IAM::ManagedPolicy",
      "DependsOn": "AutomationRole",
      "Properties": {
        "Description": "Permissions to perform ${var.project_name} automations.",
        "ManagedPolicyName": "${var.project_name}-automation",
        "Path": "/",
        "Roles": [
          "${var.project_name}-automation"
        ],
        "PolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": [
                "ec2:DescribeSecurityGroups",
                "ec2:RevokeSecurityGroupIngress"
              ],
              "Resource": "*"
            }
          ]
        }
      }
    }
  }
}
TEMPLATE
}

resource "aws_cloudformation_stack_set" "global_resources" {
  depends_on              = [aws_cloudformation_stack_set.iam_roles]
  name                    = "${var.project_name}-global-resources"
  description             = "Global resources for the ${var.project_name} event monitor."
  permission_model        = "SERVICE_MANAGED"

  lifecycle {
    ignore_changes = [administration_role_arn,call_as]
  }

  auto_deployment {
    enabled = true
    retain_stacks_on_account_removal = false
  }

  template_body = <<TEMPLATE
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "ExposedAccessKeysEventRule": {
      "Type": "AWS::Events::Rule",
      "Properties": {
        "Name": "${var.project_name}-exposed-keys",
        "Description": "Trusted Advisor ExposedAccessKeys Alert",
        "EventPattern": ${lookup(var.global_event_rule_type_map, "exposed-access-keys")},
        "State": "ENABLED",
        "Targets": [
          {
            "Id": "CrossAccountTarget",
            "Arn": "arn:aws:events:us-east-1:${var.org_account_id}:event-bus/default",
            "RoleArn": { "Fn::Sub": "arn:aws:iam::$${AWS::AccountId}:role/${var.project_name}-event-bus-sender" }
          }
        ]
      }
    },
    "AwsHealthExposedAccessKeysEventRule": {
      "Type": "AWS::Events::Rule",
      "Properties": {
        "Name": "${var.project_name}-aws-health-exposed-accesskeys",
        "Description": "AWS Health ExposedAccessKeys Alert",
        "EventPattern": ${lookup(var.global_event_rule_type_map, "aws-health")},
        "State": "ENABLED",
        "Targets": [
          {
            "Id": "CrossAccountTarget",
            "Arn": "arn:aws:events:us-east-1:${var.org_account_id}:event-bus/default",
            "RoleArn": { "Fn::Sub": "arn:aws:iam::$${AWS::AccountId}:role/${var.project_name}-event-bus-sender" }
          }
        ]
      }
    },
    "IAMEventRule": {
      "Type": "AWS::Events::Rule",
      "Properties": {
        "Name": "${var.project_name}-iam",
        "Description": "IAM EventRule",
        "EventPattern": ${lookup(var.global_event_rule_type_map, "iam")},
        "State": "ENABLED",
        "Targets": [
          {
            "Id": "CrossAccountTarget",
            "Arn": "arn:aws:events:us-east-1:${var.org_account_id}:event-bus/default",
            "RoleArn": { "Fn::Sub": "arn:aws:iam::$${AWS::AccountId}:role/${var.project_name}-event-bus-sender" }
          }
        ]
      }
    },
    "LoginAttemptEventRule": {
      "Type": "AWS::Events::Rule",
      "Properties": {
        "Name": "${var.project_name}-console-signin",
        "Description": "Failed Login Attempt EventRule",
        "EventPattern": ${lookup(var.global_event_rule_type_map, "console-signin")},
        "State": "ENABLED",
        "Targets": [
          {
            "Id": "CrossAccountTarget",
            "Arn": "arn:aws:events:us-east-1:${var.org_account_id}:event-bus/default",
            "RoleArn": { "Fn::Sub": "arn:aws:iam::$${AWS::AccountId}:role/${var.project_name}-event-bus-sender" }
          }
        ]
      }
    },
    "RootEventRule": {
      "Type": "AWS::Events::Rule",
      "Properties": {
        "Name": "${var.project_name}-root-activity",
        "Description": "Root EventRule",
        "EventPattern": ${lookup(var.global_event_rule_type_map, "root-activity")},
        "State": "ENABLED",
        "Targets": [
          {
            "Id": "CrossAccountTarget",
            "Arn": "arn:aws:events:us-east-1:${var.org_account_id}:event-bus/default",
            "RoleArn": { "Fn::Sub": "arn:aws:iam::$${AWS::AccountId}:role/${var.project_name}-event-bus-sender" }
          }
        ]
      }
    },
    "CloudTrailEventRule": {
      "Type": "AWS::Events::Rule",
      "Properties": {
        "Name": "${var.project_name}-cloudtrail",
        "Description": "CloudTrail EventRule",
        "EventPattern": ${lookup(var.global_event_rule_type_map, "cloudtrail")},
        "State": "ENABLED",
        "Targets": [
          {
            "Id": "CrossAccountTarget",
            "Arn": "arn:aws:events:us-east-1:${var.org_account_id}:event-bus/default",
            "RoleArn": { "Fn::Sub": "arn:aws:iam::$${AWS::AccountId}:role/${var.project_name}-event-bus-sender" }
          }
        ]
      }
    }
  }
}
TEMPLATE
}

resource "aws_cloudformation_stack_set" "regional_resources" {
  depends_on              = [aws_cloudformation_stack_set.global_resources] # need the iam roles for event bus
  name                    = "${var.project_name}-regional-resources"
  description             = "Regional resources for the ${var.project_name} event monitor."
  permission_model        = "SERVICE_MANAGED"
  
  lifecycle {
    ignore_changes = [administration_role_arn,call_as]
  }

  auto_deployment {
    enabled = true
    retain_stacks_on_account_removal = false
  }

  template_body = <<TEMPLATE
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "RAMEventRule": {
      "Type": "AWS::Events::Rule",
      "Properties": {
        "Name": "${var.project_name}-regional-ram",
        "Description": "RAM EventRule",
        "EventPattern": ${lookup(var.regional_event_rule_type_map, "ram")},
        "State": "ENABLED",
        "Targets": [
          {
            "Id": "CrossAccountTarget",
            "Arn": "arn:aws:events:us-east-1:${var.org_account_id}:event-bus/default",
            "RoleArn": { "Fn::Sub": "arn:aws:iam::$${AWS::AccountId}:role/${var.project_name}-event-bus-sender" }
          }
        ]
      }
    },
    "ELBEventRule": {
      "Type": "AWS::Events::Rule",
      "Properties": {
        "Name": "${var.project_name}-regional-elb",
        "Description": "ELB EventRule",
        "EventPattern": ${lookup(var.regional_event_rule_type_map, "elb")},
        "State": "ENABLED",
        "Targets": [
          {
            "Id": "CrossAccountTarget",
            "Arn": "arn:aws:events:us-east-1:${var.org_account_id}:event-bus/default",
            "RoleArn": { "Fn::Sub": "arn:aws:iam::$${AWS::AccountId}:role/${var.project_name}-event-bus-sender" }
          }
        ]
      }
    },
    "EC2EventRule": {
      "Type": "AWS::Events::Rule",
      "Properties": {
        "Name": "${var.project_name}-regional-ec2",
        "Description": "EC2 EventRule",
        "EventPattern": ${lookup(var.regional_event_rule_type_map, "ec2")},
        "State": "ENABLED",
        "Targets": [
          {
            "Id": "CrossAccountTarget",
            "Arn": "arn:aws:events:us-east-1:${var.org_account_id}:event-bus/default",
            "RoleArn": { "Fn::Sub": "arn:aws:iam::$${AWS::AccountId}:role/${var.project_name}-event-bus-sender" }
          }
        ]
      }
    },
    "NetworkEventRule": {
      "Type": "AWS::Events::Rule",
      "Properties": {
        "Name": "${var.project_name}-regional-network",
        "Description": "Network EventRule",
        "EventPattern": ${lookup(var.regional_event_rule_type_map, "network")},
        "State": "ENABLED",
        "Targets": [
          {
            "Id": "CrossAccountTarget",
            "Arn": "arn:aws:events:us-east-1:${var.org_account_id}:event-bus/default",
            "RoleArn": { "Fn::Sub": "arn:aws:iam::$${AWS::AccountId}:role/${var.project_name}-event-bus-sender" }
          }
        ]
      }
    },
    "KMSEventRule": {
      "Type": "AWS::Events::Rule",
      "Properties": {
        "Name": "${var.project_name}-regional-kms",
        "Description": "KMS EventRule",
        "EventPattern": ${lookup(var.regional_event_rule_type_map, "kms")},
        "State": "ENABLED",
        "Targets": [
          {
            "Id": "CrossAccountTarget",
            "Arn": "arn:aws:events:us-east-1:${var.org_account_id}:event-bus/default",
            "RoleArn": { "Fn::Sub": "arn:aws:iam::$${AWS::AccountId}:role/${var.project_name}-event-bus-sender" }
          }
        ]
      }
    },
    "ConfigEventRule": {
      "Type": "AWS::Events::Rule",
      "Properties": {
        "Name": "${var.project_name}-regional-config",
        "Description": "Config EventRule",
        "EventPattern": ${lookup(var.regional_event_rule_type_map, "config")},
        "State": "ENABLED",
        "Targets": [
          {
            "Id": "CrossAccountTarget",
            "Arn": "arn:aws:events:us-east-1:${var.org_account_id}:event-bus/default",
            "RoleArn": { "Fn::Sub": "arn:aws:iam::$${AWS::AccountId}:role/${var.project_name}-event-bus-sender" }
          }
        ]
      }
    },
    "S3EventRule": {
      "Type": "AWS::Events::Rule",
      "Properties": {
        "Name": "${var.project_name}-regional-s3",
        "Description": "S3 EventRule",
        "EventPattern": ${lookup(var.regional_event_rule_type_map, "s3")},
        "State": "ENABLED",
        "Targets": [
          {
            "Id": "CrossAccountTarget",
            "Arn": "arn:aws:events:us-east-1:${var.org_account_id}:event-bus/default",
            "RoleArn": { "Fn::Sub": "arn:aws:iam::$${AWS::AccountId}:role/${var.project_name}-event-bus-sender" }
          }
        ]
      }
    },
    "RDSEventRule": {
      "Type": "AWS::Events::Rule",
      "Properties": {
        "Name": "${var.project_name}-regional-rds",
        "Description": "RDS EventRule",
        "EventPattern": ${lookup(var.regional_event_rule_type_map, "rds")},
        "State": "ENABLED",
        "Targets": [
          {
            "Id": "CrossAccountTarget",
            "Arn": "arn:aws:events:us-east-1:${var.org_account_id}:event-bus/default",
            "RoleArn": { "Fn::Sub": "arn:aws:iam::$${AWS::AccountId}:role/${var.project_name}-event-bus-sender" }
          }
        ]
      }
    }
  }
}
TEMPLATE
}