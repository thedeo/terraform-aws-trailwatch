resource "aws_cloudformation_stack_set_instance" "org_regional_resources" {
  depends_on      = [
                      aws_cloudformation_stack_set_instance.regional_resources, # To give time for roles to finish creating
                      aws_cloudformation_stack_set.org_regional_resources,
                      aws_iam_role.AWSCloudFormationStackSetAdministrationRole,
                      aws_iam_role_policy.AWSCloudFormationStackSetAdministrationRole,
                      aws_iam_role.AWSCloudFormationStackSetExecutionRole,
                      aws_iam_role_policy.AWSCloudFormationStackSetExecutionRole,
                    ]
  # Remove us-east-1 in for_each because that is handled in eventbridge_rules.tf
  for_each       = setsubtract(var.available_regions, ["us-east-1"]) 

  account_id     = var.org_account_id
  region         = each.value
  stack_set_name = aws_cloudformation_stack_set.org_regional_resources.name
}

resource "aws_cloudformation_stack_set" "org_regional_resources" {
  depends_on              = [
                              aws_iam_role.AWSCloudFormationStackSetAdministrationRole,
                              aws_iam_role_policy.AWSCloudFormationStackSetAdministrationRole,
                              aws_iam_role.AWSCloudFormationStackSetExecutionRole,
                              aws_iam_role_policy.AWSCloudFormationStackSetExecutionRole,
                            ]
  name                    = "${var.project_name}-org-regional-resources"
  description             = "Org regional resources for the ${var.project_name} event monitor."
  permission_model        = "SELF_MANAGED"

  lifecycle {
    ignore_changes = [administration_role_arn,call_as]
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
            "Id": "CrossRegionTarget",
            "Arn": { "Fn::Sub": "arn:aws:events:us-east-1:$${AWS::AccountId}:event-bus/default" },
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
            "Id": "CrossRegionTarget",
            "Arn": { "Fn::Sub": "arn:aws:events:us-east-1:$${AWS::AccountId}:event-bus/default" },
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
            "Id": "CrossRegionTarget",
            "Arn": { "Fn::Sub": "arn:aws:events:us-east-1:$${AWS::AccountId}:event-bus/default" },
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
            "Id": "CrossRegionTarget",
            "Arn": { "Fn::Sub": "arn:aws:events:us-east-1:$${AWS::AccountId}:event-bus/default" },
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
            "Id": "CrossRegionTarget",
            "Arn": { "Fn::Sub": "arn:aws:events:us-east-1:$${AWS::AccountId}:event-bus/default" },
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
            "Id": "CrossRegionTarget",
            "Arn": { "Fn::Sub": "arn:aws:events:us-east-1:$${AWS::AccountId}:event-bus/default" },
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
            "Id": "CrossRegionTarget",
            "Arn": { "Fn::Sub": "arn:aws:events:us-east-1:$${AWS::AccountId}:event-bus/default" },
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
            "Id": "CrossRegionTarget",
            "Arn": { "Fn::Sub": "arn:aws:events:us-east-1:$${AWS::AccountId}:event-bus/default" },
            "RoleArn": { "Fn::Sub": "arn:aws:iam::$${AWS::AccountId}:role/${var.project_name}-event-bus-sender" }
          }
        ]
      }
    }
  }
}
TEMPLATE
}