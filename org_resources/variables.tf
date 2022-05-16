variable "project_name" {}
variable "region" {}
variable "alert_sender" {}
variable "alert_recipients" {}
variable "secgroup_automation_principal_exceptions" {}
variable "secgroup_automation_monitored_ports" {}
variable "ignored_iam_principals" {}
variable "ses_identity_arn" {}
variable "email_summary_frequency" {}
variable "dashboard_domain" {}
variable "dashboard_report_frequency" {}
variable "org_account_id" {}
variable "org_root_id" {}
variable "org_id" {}
variable "available_regions" {}
variable "create_cf_stackset_roles" {}

variable "reports" {
  type    = set(string)
  default = ["account", "ami", "securitygroup", "user"]
}

# These map vars are used to populate the eventbridge rules in a "for_each" loop
variable "global_event_rule_type_map" {
  type    = map
  default = {
    #=================================================
    # Global Event Patterns
    #=================================================
    exposed-access-keys = <<EOF
{
  "source": [
    "aws.trustedadvisor"
  ],
  "detail-type": [
    "Trusted Advisor Check Item Refresh Notification"
  ],
  "detail": {
    "check-name": [
      "Exposed Access Keys"
    ]
  }
}
EOF
    #=================================================
    aws-health = <<EOF
{
  "source": [
    "aws.health"
  ],
  "detail-type": [
    "AWS Health Event"
  ],
  "detail": {
    "service": [
      "RISK"
    ]
  }
}
EOF
    #=================================================
    iam = <<EOF
{
  "source": [
    "aws.iam"
  ],
  "detail-type": [
    "AWS API Call via CloudTrail"
  ],
  "detail": {
    "eventSource": [
      "iam.amazonaws.com"
    ],
    "eventName": [
      "CreateRole",
      "CreateAccessKey",
      "CreateUser",
      "DeleteAccessKey",
      "CreateInstanceProfile",
      "AddRoleToInstanceProfile",
      "AddUserToGroup",
      "AttachGroupPolicy",
      "AttachRolePolicy",
      "AttachUserPolicy",
      "CreateLoginProfile",
      "CreateOpenIDConnectProvider",
      "CreatePolicy",
      "CreatePolicyVersion",
      "CreateServiceSpecificCredential",
      "DeleteAccountAlias",
      "CreateSAMLProvider",
      "DeleteRole",
      "DeleteSAMLProvider",
      "DeleteServiceLinkedRole",
      "PutGroupPolicy",
      "PutUserPolicy",
      "DeleteUser",
      "DeleteGroup",
      "DeleteRolePermissionsBoundary",
      "DeleteUserPermissionsBoundary",
      "UpdateAssumeRolePolicy",
      "DeleteAccountPasswordPolicy",
      "UpdateAccountPasswordPolicy"
    ]
  }
}
EOF
    #=================================================
    console-signin = <<EOF
{
  "detail-type": [
    "AWS Console Sign In via CloudTrail"
  ]
}
EOF
    #=================================================
    root-activity = <<EOF
{
  "detail-type": [
    "AWS API Call via CloudTrail",
    "AWS Console Sign In via CloudTrail"
  ],
  "detail": {
    "userIdentity": {
      "type": [
        "Root"
      ]
    }
  }
}
EOF
    #=================================================
    cloudtrail = <<EOF
{
  "source": [
    "aws.cloudtrail"
  ],
  "detail-type": [
    "AWS API Call via CloudTrail"
  ],
  "detail": {
    "eventSource": [
      "cloudtrail.amazonaws.com"
    ],
    "eventName": [
      "StartLogging",
      "StopLogging",
      "CreateTrail",
      "DeleteTrail",
      "UpdateTrail"
    ]
  }
}
EOF
  }
}

variable "regional_event_rule_type_map" {
  type    = map
  default = {
    ram = <<EOF
{
  "source": [
    "aws.ram"
  ]
}
EOF
    #=================================================
    elb = <<EOF
{
  "source": [
    "aws.elasticloadbalancing"
  ],
  "detail-type": [
    "AWS API Call via CloudTrail"
  ],
  "detail": {
    "eventSource": [
      "elasticloadbalancing.amazonaws.com"
    ],
    "eventName": [
      "ModifyLoadBalancerAttributes"
    ]
  }
}
EOF
    #=================================================
    ec2 = <<EOF
{
  "source": [
    "aws.ec2"
  ],
  "detail-type": [
    "AWS API Call via CloudTrail"
  ],
  "detail": {
    "eventSource": [
      "ec2.amazonaws.com"
    ],
    "eventName": [
      "ModifyVolume",
      "ModifyVolumeAttribute",
      "RebootInstances",
      "StartInstances",
      "StopInstances",
      "CreateKeyPair",
      "DeleteKeyPair",
      "ImportKeyPair"
    ]
  }
}
EOF
    #=================================================
    network = <<EOF
{
  "source": [
    "aws.ec2"
  ],
  "detail-type": [
    "AWS API Call via CloudTrail"
  ],
  "detail": {
    "eventSource": [
      "ec2.amazonaws.com"
    ],
    "eventName": [
      "DeleteNatGateway",
      "CreateNatGateway",
      "DeleteVpc",
      "CreateDefaultVpc",
      "CreateVpc",
      "CreateSecurityGroup",
      "DeleteSecurityGroup",
      "AuthorizeSecurityGroupIngress",
      "RevokeSecurityGroupIngress",
      "AuthorizeSecurityGroupEgress",
      "RevokeSecurityGroupEgress",
      "CreateNetworkAclEntry",
      "CreateNetworkAcl",
      "DeleteNetworkAcl",
      "DeleteNetworkAclEntry",
      "ReplaceNetworkAclEntry",
      "ReplaceNetworkAclAssociation",
      "CreateRoute",
      "DeleteRoute",
      "ReplaceRoute",
      "ReplaceRouteTableAssociation",
      "DisassociateRouteTable",
      "AssociateRouteTable",
      "CreateVpnConnection",
      "CreateVpnGateway",
      "ModifyVpnConnection",
      "AttachVpnGateway",
      "DetachVpnGateway",
      "CreateVpcPeeringConnection",
      "AcceptVpcPeeringConnection",
      "ModifyVpcPeeringConnectionOptions",
      "DeleteVpcPeeringConnection",
      "CreateTransitGatewayPeeringAttachment",
      "AcceptTransitGatewayPeeringAttachment",
      "DeleteTransitGatewayPeeringAttachment",
      "RejectVpcPeeringConnection",
      "RejectTransitGatewayPeeringAttachment",
      "CreateTrafficMirrorFilter",
      "CreateTrafficMirrorFilterRule",
      "CreateTrafficMirrorSession",
      "CreateTrafficMirrorTarget",
      "CreateTransitGatewayVpcAttachment",
      "ModifyTrafficMirrorFilterNetworkServices",
      "ModifyTrafficMirrorFilterRule",
      "ModifyTrafficMirrorSession",
      "ModifyTransitGatewayVpcAttachment",
      "AcceptTransitGatewayVpcAttachment"
    ]
  }
}
EOF
    #=================================================
    kms = <<EOF
{
  "source": [
    "aws.kms"
  ],
  "detail-type": [
    "AWS API Call via CloudTrail"
  ],
  "detail": {
    "eventSource": [
      "kms.amazonaws.com"
    ],
    "eventName": [
      "DeleteCustomKeyStore",
      "DeleteImportedKeyMaterial",
      "DisconnectCustomKeyStore",
      "DeleteAlias",
      "PutKeyPolicy",
      "DisableKey",
      "CancelKeyDeletion",
      "UpdateAlias",
      "UpdateCustomKeyStore",
      "UpdateKeyDescription",
      "ScheduleKeyDeletion"
    ]
  }
}
EOF
    #=================================================
    config = <<EOF
{
  "source": [
    "aws.config"
  ],
  "detail-type": [
    "AWS API Call via CloudTrail"
  ],
  "detail": {
    "eventSource": [
      "config.amazonaws.com"
    ],
    "eventName": [
      "DeleteAggregationAuthorization",
      "DeleteConfigurationAggregator",
      "DeleteConfigurationRecorder",
      "DeleteConformancePack",
      "DeleteDeliveryChannel",
      "DeleteEvaluationResults",
      "DeleteOrganizationConfigRule",
      "DeleteOrganizationConformancePack",
      "DeletePendingAggregationRequest",
      "DeleteRemediationConfiguration",
      "DeleteRemediationExceptions",
      "DeleteRetentionConfiguration",
      "StopConfigurationRecorder"
    ]
  }
}
EOF
    #=================================================
    s3 = <<EOF
{
  "source": [
    "aws.s3"
  ],
  "detail-type": [
    "AWS API Call via CloudTrail"
  ],
  "detail": {
    "eventSource": [
      "s3.amazonaws.com"
    ],
    "eventName": [
      "DeleteBucket",
      "PutBucketAcl",
      "PutBucketPolicy",
      "DeleteBucketPolicy",
      "PutAccountPublicAccessBlock",
      "PutBucketPublicAccessBlock",
      "DeleteAccountPublicAccessBlock",
      "DeleteBucketPublicAccessBlock",
      "DeleteBucketEncryption",
      "PutBucketWebsite",
      "PutObjectLockLegalHold",
      "DeleteBucketReplication",
      "PutBucketCors",
      "DeleteBucketCors",
      "DeleteBucketLifecycle",
      "PutBucketLifecycle",
      "PutBucketLogging"
    ]
  }
}
EOF
    #=================================================
    rds = <<EOF
{
  "source": [
    "aws.rds"
  ],
  "detail-type": [
    "AWS API Call via CloudTrail"
  ],
  "detail": {
    "eventSource": [
      "rds.amazonaws.com"
    ],
    "eventName": [
      "AuthorizeDBSecurityGroupIngress",
      "CreateDBSecurityGroup",
      "DeleteDBSecurityGroup",
      "RevokeDBSecurityGroupIngress",
      "ModifyDBCluster",
      "ModifyDBInstance",
      "AddRoleToDBCluster",
      "AddRoleToDBInstance",
      "CreateDBCluster",
      "CreateDBInstance",
      "CreateDBInstanceReadReplica",
      "CreateGlobalCluster",
      "DeleteDBInstance",
      "DeleteDBCluster",
      "DeleteGlobalCluster",
      "PromoteReadReplica",
      "PromoteReadReplicaDBCluster",
      "RebootDBInstance"
    ]
  }
}
EOF
  }
}