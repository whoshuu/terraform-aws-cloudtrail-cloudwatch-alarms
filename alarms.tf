data "aws_caller_identity" "current" {
}

data "aws_region" "current" {
}

locals {
  alert_for     = "CloudTrailBreach"
  sns_topic_arn = var.sns_topic_arn == "" ? aws_sns_topic.default.arn : var.sns_topic_arn
  endpoints = distinct(
    compact(concat([local.sns_topic_arn], var.additional_endpoint_arns)),
  )
  region = var.region == "" ? data.aws_region.current.name : var.region

  metric_name = [
    "UnauthorizedAPICalls",
    "NoMFAConsoleSignin",
    "RootUsage",
    "IAMChanges",
    "CloudTrailCfgChanges",
    "ConsoleSigninFailures",
    "DisableOrDeleteCMK",
    "S3BucketPolicyChanges",
    "AWSConfigChanges",
    "SecurityGroupChanges",
    "NACLChanges",
    "NetworkGWChanges",
    "RouteTableChanges",
    "VPCChanges",
  ]

  metric_namespace = var.metric_namespace
  metric_value     = "1"

  filter_pattern = [
    "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }",
    "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") }"
    "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
    "{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}"
    "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
    "{ ($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\") }"
    "{ ($.eventSource = kms.amazonaws.com) && (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion)) }"
    "{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }"
    "{ ($.eventSource = config.amazonaws.com) && (($.eventName=StopConfigurationRecorder)||($.eventName=DeleteDeliveryChannel)||($.eventName=PutDeliveryChannel)||($.eventName=PutConfigurationRecorder)) }"
    "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup)}"
    "{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }"
    "{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }"
    "{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }"
    "{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }"
  ]

  alarm_description = [
    "3.1 Monitoring unauthorized API calls will help reveal application errors and may reduce time to detect malicious activity.",
    "3.2 Monitoring for single-factor console logins will increase visibility into accounts that are not protected by MFA.",
    "3.3 Monitoring for root account logins will provide visibility into the use of a fully privileged account and an opportunity to reduce the use of it.",
    "3.4 Monitoring changes to IAM policies will help ensure authentication and authorization controls remain intact.",
    "3.5 Monitoring changes to CloudTrail's configuration will help ensure sustained visibility to activities performed in the AWS account.",
    "3.6 Monitoring failed console logins may decrease lead time to detect an attempt to brute force a credential, which may provide an indicator, such as source IP, that can be used in other event correlation.",
    "3.7 Monitoring failed console logins may decrease lead time to detect an attempt to brute force a credential, which may provide an indicator, such as source IP, that can be used in other event correlation.",
    "3.8 Monitoring changes to S3 bucket policies may reduce time to detect and correct permissive policies on sensitive S3 buckets.",
    "3.9 Monitoring changes to AWS Config configuration will help ensure sustained visibility of configuration items within the AWS account.",
    "3.10 Monitoring changes to security group will help ensure that resources and services are not unintentionally exposed.",
    "3.11 Monitoring changes to NACLs will help ensure that AWS resources and services are not unintentionally exposed.",
    "3.12 Monitoring changes to network gateways will help ensure that all ingress/egress traffic traverses the VPC border via a controlled path.",
    "3.13 Monitoring changes to route tables will help ensure that all VPC traffic flows through an expected path.",
    "3.14 Monitoring changes to VPC will help ensure that all VPC traffic flows through an expected path.",
  ]
}

resource "aws_cloudwatch_log_metric_filter" "default" {
  count          = length(local.filter_pattern)
  name           = "${local.metric_name[count.index]}-filter"
  pattern        = local.filter_pattern[count.index]
  log_group_name = var.log_group_name

  metric_transformation {
    name      = local.metric_name[count.index]
    namespace = local.metric_namespace
    value     = local.metric_value
  }
}

resource "aws_cloudwatch_metric_alarm" "default" {
  count               = length(local.filter_pattern)
  alarm_name          = "${local.metric_name[count.index]}-alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = local.metric_name[count.index]
  namespace           = local.metric_namespace
  period              = "300" // 5 min
  statistic           = "Sum"
  treat_missing_data  = "notBreaching"
  threshold           = local.metric_name[count.index] == "ConsoleSignInFailureCount" ? "3" : "1"
  alarm_description   = local.alarm_description[count.index]
  alarm_actions       = local.endpoints
}

resource "aws_cloudwatch_dashboard" "main" {
  count          = var.create_dashboard == "true" ? 1 : 0
  dashboard_name = "CISBenchmark_Statistics_Combined"

  dashboard_body = <<EOF
 {
   "widgets": [
       {
          "type":"metric",
          "x":0,
          "y":0,
          "width":20,
          "height":16,
          "properties":{
             "metrics":[
               ${join(
  ",",
  formatlist(
    "[ \"${local.metric_namespace}\", \"%v\" ]",
    local.metric_name,
  ),
)}
             ],
             "period":300,
             "stat":"Sum",
             "region":"${var.region}",
             "title":"CISBenchmark Statistics"
          }
       }
   ]
 }

EOF

}

resource "aws_cloudwatch_dashboard" "main_individual" {
  count          = var.create_dashboard == "true" ? 1 : 0
  dashboard_name = "CISBenchmark_Statistics_Individual"

  dashboard_body = <<EOF
 {
   "widgets": [
     ${join(
  ",",
  formatlist(
    "{\n          \"type\":\"metric\",\n          \"x\":%v,\n          \"y\":%v,\n          \"width\":12,\n          \"height\":6,\n          \"properties\":{\n             \"metrics\":[\n                [ \"${local.metric_namespace}\", \"%v\" ]\n            ],\n          \"period\":300,\n          \"stat\":\"Sum\",\n          \"region\":\"${var.region}\",\n          \"title\":\"%v\"\n          }\n       }\n       ",
    local.layout_x,
    local.layout_y,
    local.metric_name,
    local.metric_name,
  ),
)}
   ]
 }

EOF

}

locals {
  # Two Columns
  # Will experiment with this values
  layout_x = [0, 12, 0, 12, 0, 12, 0, 12, 0, 12, 0, 12, 0, 12]

  layout_y = [0, 0, 7, 7, 15, 15, 22, 22, 29, 29, 36, 36, 43, 43]
}

