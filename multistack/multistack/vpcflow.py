#### How to call this file inside app.py file and options
# FlowLogsStack = flowlogs(app, "MY-VPCFLOW", env=myenv, vpc = VPCStack.vpc)
# where:
# FlowLogsStack ==> Name of stack, used if you will import values from it in another stack (Mandatory)
# flowlogs ==> reference to name of this script vpcflow.py on import (Mandatory)
# MY-VPCFLOW ==> Name of contruct, you can use on cdk (cdk list, cdk deploy or cdk destroy). (Mandatory) This is the name of Cloudformation Template in cdk.out dir (MY-VPCFLOW.template.json)
# logfor = 'default'  ==> Log Format, direct in the code. (defaul|full)
# vpcid ==> VPC-ID that where flow logs will be created (Mandatory)
# Since this templates are used to tests, there is a fixed retention policy for logs set to 1 week.
# the log format is custom using these fields (${version} ${account-id} ${vpc-id} ${region} ${az-id} ${sublocation-type} ${sublocation-id} ${subnet-id} ${instance-id} ${interface-id} ${type} ${pkt-src-aws-service} ${srcaddr} ${pkt-dst-aws-service} ${dstaddr} ${srcport} ${dstport} ${pkt-srcaddr} ${pkt-dstaddr} ${flow-direction} ${traffic-path} ${protocol} ${bytes} ${packets} ${start} ${end} ${action} ${tcp-flags} ${log-status})
# see fields available at https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html#flow-logs-fields
# if you want to query using cloudwatch insights you must use the following query to import
# fields @timestamp, @message
# | parse @message /(?<@version>.*)\ (?<@accountid>.*)\ (?<@vpcid>.*)\ (?<@region>.*)\ (?<@azid>.*)\ (?<@sublocationtype>.*)\ (?<@sublocationid>.*)\ (?<@subnetid>.*)\ (?<@instanceid>.*)\ (?<@interfaceid>.*)\ (?<@type>.*)\ (?<@pktsrcawsservice>.*)\ (?<@srcaddr>.*)\ (?<@pktdstawsservice>.*)\ (?<@dstaddr>.*)\ (?<@srcport>.*)\ (?<@dstport>.*)\ (?<@pktsrcaddr>.*)\ (?<@pktdstaddr>.*)\ (?<@flowdirection>.*)\ (?<@trafficpath>.*)\ (?<@protocol>.*)\ (?<@bytes>.*)\ (?<@packets>.*)\ (?<@start>.*)\ (?<@end>.*)\ (?<@action>.*)\ (?<@tcpflags>.*)\ (?<@logstatus>.*)/
# | display @version, @accountid, @vpcid, @region, @azid, @sublocationtype, @sublocationid, @subnetid, @instanceid, @interfaceid, @type, @pktsrcawsservice, @srcaddr, @pktdstawsservice, @dstaddr, @srcport, @dstport, @pktsrcaddr, @pktdstaddr, @flowdirection, @trafficpath, @protocol, @bytes, @packets, @start, @end, @action, @tcpflags, @logstatus
# | sort @timestamp desc
# | limit 1000


import os
import json
from aws_cdk import (
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_logs as log,
    core,
)
account = os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"])
region = os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])
class flowlogs(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, logfor = str, vpcid = str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        if logfor == 'full':
            self.format = '${version} ${account-id} ${vpc-id} ${region} ${az-id} ${sublocation-type} ${sublocation-id} ${subnet-id} ${instance-id} ${interface-id} ${type} ${pkt-src-aws-service} ${srcaddr} ${pkt-dst-aws-service} ${dstaddr} ${srcport} ${dstport} ${pkt-srcaddr} ${pkt-dstaddr} ${flow-direction} ${traffic-path} ${protocol} ${bytes} ${packets} ${start} ${end} ${action} ${tcp-flags} ${log-status}'
        else:
            self.format = '${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status}'
        # Log Group for Flow Logs
        self.flowloggroup = log.LogGroup(
            self,
            f"{construct_id}:FlowLogsGroup",
            retention=log.RetentionDays.ONE_WEEK
        )
        self.flowpolicy = iam.PolicyStatement(
            actions=[
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:DescribeLogGroups",
                "logs:DescribeLogStreams",
                "logs:PutLogEvents"
            ],
            effect=iam.Effect.ALLOW,
        )
        # Add all resources to this policy document
        self.flowpolicy.add_all_resources()
        # Iam Role
        self.flowlogrole = iam.Role(
            self,
            f"{construct_id}:FlowLogsRole",
            assumed_by=iam.ServicePrincipal('vpc-flow-logs.amazonaws.com'),
            description="Role for Delivery VPC Flow Logs",
        )
        # Attach policy to Iam Role
        self.flowlogrole.add_to_principal_policy(statement=self.flowpolicy)
        # Create VPC Flow Log for VPC
        ec2.CfnFlowLog(
            self,
            f"{construct_id}",
            resource_id=vpcid,
            resource_type='VPC',
            traffic_type='ALL',
            deliver_logs_permission_arn=self.flowlogrole.role_arn,
            log_destination_type='cloud-watch-logs',
            log_group_name=self.flowloggroup.log_group_name,
            max_aggregation_interval=60,
            log_format=format(self.format),
        )
