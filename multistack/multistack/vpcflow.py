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
    def __init__(self, scope: core.Construct, construct_id: str, vpc = ec2.Vpc, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.vpc = vpc
        # Log Group for Flow Logs
        self.flowloggroup = log.LogGroup(
            self,
            "FlowLogsGroup",
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
            "FlowLogsRole",
            assumed_by=iam.ServicePrincipal('vpc-flow-logs.amazonaws.com'),
            description="Role for Delivery VPC Flow Logs",
        )
        # Attach policy to Iam Role
        self.flowlogrole.add_to_policy(self.flowpolicy)
        # Create VPC Flow Log for VPC
        ec2.CfnFlowLog(
            self,
            "VpcFlowLogs",
            resource_id=self.vpc.vpc_id,
            resource_type='VPC',
            traffic_type='ALL',
            deliver_logs_permission_arn=self.flowlogrole.role_arn,
            log_destination_type='cloud-watch-logs',
            log_group_name=self.flowloggroup.log_group_name,
            max_aggregation_interval=60,
            log_format=format('${version} ${vpc-id} ${subnet-id} ${instance-id} ${interface-id} ${account-id} ${type} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${pkt-srcaddr} ${pkt-dstaddr} ${protocol} ${bytes} ${packets} ${start} ${end} ${action} ${tcp-flags} ${log-status}'),
        )
