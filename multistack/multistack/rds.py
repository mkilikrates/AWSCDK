import os
import json
from aws_cdk import (
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_rds as rds,
    aws_ssm as ssm,
    aws_logs as log,
    core,
)
account = os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"])
region = os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])
resconf = "resourcesmap.cfg"
cidrid = 0
natgw = 1
with open(resconf) as resfile:
    resmap = json.load(resfile)
with open('zonemap.cfg') as zonefile:
    zonemap = json.load(zonefile)
class mariamaz(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, vpc = ec2.Vpc, bastionsg = ec2.SecurityGroup, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.vpc = vpc
        self.bastionsg = bastionsg
        # create policy to log rds
        self.rdslogpolicy = iam.PolicyStatement(
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
        self.rdslogpolicy.add_all_resources()
        # Iam Role
        self.rdslogrole = iam.Role(
            self,
            "RDSLogsRole",
            assumed_by=iam.ServicePrincipal('rds.amazonaws.com'),
            description="Role for Delivery RDS Logs",
        )
        # Attach policy to Iam Role
        self.rdslogrole.add_to_policy(self.rdslogpolicy)

        # get prefix list from file to allow traffic from the office
        srcprefix = zonemap['Mappings']['RegionMap'][region]['PREFIXLIST']        
        # create security group for rds
        self.rdssg = ec2.SecurityGroup(
            self,
            'MyRdsSG',
            allow_all_outbound=True,
            vpc=self.vpc
        )
         # add ingress rules
        self.rdssg.add_ingress_rule(
            ec2.Peer.prefix_list(srcprefix),
            ec2.Port.all_traffic()
        )
        self.rdssg.add_ingress_rule(
            self.bastionsg,
            ec2.Port.all_traffic()
        )
        self.rdssg.add_ingress_rule(
            self.rdssg,
            ec2.Port.all_traffic()
        )
        # get data for rds resource
        res = 'rdsmariasmallmz'
        resname = resmap['Mappings']['Resources'][res]['NAME']
        ressize = resmap['Mappings']['Resources'][res]['SIZE']
        resclass = resmap['Mappings']['Resources'][res]['CLASS']
        resusr = resmap['Mappings']['Resources'][res]['DBUSR']
        respol = resmap['Mappings']['Resources'][res]['RemovalPolicy']
        # create RDS Cluster
        self.rds = rds.DatabaseCluster(
            self,
            'MyRdsCluster',
            engine=rds.DatabaseClusterEngine.AURORA_MYSQL,
            instance_props=rds.InstanceProps(
                vpc=self.vpc,
                allow_major_version_upgrade=True,
                auto_minor_version_upgrade=True,
                delete_automated_backups=True,
                instance_type=ec2.InstanceType.of(
                    instance_class=ec2.InstanceClass(resclass),
                    instance_size=ec2.InstanceSize(ressize)
                ),
                vpc_subnets=ec2.SubnetType.PUBLIC,
                security_groups=[self.rdssg],
                publicly_accessible=True
            ),
            credentials=rds.Credentials.from_generated_secret(resusr),
            deletion_protection=False,
            instance_identifier_base=resname,
            removal_policy=core.RemovalPolicy(respol),
            cloudwatch_logs_exports=[
                "error",
                "general",
                "slowquery",
                "audit"
            ],
            cloudwatch_logs_retention=log.RetentionDays.ONE_WEEK,
            cloudwatch_logs_retention_role=self.rdslogrole
        )
        core.CfnOutput(
            self,
            f"{construct_id}:rds-endpoint",
            value=f"{self.rds.cluster_endpoint.hostname}:{self.rds.cluster_endpoint.port}",
            export_name=f"{construct_id}:rds-endpoint"
        )
        core.CfnOutput(
            self,
            f"{construct_id}:rds-ro-endpoint",
            value=f"{self.rds.cluster_read_endpoint.hostname}:{self.rds.cluster_read_endpoint.port}",
            export_name=f"{construct_id}:rds-ro-endpoint"
        )
        
