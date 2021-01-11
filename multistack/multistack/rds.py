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
class mariamazpub(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, vpc = ec2.Vpc, bastionsg = ec2.SecurityGroup, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.vpc = vpc
        self.bastionsg = bastionsg
        # get prefix list from file to allow traffic from the office
        srcprefix = zonemap['Mappings']['RegionMap'][region]['PREFIXLIST']        
        # create security group for rds
        self.rdssg = ec2.SecurityGroup(
            self,
            f"{construct_id}:MyRdsSG",
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
        res = 'rdsmariasmall'
        resname = resmap['Mappings']['Resources'][res]['NAME']
        ressize = resmap['Mappings']['Resources'][res]['SIZE']
        resclass = resmap['Mappings']['Resources'][res]['CLASS']
        resusr = resmap['Mappings']['Resources'][res]['DBUSR']
        respol = resmap['Mappings']['Resources'][res]['RemovalPolicy']
        # create RDS Cluster
        self.rds = rds.DatabaseCluster(
            self,
            f"{construct_id}:MyRdsCluster",
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
class mariamazpriv(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, vpc = ec2.Vpc, bastionsg = ec2.SecurityGroup, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.vpc = vpc
        self.bastionsg = bastionsg
        # get prefix list from file to allow traffic from the office
        srcprefix = zonemap['Mappings']['RegionMap'][region]['PREFIXLIST']        
        # create security group for rds
        self.rdssg = ec2.SecurityGroup(
            self,
            f"{construct_id}:MyRdsSG",
            allow_all_outbound=True,
            vpc=self.vpc
        )
         # add ingress rules
        self.rdssg.add_ingress_rule(
            self.bastionsg,
            ec2.Port.all_traffic()
        )
        self.rdssg.add_ingress_rule(
            self.rdssg,
            ec2.Port.all_traffic()
        )
        # get data for rds resource
        res = 'rdsmariasmall'
        resname = resmap['Mappings']['Resources'][res]['NAME']
        ressize = resmap['Mappings']['Resources'][res]['SIZE']
        resclass = resmap['Mappings']['Resources'][res]['CLASS']
        resusr = resmap['Mappings']['Resources'][res]['DBUSR']
        respol = resmap['Mappings']['Resources'][res]['RemovalPolicy']
        # create RDS Cluster
        self.rds = rds.DatabaseCluster(
            self,
            f"{construct_id}:MyRdsCluster",
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
                vpc_subnets=ec2.SubnetType.PRIVATE,
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

class mariamazisol(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, vpc = ec2.Vpc, bastionsg = ec2.SecurityGroup, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.vpc = vpc
        self.bastionsg = bastionsg
        # get prefix list from file to allow traffic from the office
        srcprefix = zonemap['Mappings']['RegionMap'][region]['PREFIXLIST']        
        # create security group for rds
        self.rdssg = ec2.SecurityGroup(
            self,
            f"{construct_id}:MyRdsSG",
            allow_all_outbound=True,
            vpc=self.vpc
        )
         # add ingress rules
        self.rdssg.add_ingress_rule(
            self.bastionsg,
            ec2.Port.all_traffic()
        )
        self.rdssg.add_ingress_rule(
            self.rdssg,
            ec2.Port.all_traffic()
        )
        # get data for rds resource
        res = 'rdsmariasmall'
        resname = resmap['Mappings']['Resources'][res]['NAME']
        ressize = resmap['Mappings']['Resources'][res]['SIZE']
        resclass = resmap['Mappings']['Resources'][res]['CLASS']
        resusr = resmap['Mappings']['Resources'][res]['DBUSR']
        respol = resmap['Mappings']['Resources'][res]['RemovalPolicy']
        # create RDS Cluster
        self.rds = rds.DatabaseCluster(
            self,
            f"{construct_id}:MyRdsCluster",
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
                vpc_subnets=ec2.SubnetType.ISOLATED,
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

class mariasazpub(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, vpc = ec2.Vpc, bastionsg = ec2.SecurityGroup, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.vpc = vpc
        self.bastionsg = bastionsg
        # get prefix list from file to allow traffic from the office
        srcprefix = zonemap['Mappings']['RegionMap'][region]['PREFIXLIST']        
        # create security group for rds
        self.rdssg = ec2.SecurityGroup(
            self,
            f"{construct_id}:MyRdsSG",
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
        res = 'rdsmariasmall'
        resname = resmap['Mappings']['Resources'][res]['NAME']
        ressize = resmap['Mappings']['Resources'][res]['SIZE']
        resclass = resmap['Mappings']['Resources'][res]['CLASS']
        resusr = resmap['Mappings']['Resources'][res]['DBUSR']
        respol = resmap['Mappings']['Resources'][res]['RemovalPolicy']
        # create RDS Instance
        self.rds = rds.DatabaseInstance(
            self,
            f"{construct_id}:MyRdsInstance",
            engine=rds.DatabaseInstanceEngine.MARIADB,
            instance_type=ec2.InstanceType.of(
                instance_class=ec2.InstanceClass(resclass),
                instance_size=ec2.InstanceSize(ressize)
            ),
            database_name=f"{construct_id}:MydataBase",
            vpc=self.vpc,
            allow_major_version_upgrade=True,
            auto_minor_version_upgrade=True,
            delete_automated_backups=True,
            vpc_subnets=ec2.SubnetType.PUBLIC,
            security_groups=[self.rdssg],
            publicly_accessible=True,
            credentials=rds.Credentials.from_generated_secret(resusr),
            deletion_protection=False,
            removal_policy=core.RemovalPolicy(respol),
            cloudwatch_logs_exports=[
                "error",
                "general",
                "slowquery",
                "audit"
            ],
            cloudwatch_logs_retention=log.RetentionDays.ONE_WEEK,
        )
        core.CfnOutput(
            self,
            f"{construct_id}:rds-endpoint",
            value=f"{self.rds.db_instance_endpoint_address}:{self.rds.db_instance_endpoint_port}",
            export_name=f"{construct_id}:rds-endpoint"
        )
class mariasazpriv(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, vpc = ec2.Vpc, bastionsg = ec2.SecurityGroup, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.vpc = vpc
        self.bastionsg = bastionsg
        # get prefix list from file to allow traffic from the office
        srcprefix = zonemap['Mappings']['RegionMap'][region]['PREFIXLIST']        
        # create security group for rds
        self.rdssg = ec2.SecurityGroup(
            self,
            f"{construct_id}:MyRdsSG",
            allow_all_outbound=True,
            vpc=self.vpc
        )
         # add ingress rules
        self.rdssg.add_ingress_rule(
            self.bastionsg,
            ec2.Port.all_traffic()
        )
        self.rdssg.add_ingress_rule(
            self.rdssg,
            ec2.Port.all_traffic()
        )
        # get data for rds resource
        res = 'rdsmariasmall'
        resname = resmap['Mappings']['Resources'][res]['NAME']
        ressize = resmap['Mappings']['Resources'][res]['SIZE']
        resclass = resmap['Mappings']['Resources'][res]['CLASS']
        resusr = resmap['Mappings']['Resources'][res]['DBUSR']
        respol = resmap['Mappings']['Resources'][res]['RemovalPolicy']
        # create RDS Instance
        self.rds = rds.DatabaseInstance(
            self,
            f"{construct_id}:MyRdsInstance",
            engine=rds.DatabaseInstanceEngine.MARIADB,
            instance_type=ec2.InstanceType.of(
                instance_class=ec2.InstanceClass(resclass),
                instance_size=ec2.InstanceSize(ressize)
            ),
            database_name=f"{construct_id}:MydataBase",
            vpc=self.vpc,
            allow_major_version_upgrade=True,
            auto_minor_version_upgrade=True,
            delete_automated_backups=True,
            vpc_subnets=ec2.SubnetType.PRIVATE,
            security_groups=[self.rdssg],
            publicly_accessible=True,
            credentials=rds.Credentials.from_generated_secret(resusr),
            deletion_protection=False,
            removal_policy=core.RemovalPolicy(respol),
            cloudwatch_logs_exports=[
                "error",
                "general",
                "slowquery",
                "audit"
            ],
            cloudwatch_logs_retention=log.RetentionDays.ONE_WEEK,
        )
        core.CfnOutput(
            self,
            f"{construct_id}:rds-endpoint",
            value=f"{self.rds.db_instance_endpoint_address}:{self.rds.db_instance_endpoint_port}",
            export_name=f"{construct_id}:rds-endpoint"
        )
class mariasazisol(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, vpc = ec2.Vpc, bastionsg = ec2.SecurityGroup, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.vpc = vpc
        self.bastionsg = bastionsg
        # get prefix list from file to allow traffic from the office
        srcprefix = zonemap['Mappings']['RegionMap'][region]['PREFIXLIST']        
        # create security group for rds
        self.rdssg = ec2.SecurityGroup(
            self,
            f"{construct_id}:MyRdsSG",
            allow_all_outbound=True,
            vpc=self.vpc
        )
         # add ingress rules
        self.rdssg.add_ingress_rule(
            self.bastionsg,
            ec2.Port.all_traffic()
        )
        self.rdssg.add_ingress_rule(
            self.rdssg,
            ec2.Port.all_traffic()
        )
        # get data for rds resource
        res = 'rdsmariasmall'
        resname = resmap['Mappings']['Resources'][res]['NAME']
        ressize = resmap['Mappings']['Resources'][res]['SIZE']
        resclass = resmap['Mappings']['Resources'][res]['CLASS']
        resusr = resmap['Mappings']['Resources'][res]['DBUSR']
        respol = resmap['Mappings']['Resources'][res]['RemovalPolicy']
        # create RDS Instance
        self.rds = rds.DatabaseInstance(
            self,
            f"{construct_id}:MyRdsInstance",
            engine=rds.DatabaseInstanceEngine.MARIADB,
            instance_type=ec2.InstanceType.of(
                instance_class=ec2.InstanceClass(resclass),
                instance_size=ec2.InstanceSize(ressize)
            ),
            database_name=f"{construct_id}:MydataBase",
            vpc=self.vpc,
            allow_major_version_upgrade=True,
            auto_minor_version_upgrade=True,
            delete_automated_backups=True,
            vpc_subnets=ec2.SubnetType.ISOLATED,
            security_groups=[self.rdssg],
            publicly_accessible=True,
            credentials=rds.Credentials.from_generated_secret(resusr),
            deletion_protection=False,
            removal_policy=core.RemovalPolicy(respol),
            cloudwatch_logs_exports=[
                "error",
                "general",
                "slowquery",
                "audit"
            ],
            cloudwatch_logs_retention=log.RetentionDays.ONE_WEEK,
        )
        core.CfnOutput(
            self,
            f"{construct_id}:rds-endpoint",
            value=f"{self.rds.db_instance_endpoint_address}:{self.rds.db_instance_endpoint_port}",
            export_name=f"{construct_id}:rds-endpoint"
        )
