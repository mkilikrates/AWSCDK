import os
import json
from aws_cdk import (
    aws_ec2 as ec2,
    core,
)
account = os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"])
region = os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])

class vpcebasicv4(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, vpc = ec2.Vpc, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.vpc = vpc
        # create security group for Interface VPC Endpoints
        self.vpcesg = ec2.SecurityGroup(
            self,
            'VPCEsg',
            vpc=self.vpc,
            allow_all_outbound=True,
            description='security group for Interface VPC Endpoints'
        )
        # ingress rules
        ec2.CfnSecurityGroupIngress(
            self,
            "MyVPCEIngressVPCIpv4",
            ip_protocol="-1",
            cidr_ip=self.vpc.vpc_cidr_block,
            group_id=self.vpcesg.security_group_id
        )
        # egress rule
        ec2.CfnSecurityGroupEgress(
            self,
            "MyVPCEEgressAllIpv4",
            ip_protocol="-1",
            cidr_ip="0.0.0.0/0",
            group_id=self.vpcesg.security_group_id
        )
        # add interface Endpoint
        # SSM
        ec2.InterfaceVpcEndpoint(
            self,
            'SSMEndpoint',
            vpc=self.vpc,
            service=ec2.InterfaceVpcEndpointAwsService.SSM,
            subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.ISOLATED,
                one_per_az=True
            ),
            security_groups=[self.vpcesg]
        )
        #EC2
        ec2.InterfaceVpcEndpoint(
            self,
            'EC2Endpoint',
            vpc=self.vpc,
            service=ec2.InterfaceVpcEndpointAwsService.EC2,
            subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.ISOLATED,
                one_per_az=True
            ),
            security_groups=[self.vpcesg]
        )
        #LOG
        ec2.InterfaceVpcEndpoint(
            self,
            'LogsEndpoint',
            vpc=self.vpc,
            service=ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS,
            subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.ISOLATED,
                one_per_az=True
            ),
            security_groups=[self.vpcesg]
        )
        #EVENTS
        ec2.InterfaceVpcEndpoint(
            self,
            'EventsEndpoint',
            vpc=self.vpc,
            service=ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_EVENTS,
            subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.ISOLATED,
                one_per_az=True
            ),
            security_groups=[self.vpcesg]
        )
        #MONITORING
        ec2.InterfaceVpcEndpoint(
            self,
            'MonitoringEndpoint',
            vpc=self.vpc,
            service=ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH,
            subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.ISOLATED,
                one_per_az=True
            ),
            security_groups=[self.vpcesg]
        )

class vpcebasicv6(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, vpc = ec2.Vpc, vpcstack = core.CfnStack.__name__, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.vpc = vpc
        self.vpcstack = vpcstack
        # create security group for Interface VPC Endpoints
        self.vpcesg = ec2.SecurityGroup(
            self,
            'VPCEsg',
            vpc=self.vpc,
            allow_all_outbound=True,
            description='security group for Interface VPC Endpoints'
        )
        # ingress rules
        ec2.CfnSecurityGroupIngress(
            self,
            "MyVPCEIngressVPCIpv4",
            ip_protocol="-1",
            cidr_ip=self.vpc.vpc_cidr_block,
            group_id=self.vpcesg.security_group_id
        )
        # can not use self.vpc.vpc_ipv6_cidr_blocks because this is not exported properly
        cidrv6 = core.Fn.import_value(
            f"{self.vpcstack}:vpccidrv6"
        )
        ec2.CfnSecurityGroupIngress(
            self,
            "MyVPCEIngressVPCIpv6",
            ip_protocol="-1",
            cidr_ipv6=cidrv6,
            group_id=self.vpcesg.security_group_id
        )
        # egress rule
        ec2.CfnSecurityGroupEgress(
            self,
            "MyVPCEEgressAllIpv6",
            ip_protocol="-1",
            cidr_ipv6="::/0",
            group_id=self.vpcesg.security_group_id
        )
        ec2.CfnSecurityGroupEgress(
            self,
            "MyVPCEEgressAllIpv4",
            ip_protocol="-1",
            cidr_ip="0.0.0.0/0",
            group_id=self.vpcesg.security_group_id
        )
        # add interface Endpoint
        # SSM
        ec2.InterfaceVpcEndpoint(
            self,
            'SSMEndpoint',
            vpc=self.vpc,
            service=ec2.InterfaceVpcEndpointAwsService.SSM,
            subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.ISOLATED,
                one_per_az=True
            ),
            security_groups=[self.vpcesg]
        )
        #EC2
        ec2.InterfaceVpcEndpoint(
            self,
            'EC2Endpoint',
            vpc=self.vpc,
            service=ec2.InterfaceVpcEndpointAwsService.EC2,
            subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.ISOLATED,
                one_per_az=True
            ),
            security_groups=[self.vpcesg]
        )
        #LOG
        ec2.InterfaceVpcEndpoint(
            self,
            'LogsEndpoint',
            vpc=self.vpc,
            service=ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS,
            subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.ISOLATED,
                one_per_az=True
            ),
            security_groups=[self.vpcesg]
        )
        #EVENTS
        ec2.InterfaceVpcEndpoint(
            self,
            'EventsEndpoint',
            vpc=self.vpc,
            service=ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_EVENTS,
            subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.ISOLATED,
                one_per_az=True
            ),
            security_groups=[self.vpcesg]
        )
        #MONITORING
        ec2.InterfaceVpcEndpoint(
            self,
            'MonitoringEndpoint',
            vpc=self.vpc,
            service=ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH,
            subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.ISOLATED,
                one_per_az=True
            ),
            security_groups=[self.vpcesg]
        )
        # S3
        #ec2.GatewayVpcEndpointAwsService(
            
        #)
