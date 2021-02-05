import os
import json
from aws_cdk import (
    aws_ec2 as ec2,
    aws_iam as iam,
    core,
)
account = core.Aws.ACCOUNT_ID
region = core.Aws.REGION

class vpcebasicv4(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, endptkind, vpc = ec2.Vpc, vpcstack = core.CfnStack.__name__, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.vpc = vpc
        self.vpcstack = vpcstack
        self.endptkind = endptkind
        if self.endptkind == 'freeonly':
            #S3 Policy
            self.iampolS3VpcEnd = iam.PolicyStatement(
                actions=[
                    "s3:*"
                ],
                effect=iam.Effect.DENY,
                resources=[
                    "*"
                ],
                principals=[
                    iam.AnyPrincipal()
                ],
                conditions=(
                    { "StringNotEquals" : { "aws:SourceVpc" : self.vpc.vpc_id } }
                ),
                sid=('Allow-only-VPC-to-use-it')
            )
            #S3
            ec2.GatewayVpcEndpoint(
                self,
                f"{construct_id}:S3Endpoint",
                vpc=self.vpc,
                service=ec2.GatewayVpcEndpointAwsService.S3,
            ).add_to_policy(self.iampolS3VpcEnd)
        else:
            # create security group for Interface VPC Endpoints
            self.vpcesg = ec2.SecurityGroup(
                self,
                f"{construct_id}:VPCEsg",
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
            if self.vpc.stack == 'Ipv6':
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
                "MyVPCEEgressAllIpv4",
                ip_protocol="-1",
                cidr_ip="0.0.0.0/0",
                group_id=self.vpcesg.security_group_id
            )
            if self.vpc.stack == 'Ipv6':
                # egress rule
                ec2.CfnSecurityGroupEgress(
                    self,
                    "MyVPCEEgressAllIpv6",
                    ip_protocol="-1",
                    cidr_ipv6="::/0",
                    group_id=self.vpcesg.security_group_id
                )
            # add interface Endpoint
            # SSM
            ec2.InterfaceVpcEndpoint(
                self,
                f"{construct_id}:SSMEndpoint",
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
                f"{construct_id}:EC2Endpoint",
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
                f"{construct_id}:LogsEndpoint",
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
                f"{construct_id}:EventsEndpoint",
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
                f"{construct_id}:MonitoringEndpoint",
                vpc=self.vpc,
                service=ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH,
                subnets=ec2.SubnetSelection(
                    subnet_type=ec2.SubnetType.ISOLATED,
                    one_per_az=True
                ),
                security_groups=[self.vpcesg]
            )
