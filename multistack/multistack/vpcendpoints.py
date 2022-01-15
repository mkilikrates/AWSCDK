import os
import json
from aws_cdk import (
    aws_ec2 as ec2,
    aws_iam as iam,
    core,
)
account = core.Aws.ACCOUNT_ID
region = core.Aws.REGION
resconf = "resourcesmap.cfg"
with open(resconf) as resfile:
    resmap = json.load(resfile)
with open('zonemap.cfg') as zonefile:
    zonemap = json.load(zonefile)

class VPCEStack(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, res, preflst, allowall, ipstack, vpc = ec2.Vpc, allowsg = ec2.SecurityGroup, vpcstack = core.CfnStack.__name__, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        res = res
        # get imported objects
        self.vpc = vpc
        self.vpcstack = vpcstack
        self.ipstack = ipstack
        # get data for bastion resource
        counter = 0
        for endpt in resmap['Mappings']['Resources'][res]['EndpointList']:
            restype = endpt['Type']
            ressrv = endpt['Service']
            resname = endpt['Name']
            mypol =''
            if 'POLICE' in endpt:
                mypol = []
                for police in endpt['POLICE']:
                    newpol = {}
                    if 'Actions' in police:
                        newpol["actions"] = police['Actions']
                    if 'Conditions' in police:
                        newpol["conditions"] = police['Conditions']
                    if 'Effect' in police:
                        if police['Effect'] == "allow":
                            newpol["effect"] = iam.Effect.ALLOW
                        if police['Effect'] == "deny":
                            newpol["effect"] = iam.Effect.DENY
                    if 'NoActions' in police:
                        newpol["not_actions"] = police['NoActions']
                    if 'NoResources' in police:
                        newpol["not_resources"] = police['NoResources']
                    if 'Principals' in police:
                        newpol["principals"] = [iam.ArnPrincipal(police['Principals'])]
                    if 'NoPrincipals' in police:
                        newpol["not_principals"] = police['NoPrincipals']
                    if 'Resources' in police:
                        newpol["resources"] = police['Resources']
                    if 'SID' in police:
                        newpol["sid"] = police['SID']
                    mypol.append(iam.PolicyStatement(**newpol))
            if restype == 'Gateway':
                mys3gw = ec2.GatewayVpcEndpoint(
                    self,
                    f"{construct_id}:{resname}",
                    vpc=self.vpc,
                    service=ec2.GatewayVpcEndpointAwsService.S3,
                )
                if mypol != '':
                    for police in mypol:
                        mys3gw.add_to_principal_policy(statement=police)
            if restype == 'Interface':
                # create security group for Interface VPC Endpoints
                if counter == 0:
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
                    if self.ipstack == 'Ipv6':
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
                    if allowsg != '':
                        self.vpcesg.add_ingress_rule(
                            self.allowsg,
                            ec2.Port.all_traffic()
                        )
                    if preflst == True:
                        # get prefix list from file to allow traffic from the office
                        mymap = core.CfnMapping(
                            self,
                            f"{construct_id}Map",
                            mapping=zonemap["Mappings"]["RegionMap"]
                        )
                        srcprefix = mymap.find_in_map(core.Aws.REGION, 'PREFIXLIST')
                        self.vpcesg.add_ingress_rule(
                            ec2.Peer.prefix_list(srcprefix),
                            ec2.Port.all_traffic()
                        )
                    if allowall == True:
                        self.vpcesg.add_ingress_rule(
                            ec2.Peer.any_ipv4,
                            ec2.Port.all_traffic()
                        )
                        if self.ipstack == 'Ipv6':
                            self.vpcesg.add_ingress_rule(
                                ec2.Peer.any_ipv6,
                                ec2.Port.all_traffic()
                            )
                    if type(allowall) == int or type(allowall) == float:
                        self.vpcesg.add_ingress_rule(
                            ec2.Peer.any_ipv4(),
                            ec2.Port.tcp(allowall)
                        )
                        if self.ipstack == 'Ipv6':
                            self.vpcesg.add_ingress_rule(
                                ec2.Peer.any_ipv6(),
                                ec2.Port.tcp(allowall)
                            )
                    # egress rule
                    ec2.CfnSecurityGroupEgress(
                        self,
                        "MyVPCEEgressAllIpv4",
                        ip_protocol="-1",
                        cidr_ip="0.0.0.0/0",
                        group_id=self.vpcesg.security_group_id
                    )
                    if self.ipstack == 'Ipv6':
                        # egress rule
                        ec2.CfnSecurityGroupEgress(
                            self,
                            "MyVPCEEgressAllIpv6",
                            ip_protocol="-1",
                            cidr_ipv6="::/0",
                            group_id=self.vpcesg.security_group_id
                        )
                ressubgrp = endpt['SUBNETGRP']
                if ressrv == 'SSM':
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.SSM
                if ressrv == 'EC2':
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.EC2
                if ressrv == 'LOG':
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS
                if ressrv == 'EVENTS':
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_EVENTS
                if ressrv == 'CW':
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH
                if ressrv == "APIGATEWAY":
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.APIGATEWAY
                if ressrv == "ATHENA":
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.ATHENA
                if ressrv == "CLOUDFORMATION":
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.CLOUDFORMATION
                if ressrv == "CLOUDTRAIL":
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.CLOUDTRAIL
                if ressrv == "CODEBUILD":
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.CODEBUILD
                if ressrv == "CODEBUILD_FIPS":
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.CODEBUILD_FIPS
                if ressrv == "CODECOMMIT":
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.CODECOMMIT
                if ressrv == "CODECOMMIT_FIPS":
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.CODECOMMIT_FIPS
                if ressrv == "CODECOMMIT_GIT":
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.CODECOMMIT_GIT
                if ressrv == "CODECOMMIT_GIT_FIPS":
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.CODECOMMIT_GIT_FIPS
                if ressrv == "CODEPIPELINE":
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.CODEPIPELINE
                if ressrv == "CONFIG":
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.CONFIG
                if ressrv == "EC2_MESSAGES":
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.EC2_MESSAGES
                if ressrv == "ECR":
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.ECR
                if ressrv == "ECR_DOCKER":
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.ECR_DOCKER
                if ressrv == "ECS":
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.ECS
                if ressrv == "ECS_AGENT":
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.ECS_AGENT
                if ressrv == "ECS_TELEMETRY":
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.ECS_TELEMETRY
                if ressrv == "ELASTIC_FILESYSTEM":
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.ELASTIC_FILESYSTEM
                if ressrv == "ELASTIC_FILESYSTEM_FIPS":
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.ELASTIC_FILESYSTEM_FIPS
                if ressrv == "ELASTIC_INFERENCE_RUNTIME":
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.ELASTIC_INFERENCE_RUNTIME
                if ressrv == "ELASTIC_LOAD_BALANCING":
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.ELASTIC_LOAD_BALANCING
                if ressrv == "GLUE":
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.GLUE
                if ressrv == "KINESIS_FIREHOSE":
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.KINESIS_FIREHOSE
                if ressrv == "KINESIS_STREAMS":
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.KINESIS_STREAMS
                if ressrv == "KMS":
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.KMS
                if ressrv == "LAMBDA_":
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.LAMBDA_
                if ressrv == "REKOGNITION":
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.REKOGNITION
                if ressrv == "REKOGNITION_FIPS":
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.REKOGNITION_FIPS
                if ressrv == "SAGEMAKER_API":
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.SAGEMAKER_API
                if ressrv == "SAGEMAKER_NOTEBOOK":
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.SAGEMAKER_NOTEBOOK
                if ressrv == "SAGEMAKER_RUNTIME":
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.SAGEMAKER_RUNTIME
                if ressrv == "SAGEMAKER_RUNTIME_FIPS":
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.SAGEMAKER_RUNTIME_FIPS
                if ressrv == "SECRETS_MANAGER":
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.SECRETS_MANAGER
                if ressrv == "SERVICE_CATALOG":
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.SERVICE_CATALOG
                if ressrv == "SNS":
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.SNS
                if ressrv == "SQS":
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.SQS
                if ressrv == "SSM_MESSAGES":
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.SSM_MESSAGES
                if ressrv == "STEP_FUNCTIONS":
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.STEP_FUNCTIONS
                if ressrv == "STORAGE_GATEWAY":
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.STORAGE_GATEWAY
                if ressrv == "STS":
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.STS
                if ressrv == "TRANSFER":
                    vpcesrv = ec2.InterfaceVpcEndpointAwsService.TRANSFER
                if mypol == '':
                    ec2.InterfaceVpcEndpoint(
                        self,
                        f"{construct_id}{resname}",
                        vpc=self.vpc,
                        service=vpcesrv,
                        subnets=ec2.SubnetSelection(subnet_group_name=ressubgrp,one_per_az=True),
                        security_groups=[self.vpcesg],
                        #private_dns_enabled=False
                    )
                else:
                    ec2.InterfaceVpcEndpoint(
                        self,
                        f"{construct_id}{resname}",
                        vpc=self.vpc,
                        service=vpcesrv,
                        subnets=ec2.SubnetSelection(subnet_group_name=ressubgrp,one_per_az=True),
                        security_groups=[self.vpcesg]
                    ).add_to_principal_policy(statement=iam.PolicyStatement(**mypol))
                counter = counter + 1
