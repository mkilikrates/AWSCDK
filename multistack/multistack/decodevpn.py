#### How to call this file inside app.py file and options
#S3VPNStack = vpns3(app, "MY-S2SVPNS3", env=myenv, route = route, vpnid = S2SVPNStack.mycustomvpn, res = 's3bucket', vpc = VPCStack.vpc)
# where:
# S3VPNStack ==> Name of stack, used if you will import values from it in another stack
# vpns3 ==> reference to class S2SVPNS3 and name of this script decodevpn.py
# MY-S2SVPNS3 ==> Name of contruct, you can use on cdk (cdk list, cdk deploy or cdk destroy). . This is the name of Cloudformation Template in cdk.out dir (MY-S2SVPNS3.template.json)
# env ==> Environment to be used on this script (Account and region)
# route ==> what is the routing preference. (bgp | static)
# remoteregion ==> region where vpn was created (to read using describe vpn API CALL)
# funct ==> to just use a lambda function that already exist (in case of calling more than one time)
# res ==> resource name to be used in this script, see it bellow in resourcesmap.cfg
# vpnstackname ==> StackName in case of reference cross regions, to find the vpnid using this reference on lambda
# vpnid ==> VPN id to download configurantion and parse to write config files
# PS use vpnstackname or vpnid
# vpc ==> vcp-id where will be launched the virtual appliance

#### How to create a resource information on resourcesmap.cfg for this template
# {
#     "s3bucket": { 
#         "NAME": "mybucket",  ####==> It will be used to create Tag Name associated with this resource. (Mandatory)
#         "S3": "bucketname"   ####==> Bucket Name. (Mandatory)
#     }
# }
import os
import json
from aws_cdk import (
    aws_lambda as lambda_,
    aws_lambda_python as lpython,
    aws_iam as iam,
    aws_logs as log,
    aws_ec2 as ec2,
    aws_ssm as ssm,
    core,
)
account = os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"])
region = os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])
resconf = "resourcesmap.cfg"
with open(resconf) as resfile:
    resmap = json.load(resfile)

class S2SVPNS3(core.Stack):

    def __init__(self, scope: core.Construct, construct_id: str, route, remoteregion, funct, res, vpnstackname = str, vpnid = str, vpc = ec2.Vpc, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # The code that defines your stack goes here
        # get imported objects
        self.vpc = vpc
        vpnproperties = {}
        if remoteregion == '':
            remoteregion = region
        vpnproperties['Region'] = remoteregion
        if vpnid == '':
            vpnproperties['VPN'] = vpnstackname
        else:
            self.vpnid = vpnid
            vpnproperties['VPN'] = self.vpnid
        self.route = route
        vpnproperties['Route'] = self.route
        res = res
        if 'S3' in resmap['Mappings']['Resources'][res]:
            self.bucketname = resmap['Mappings']['Resources'][res]['S3']
            vpnproperties['S3'] = self.bucketname
        if 'VPNLRT' in resmap['Mappings']['Resources'][res]:
            self.vpnlrt = resmap['Mappings']['Resources'][res]['VPNLRT']
        else:
            self.vpnlrt = self.vpc.vpc_cidr_block
        vpnproperties['LocalCidr'] = self.vpnlrt
        if self.route == 'static':
            self.vpnrrt = resmap['Mappings']['Resources'][res]['VPNRRT']
            vpnproperties['RemoteCidr'] = self.vpnrrt
        if 'TYPE' in resmap['Mappings']['Resources'][res]:
            ec2type = resmap['Mappings']['Resources'][res]['TYPE']
        else:
            ec2type = ''
        vpnproperties['ApplianceKind'] = ec2type
        if funct =='':
            # create Police for lambda function
            self.mylambdapolicy = iam.PolicyStatement(
                actions=[
                    "ec2:DescribeVpnConnections",
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:DescribeLogGroups",
                    "logs:DescribeLogStreams",
                    "logs:PutLogEvents"
                ],
                resources=["*"],
                effect=iam.Effect.ALLOW
            )
            self.mylambdaS3policy = iam.PolicyStatement(
                actions=[
                    "s3:GetObject",
                    "s3:ListBucket",
                    "s3:DeleteObject",
                    "s3:PutObject",
                    "ssm:PutParameter"
                ],
                resources=[
                    f"arn:aws:s3:::{self.bucketname}",
                    f"arn:aws:s3:::{self.bucketname}/vpn/*"
                ],
                effect=iam.Effect.ALLOW
            )
            self.mylambdaSSMpolicy = iam.PolicyStatement(
                actions=[
                    "ssm:PutParameter",
                    "ssm:GetParameter",
                    "ssm:DeleteParameter"
                ],
                resources=["*"],
                effect=iam.Effect.ALLOW
            )
            self.mylambdarole = iam.Role(
                self,
                "LambdaRole",
                assumed_by=iam.ServicePrincipal(
                    'lambda.amazonaws.com'
                ),
                description=(
                    'Role for Lambda to write vpn config files on s3 bucket as Custom Resources in CloudFormation'
                )
            )
            self.mylambdarole.add_to_policy(self.mylambdapolicy)
            self.mylambdarole.add_to_policy(self.mylambdaS3policy)
            self.mylambdarole.add_to_policy(self.mylambdaSSMpolicy)
            # Create Lambda Function
            self.mylambda = lpython.PythonFunction(
                self,
                f"{construct_id}:Lambda",
                handler="lambda_handler",
                timeout=core.Duration.seconds(90),
                runtime=lambda_.Runtime.PYTHON_3_8,
                description="Lambda to write vpn config files on s3 bucket  as Custom Resources in CloudFormation",
                entry="lambda/DecoderVPN/",
                role=(self.mylambdarole),
                log_retention=log.RetentionDays.ONE_WEEK
            )
            funct = self.mylambda.function_arn
        self.mycustomresource = core.CustomResource(
            self,
            f"{construct_id}:CustomResource",
            service_token=funct,
            properties=[vpnproperties]
        )

        self.funct = core.CfnOutput(
            self,
            f"{construct_id}:LambdaArn",
            value=funct,
            export_name=f"{construct_id}:LambdaArn"
        )
        # # create Police for lambda function
        # self.vpnreadpolicy = iam.PolicyStatement(
        #     actions=[
        #         "s3:GetObject",
        #         "s3:ListBucket"
        #     ],
        #     resources=[
        #         f"arn:aws:s3:::{self.bucketname}",
        #         f"arn:aws:s3:::{self.bucketname}/vpn/{self.vpnid}*"
        #     ],
        #     effect=iam.Effect.ALLOW
        # )
        # self.bkt = core.CfnOutput(
        #     self,
        #     f"{construct_id}:bucketname",
        #     value=self.bucketname,
        #     export_name=f"{construct_id}:bucketname"
        # )
        # self.vpndir = core.CfnOutput(
        #     self,
        #     f"{construct_id}:folder",
        #     value=f"/vpn/{self.vpnid}/",
        #     export_name=f"{construct_id}:folder"
        # )
        