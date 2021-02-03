import os
import json
from aws_cdk import (
    aws_lambda as lambda_,
    aws_lambda_python as lpython,
    aws_iam as iam,
    aws_logs as log,
    aws_ec2 as ec2,
    core,
)
account = os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"])
region = os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])
resconf = "resourcesmap.cfg"
with open(resconf) as resfile:
    resmap = json.load(resfile)

class S2SVPNS3(core.Stack):

    def __init__(self, scope: core.Construct, construct_id: str, route, res, vpnid = ec2.VpnConnection, vpc = ec2.Vpc, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # The code that defines your stack goes here
        # get imported objects
        self.vpc = vpc
        self.vpnid = vpnid.ref
        self.route = route
        res = res
        self.bucketname = resmap['Mappings']['Resources'][res]['S3']
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
                "s3:PutObject"
            ],
            resources=[
                f"arn:aws:s3:::{self.bucketname}",
                f"arn:aws:s3:::{self.bucketname}/vpn/*"
            ],
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
        
        self.mycustomresource = core.CustomResource(
            self,
            f"{construct_id}:CustomResource",
            service_token=self.mylambda.function_arn,
            properties=[
                {
                    "VPN" : self.vpnid,
                    "Route" : self.route,
                    "InstIPv4" : "insipv4",
                    "RemoteCidr" : self.vpc.vpc_cidr_block,
                    "LocalCidr" : "vpccidr",
                    "S3" : self.bucketname,
                }
            ]
        )
        core.CfnOutput(
            self,
            f"{construct_id}:LambdaArn",
            value=self.mylambda.function_arn,
            export_name=f"{construct_id}:LambdaArn"
        )
