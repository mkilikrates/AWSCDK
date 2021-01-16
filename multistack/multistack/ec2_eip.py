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
class EIP(core.Stack):

    def __init__(self, scope: core.Construct, construct_id: str, allocregion, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # The code that defines your stack goes here
        # create Police for lambda function
        self.mylambdapolicy = iam.PolicyStatement(
            actions=[
                "ec2:ReleaseAddress",
                "ec2:DescribeAddresses",
                "ec2:AllocateAddress",
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:DescribeLogGroups",
                "logs:DescribeLogStreams",
                "logs:PutLogEvents"
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
                'Role for Lambda to manage Elastic Ips as Custom Resources in CloudFormation'
            )
        )
        self.mylambdarole.add_to_policy(self.mylambdapolicy)
        # Create Lambda Function
        self.mylambda = lpython.PythonFunction(
            self,
            f"{construct_id}:Lambda",
            handler="lambda_handler",
            timeout=core.Duration.seconds(90),
            runtime=lambda_.Runtime.PYTHON_3_8,
            description="Lambda to manage Elastic Ips as Custom Resources in CloudFormation",
            entry="lambda/AssignEIP/",
            role=(self.mylambdarole),
            log_retention=log.RetentionDays.ONE_WEEK
        )
        self.mycustomresource = core.CfnCustomResource(
            self,
            f"{construct_id}:CustomResource",
            service_token=self.mylambda.function_arn
        ).add_property_override(
            "Properties.Region", allocregion
            )