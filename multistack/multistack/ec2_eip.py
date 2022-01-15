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
account = core.Aws.ACCOUNT_ID
region = core.Aws.REGION
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
        #self.mylambdarole.add_to_policy(self.mylambdapolicy)
        self.mylambdarole.add_to_principal_policy(statement=self.mylambdapolicy)

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
        self.mycustomresource = core.CustomResource(
            self,
            f"{construct_id}:CustomResource",
            service_token=self.mylambda.function_arn,properties=[
                {
                    "Region" : allocregion
                }
            ]
        )
        self.ip = core.CfnOutput(
            self,
            f"{construct_id}:PublicIp",
            value=self.mycustomresource.get_att_string("PublicIp"),
            export_name=f"{construct_id}:PublicIp"
        )
        self.alloc = core.CfnOutput(
            self,
            f"{construct_id}:AllocationId",
            value=self.mycustomresource.get_att_string("AllocationId"),
            export_name=f"{construct_id}:AllocationId"
        )
        core.CfnOutput(
            self,
            f"{construct_id}:Region",
            value=self.mycustomresource.get_att_string("Region"),
            export_name=f"{construct_id}:Region"
        )


