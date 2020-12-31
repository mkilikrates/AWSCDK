import os
import json
from aws_cdk import (
    aws_lambda as lambda_,
    aws_lambda_python as lpython,
    aws_iam as iam,
    aws_events as events,
    aws_events_targets as targets,
    aws_logs as log,
    core,
)
account = os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"])
region = os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])


class VpcFrugalStack(core.Stack):

    def __init__(self, scope: core.Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # The code that defines your stack goes here
        # create Police for lambda function
        mylambdapolicy = iam.PolicyStatement(
            actions=[
                "ec2:DescribeVpcs",
                "ec2:DescribeVpcAttribute",
                "ec2:DescribeInstances",
                "route53:GetHostedZone",
                "route53:ChangeResourceRecordSets",
                "route53:ListHostedZones",
                "route53:AssociateVPCWithHostedZone",
                "route53:DisassociateVPCFromHostedZone",
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:DescribeLogGroups",
                "logs:DescribeLogStreams",
                "logs:PutLogEvents"
            ],
            resources=["*"],
            effect=iam.Effect.ALLOW
        )
        mylambdarole = iam.Role(
            self,
            "LambdaRole",
            assumed_by=iam.ServicePrincipal(
                'lambda.amazonaws.com'
            ),
            description=(
                'Role for Lambda to update resources using Tags'
            )
        )
        mylambdarole.add_to_policy(mylambdapolicy)
        # Create Lambda Function
        mylambda = lpython.PythonFunction(
            self,
            'TagToLambda',
            handler="lambda_handler",
            timeout=core.Duration.seconds(90),
            runtime=lambda_.Runtime.PYTHON_3_8,
            description="Lambda to update resources using Tags",
            entry="lib/mylambdatag/",
            role=(mylambdarole),
            log_retention=log.RetentionDays.ONE_WEEK
        )
        # Create Event Rule target Lambda
        myec2rule = events.Rule(
            self,
            "EC2TagsState",
            description="EventRule for EC2 state change",
            event_pattern=events.EventPattern(
                source=["aws.ec2"],
                detail_type=[
                    "EC2 Instance State-change Notification"
                ],
                detail={
                    "state":[
                        "running",
                        "shutting-down",
                        "stopping"
                    ]
                }
            ),
            enabled=True,
            targets=[
                targets.LambdaFunction(
                    handler=mylambda
                )
            ]
        )

