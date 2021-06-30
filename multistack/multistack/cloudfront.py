import os
import json
import aws_cdk.core as core
import aws_cdk.aws_cloudfront as cloudfront
account = os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"])
region = os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])
class CloudFrontStack(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, res, origin, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        res = res
        resconf = "resourcesmap.cfg"
        with open(resconf) as resfile:
            resmap = json.load(resfile)
        # CloudFrontWebDistribution
        self.distribution = cloudfront.CloudFrontWebDistribution(
            self,
            f"{self.stack_name}WDist",
            origin_configs=[cloudfront.SourceConfiguration(
                custom_origin_source=cloudfront.CustomOriginConfig(
                    domain_name=origin
                ),
                behaviors=[cloudfront.Behavior(is_default_behavior=True)]
            )]
        )
        core.CfnOutput(
            self,
            f"{self.stack_name}:sg",
            value=self.distribution.domain_name,
            export_name=f"{construct_id}:sg"
        )
        