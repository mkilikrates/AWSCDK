import os
import json
from aws_cdk import (
    aws_iam as iam,
    aws_eks as eks,
    core
)
import constructs as constructs
import cdk8s as cdk8s
import cdk8s_plus as kplus

account = os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"])
region = os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])
resconf = "resourcesmap.cfg"
with open(resconf) as resfile:
    resmap = json.load(resfile)

class MyAppStack(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, res, ekscluster = eks.Cluster, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.eksclust = ekscluster
        res = res
        self.bucketname = resmap['Mappings']['Resources'][res]['S3']
        # create policy to pod
        mypodprincipal = iam.OpenIdConnectPrincipal(self.eksclust.open_id_connect_provider)
        self.mysvcacc = self.eksclust.add_service_account(
            f"{construct_id}svcacc",
            name=f"{construct_id}svcacc",
            namespace=('default')
        )
        self.mysvcacc.add_to_principal_policy(
            statement=iam.PolicyStatement(
                actions=[
                    "s3:GetObject",
                    "s3:ListBucket"
                ],
                resources=[
                    f"arn:aws:s3:::{self.bucketname}",
                    f"arn:aws:s3:::{self.bucketname}/images/*"
                ],
                effect=iam.Effect.ALLOW,
            )
        )
        self.mypod = {
            'apiVersion': 'v1',
            'kind': 'Pod',
            'metadata': { 'name': f"{construct_id}nginximagepod" },
            'spec': {
                'serviceAccountName': self.mysvcacc.service_account_name,
                'containers': [
                    {
                        'name': f"{construct_id}",
                        'image': 'nginx',
                        'ports': [ { 'containerPort': 80 }],
                        'volumeMounts': [ { 'name': 'www', 'mountPath' : '/usr/share/nginx/html' } ]
                    }
                ],
                'initContainers': [
                    {
                        'name': f"{construct_id}s3cp",
                        'image': 'amazon/aws-cli',
                        'args' : [
                            's3',
                            'cp',
                            '--recursive',
                            f"s3://{self.bucketname}/images/",
                            "/www/"
                        ],
                        'volumeMounts': [ { 'name': 'www', 'mountPath' : '/www' } ]
                    }
                ],
                'volumes': [ { 'name': 'www', 'emptyDir': {} } ]
            }
        }
        self.eksclust.add_manifest(f"{construct_id}Pod", self.mypod)
        