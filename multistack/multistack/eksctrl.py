import os
import json
import requests
import yaml
from aws_cdk import (
    aws_ec2 as ec2,
    aws_eks as eks,
    aws_iam as iam,
    core,
)
import multistack.ekselb as MyChart
import cdk8s as cdk8s
account = core.Aws.ACCOUNT_ID
region = core.Aws.REGION

class eksELB(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, ekscluster = eks.Cluster, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.eksclust = ekscluster
        # service account for load balancer
        self.albsvcacc = self.eksclust.add_service_account(
            "aws-load-balancer-controller",
            name="aws-load-balancer-controller",
            namespace=('default')
        )
        url = 'https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/v2.1.3/docs/install/iam_policy.json'
        mypol = requests.get(url)
        mypolstat = json.dumps(mypol.json())
        mynewpol = json.loads(mypolstat)
        for statement in mynewpol['Statement']:
            self.albsvcacc.add_to_principal_policy(iam.PolicyStatement.from_json(statement))
        # load balancer controller
        self.eksclust.add_cdk8s_chart(
            "aws-load-balancer-controller",
            chart=MyChart.Albctrl(cdk8s.App(),"aws-load-balancer-controller", clustername = self.eksclust.cluster_name, namespace='default')
        ).node.add_dependency(self.albsvcacc)

class eksDNS(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, ekscluster = eks.Cluster, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.eksclust = ekscluster
        # service account for external dns controller
        self.dnsvcacc = self.eksclust.add_service_account(
            "external-dns",
            name="external-dns",
            namespace=('default')
        )
        # external dns controller
        self.manifest = MyChart.extdns(
                cdk8s.App(),
                "Manifest-external-dns",
                svcaccount = self.dnsvcacc,
        )
        # apply chart
        self.chart = self.eksclust.add_cdk8s_chart(
            "external-dns",
            chart=self.manifest
        ).node.add_dependency(self.dnsvcacc)

