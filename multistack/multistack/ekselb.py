import cdk8s_plus as kplus
import constructs
import cdk8s as cdk8s
from cdk8s_aws_alb_ingress_controller import (
    AwsLoadBalancerController, 
    AwsLoadBalancePolicy, 
    VersionsLists
)
from aws_cdk import (
    aws_ec2 as ec2,
    aws_eks as eks,
    aws_iam as iam,
    core,
)
account = core.Aws.ACCOUNT_ID
region = core.Aws.REGION
class Albctrl(cdk8s.Chart):
    def __init__(self, scope: constructs.Construct, construct_id: str, clustername: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.clustername = clustername
        AwsLoadBalancerController(
            self,
            f"{construct_id}-alb",
            cluster_name=self.clustername,
            create_service_account=False,
        )
        #AwsLoadBalancePolicy.add_policy(VersionsLists.AWS_LOAD_BALANCER_CONTROLLER_POLICY_V2, 'aws-load-balancer-controller')

class Albpol(cdk8s.Chart):
    def __init__(self, scope: constructs.Construct, construct_id: str, svcaccount = eks.ServiceAccount, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.svcaccount = svcaccount
        AwsLoadBalancePolicy.add_policy(
            version=VersionsLists.AWS_LOAD_BALANCER_CONTROLLER_POLICY_V2,
            role=self.svcaccount
        )

