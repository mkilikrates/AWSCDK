import json
import cdk8s_plus as kplus
import constructs
import cdk8s as cdk8s
import yaml
import path

from cdk8s_aws_alb_ingress_controller import (
    AwsLoadBalancerController, 
    AwsLoadBalancePolicy, 
    VersionsLists,
)
from aws_cdk import (
    aws_ec2 as ec2,
    aws_eks as eks,
    aws_iam as iam,
    core,
)
account = core.Aws.ACCOUNT_ID
region = core.Aws.REGION
resconf = "resourcesmap.cfg"
with open(resconf) as resfile:
    resmap = json.load(resfile)

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
class certmgr(cdk8s.Chart):
    def __init__(self, scope: constructs.Construct, construct_id: str, clustername: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.clustername = clustername
        CertManager(
            
        )
        AwsLoadBalancerController(
            self,
            f"{construct_id}-alb",
            cluster_name=self.clustername,
            create_service_account=False,
        )

class Albpol(cdk8s.Chart):
    def __init__(self, scope: constructs.Construct, construct_id: str, svcaccount = eks.ServiceAccount, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.svcaccount = svcaccount
        AwsLoadBalancePolicy.add_policy(
            version=VersionsLists.AWS_LOAD_BALANCER_CONTROLLER_POLICY_V2,
            role=self.svcaccount
        )

class nginxs3(cdk8s.Chart):
    def __init__(self, scope: constructs.Construct, construct_id: str, clustername: str, res: str, svcaccname: str, svcannot: dict, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.clustername = clustername
        res = res
        resname = resmap['Mappings']['Resources'][res]['NAME']
        restgport = resmap['Mappings']['Resources'][res]['TGPORT']
        reslbport = resmap['Mappings']['Resources'][res]['LBPORT']
        desircap = resmap['Mappings']['Resources'][res]['desir']
        appdomain = resmap['Mappings']['Resources'][res]['DOMAIN']
        ressubgrp = resmap['Mappings']['Resources'][res]['SUBNETGRP']
        reselb = resmap['Mappings']['Resources'][res]['LBType']
        elbface = resmap['Mappings']['Resources'][res]['INTERNET']
        ress3 = resmap['Mappings']['Resources'][res]['S3']
        ress3pfx = resmap['Mappings']['Resources'][res]['S3PRFX']
        # defining some common variables
        appvol = kplus.Volume.from_empty_dir('www')
        # defining containeres
        container = kplus.Container(
            image='nginx',
            volume_mounts=[
                kplus.VolumeMount(
                    path='/usr/share/nginx/html',
                    volume=appvol,
                    read_only=True
                )
            ],
            port=restgport
        )
        initcontainer = kplus.Container(
            image='amazon/aws-cli',
            args=['s3', 'cp', '--recursive', f"s3://{ress3}/{ress3pfx}/", "/www/"],
            volume_mounts=[
                kplus.VolumeMount(
                    path='/usr/share/nginx/html',
                    volume=appvol,
                    read_only=False
                )
            ]
        )
        # defining a deployment
        self.deployment = kplus.Deployment(
            self,
            "-deployment",
            replicas=desircap,
            service_account=kplus.ServiceAccount.from_service_account_name(svcaccname),
            containers=[container],
            #initcontainers=[initcontainer]
            # https://github.com/cdk8s-team/cdk8s/issues/545
        )
        # defining a service
        self.service = self.deployment.expose(
            restgport,
            service_type=kplus.ServiceType.NODE_PORT,
        )
        self.ingress = kplus.Ingress(
            self,
            "-ing",
        )
        for k,v in svcannot.items():
            self.ingress._api_object.metadata.add_annotation(k,v)
#            print("Key: {0}, Value: {1}".format(k,v))
        self.ingress.add_host_rule(
            host=f"{resname}.{appdomain}",
            path='/*',
            backend=kplus.IngressBackend.from_service(self.service)
        )
class deployment(cdk8s.Chart):
    def __init__(self, scope: constructs.Construct, construct_id: str, res: str, svcaccname: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.svcaccname = svcaccname
        res = res
        resname = resmap['Mappings']['Resources'][res]['NAME']
        restgport = resmap['Mappings']['Resources'][res]['TGPORT']
        ress3 = resmap['Mappings']['Resources'][res]['S3']
        ress3pfx = resmap['Mappings']['Resources'][res]['S3PRFX']
        desircap = resmap['Mappings']['Resources'][res]['desir']

        # defining some common variables
        appvol = kplus.Volume.from_empty_dir('www')
        # defining containeres
        container = kplus.Container(
            image='nginx',
            volume_mounts=[
                kplus.VolumeMount(
                    path='/usr/share/nginx/html',
                    volume=appvol,
                    read_only=True
                )
            ],
            port=restgport
        )
        initcontainer = kplus.Container(
            image='amazon/aws-cli',
            args=['s3', 'cp', '--recursive', f"s3://{ress3}/{ress3pfx}/", "/www/"],
            volume_mounts=[
                kplus.VolumeMount(
                    path='/usr/share/nginx/html',
                    volume=appvol,
                    read_only=False
                )
            ]
        )
        # defining a deployment
        self.deployment = kplus.Deployment(
            self,
            f"{construct_id}-deployment",
            replicas=desircap,
            service_account=kplus.ServiceAccount.from_service_account_name(self.svcaccname),
            containers=[container],
            #initcontainers=[initcontainer]
            # https://github.com/cdk8s-team/cdk8s/issues/545
        ).select_by_label(key='app', value=f"{construct_id}-{resname}")

class service(cdk8s.Chart):
    def __init__(self, scope: constructs.Construct, construct_id: str, res: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.deployment = deployment
        res = res
        resname = resmap['Mappings']['Resources'][res]['NAME']
        restgport = resmap['Mappings']['Resources'][res]['TGPORT']
        # defining a service
        self.service = kplus.Service(
            self,
            f"{construct_id}-service",
        )
        self.service.serve(port=restgport)
        self.service.add_selector(label='app', value=f"{construct_id}-{resname}")

class ingress(cdk8s.Chart):
    def __init__(self, scope: constructs.Construct, construct_id: str, res: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        reslbport = resmap['Mappings']['Resources'][res]['LBPORT']
        resname = resmap['Mappings']['Resources'][res]['NAME']
        appdomain = resmap['Mappings']['Resources'][res]['DOMAIN']
        appLabel = { 'app': f"{construct_id}-{resname}"}
        self.ingress = kplus.Ingress(
            self,
            f"{construct_id}-ingress",
        )




