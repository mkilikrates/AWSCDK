import json
import cdk8s_plus as kplus
import constructs
import cdk8s as cdk8s
# import yaml
# import path

from cdk8s_aws_alb_ingress_controller import (
    AwsLoadBalancerController as ingAwsLoadBalancerController, 
    AwsLoadBalancePolicy as ingAwsLoadBalancePolicy, 
    VersionsLists as ingVersionsLists,
)
from cdk8s_aws_load_balancer_controller import (
    AwsLoadBalancerController as albAwsLoadBalancerController, 
    AwsLoadBalancePolicy as albAwsLoadBalancePolicy, 
    VersionsLists as albVersionsLists,
)
from cdk8s_external_dns import (
    AwsExternalDns, 
    AwsZoneTypeOptions, 
    AwsExternalDnsPolicyHelper
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
    def __init__(self, scope: constructs.Construct, construct_id: str, clustername: str, svcaccount = eks.ServiceAccount, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.clustername = clustername
        albAwsLoadBalancerController(
            self,
            f"{construct_id}-alb",
            cluster_name=self.clustername,
            create_service_account=False,
        )
        albAwsLoadBalancePolicy.add_policy(albVersionsLists.AWS_LOAD_BALANCER_CONTROLLER_POLICY_V2.value, 'aws-load-balancer-controller')

class Ingctrl(cdk8s.Chart):
    def __init__(self, scope: constructs.Construct, construct_id: str, clustername: str, svcaccount = eks.ServiceAccount, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.clustername = clustername
        ingAwsLoadBalancerController(
            self,
            f"{construct_id}-ing",
            cluster_name=self.clustername,
            create_service_account=False,
        )
        ingAwsLoadBalancePolicy.add_policy(ingVersionsLists.AWS_LOAD_BALANCER_CONTROLLER_POLICY_V2.value, 'aws-ingress-controller')

class extdns(cdk8s.Chart):
    def __init__(self, scope: constructs.Construct, construct_id: str, svcaccount = eks.ServiceAccount, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.svcaccount = svcaccount
        AwsExternalDns(
            self,
            "external-dns",
            domain_filter='',
            aws_zone_type=AwsZoneTypeOptions.PRIVATE
            # https://github.com/kubernetes-sigs/external-dns/blob/master/docs/tutorials/aws-sd.md
            # Valid values are public, private, or no value for both
        )
        AwsExternalDnsPolicyHelper.add_policy(self.svcaccount)

class extdnspol(cdk8s.Chart):
    def __init__(self, scope: constructs.Construct, construct_id: str, svcaccount = eks.ServiceAccount, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.svcaccount = svcaccount
        AwsExternalDnsPolicyHelper.add_policy(self.svcaccount)

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
        www = kplus.IConfigMap = kplus.ConfigMap.from_config_map_name('www')
        appvol = kplus.Volume.from_config_map(www)
        # defining containeres
        container = kplus.Container(
            name='nginx',
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
            name='awscli',
            image='amazon/aws-cli',
            args=['s3', 'cp', '--recursive', f"s3://{ress3}/{ress3pfx}/", "/www/"],
            volume_mounts=[
                kplus.VolumeMount(
                    path='/www',
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
            service_type=kplus.ServiceType.NODE_PORT
        )
        self.ingress = kplus.Ingress(
            self,
            "-ing",
        )
        for k,v in svcannot.items():
            self.ingress._api_object.metadata.add_annotation(k,v)
#            print("Key: {0}, Value: {1}".format(k,v))
        self.ingress.add_rule(
            path='/*',
            backend=kplus.IngressBackend.from_service(self.service),
        )
class deployment(cdk8s.Chart):
    def __init__(self, scope: constructs.Construct, construct_id: str, res: str, svcaccname: str, labels: dict, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.svcaccname = svcaccname
        res = res
        resname = resmap['Mappings']['Resources'][res]['NAME']
        restgport = resmap['Mappings']['Resources'][res]['TGPORT']
        ress3 = resmap['Mappings']['Resources'][res]['S3']
        ress3pfx = resmap['Mappings']['Resources'][res]['S3PRFX']
        desircap = resmap['Mappings']['Resources'][res]['desir']
        appdomain = resmap['Mappings']['Resources'][res]['DOMAIN']

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
            port=restgport,
            name=f"{construct_id}"
        )
        initcontainer = kplus.Container(
            image='amazon/aws-cli',
            args=['s3', 'cp', '--recursive', f"s3://{ress3}/{ress3pfx}/", "/www/"],
            volume_mounts=[
                kplus.VolumeMount(
                    path='/www',
                    volume=appvol,
                    read_only=False
                ),
            ],
            name='s3cp'
        )
        # defining a deployment
        self.deployment = kplus.Deployment(
            self,
            f"{construct_id}",
            replicas=desircap,
            service_account=kplus.ServiceAccount.from_service_account_name(self.svcaccname),
            containers=[container]
            #initcontainers=[initcontainer]
            # https://github.com/cdk8s-team/cdk8s/issues/545
        ).select_by_label(key='app', value=f"{resname}.{appdomain}")

class service(cdk8s.Chart):
    def __init__(self, scope: constructs.Construct, construct_id: str, res: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.deployment = deployment
        res = res
        resname = resmap['Mappings']['Resources'][res]['NAME']
        restgport = resmap['Mappings']['Resources'][res]['TGPORT']
        appdomain = resmap['Mappings']['Resources'][res]['DOMAIN']
        # defining a service
        self.service = kplus.Service(
            self,
            f"{construct_id}-service",
        )
        self.service.serve(port=restgport)
        self.service.add_selector(label='app.kubernetes.io/name', value=f"{resname}.{appdomain}")

class ingress(cdk8s.Chart):
    def __init__(self, scope: constructs.Construct, construct_id: str, res: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        reslbport = resmap['Mappings']['Resources'][res]['LBPORT']
        resname = resmap['Mappings']['Resources'][res]['NAME']
        appdomain = resmap['Mappings']['Resources'][res]['DOMAIN']
        self.ingress = kplus.Ingress(
            self,
            "-ing",
        )
        for k,v in svcannot.items():
            self.ingress._api_object.metadata.add_annotation(k,v)
#            print("Key: {0}, Value: {1}".format(k,v))

