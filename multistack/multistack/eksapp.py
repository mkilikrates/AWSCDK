import os
import json
import yaml
from aws_cdk import (
    aws_iam as iam,
    aws_eks as eks,
    aws_ec2 as ec2,
    aws_certificatemanager as acm,
    aws_route53 as r53,
    aws_route53_targets as r53tgs,
    core
)
import multistack.ekselb as MyChart
import cdk8s as cdk8s

account = os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"])
region = os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])
resconf = "resourcesmap.cfg"
with open(resconf) as resfile:
    resmap = json.load(resfile)

class MyAppStack(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, res, preflst, allowall, vpc = ec2.Vpc, allowsg = ec2.SecurityGroup, ekscluster = eks.Cluster, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.eksclust = ekscluster
        self.vpc = vpc
        allowsg = allowsg
        res = res
        resname = resmap['Mappings']['Resources'][res]['NAME']
        restgport = resmap['Mappings']['Resources'][res]['TGPORT']
        reslbport = resmap['Mappings']['Resources'][res]['LBPORT']
        desircap = resmap['Mappings']['Resources'][res]['desir']
        appdomain = resmap['Mappings']['Resources'][res]['DOMAIN']
        ressubgrp = resmap['Mappings']['Resources'][res]['SUBNETGRP']
        reselb = resmap['Mappings']['Resources'][res]['LBType']
        elbface = resmap['Mappings']['Resources'][res]['INTERNET']

        self.mysvcacc = self.eksclust.add_service_account(
            f"{construct_id}-{resname}-svcacc",
            name=f"{construct_id}-{resname}-svcacc",
            namespace=('default')
        )
        # get hosted zone id
        self.hz = r53.HostedZone.from_lookup(
            self,
            f"{construct_id}:Domain",
            domain_name=appdomain,
            private_zone=False
        )
        # generate public certificate
        self.cert = acm.Certificate(
            self,
            f"{construct_id}:Certificate",
            domain_name=f"{resname}.{appdomain}",
            validation=acm.CertificateValidation.from_dns(self.hz)
        )

        # check if want to want copy files to nginx test
        if 'S3CP' in resmap['Mappings']['Resources'][res]:
            res = resmap['Mappings']['Resources'][res]['S3CP']
            self.bucketname = resmap['Mappings']['Resources'][res]['S3']
            # create policy to pod
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
            # create a deployment using serviceaccount and initContainers to copy content to be served
            appLabel = { 'app': f"{construct_id}-{resname}"}
            self.mydeploy = {
                'apiVersion': 'apps/v1',
                'kind': 'Deployment',
                'metadata': { 'name': f"{construct_id}-{resname}" },
                'spec': {
                    'replicas': desircap,
                    'selector': { 'matchLabels': appLabel },
                    'template': {
                        'metadata': { 'labels': appLabel },
                        'spec':{
                            'serviceAccountName': self.mysvcacc.service_account_name,
                            'containers': [
                                {
                                    'name': f"{construct_id}-{resname}",
                                    'image': 'nginx',
                                    'ports': [ { 'containerPort': restgport }],
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
                }
            }
            output = yaml.dump(self.mydeploy)
            print(output)
            # add annotations to service
            mysvcannot = {}
            self.mysvc = {
                'apiVersion': 'v1',
                'kind': 'Service',
                'metadata': { 
                    'name': f"{construct_id}mysvc",
                    'annotations': mysvcannot
                },
                'spec': {
                    'type': "LoadBalancer",
                    'ports': [
                        {
                            'port': reslbport,
                            'targetPort': restgport
                        }
                    ],
                    'selector': appLabel
                }
            }
            output = yaml.dump(self.mysvc)
            print(output)

            if ressubgrp == 'Private':
                mysvcannot['service.beta.kubernetes.io/aws-load-balancer-internal'] = 'true'
            if reselb == 'clb':
                mysvcannot['service.beta.kubernetes.io/aws-load-balancer-ssl-cert'] = self.cert.certificate_arn
                mysvcannot['service.beta.kubernetes.io/aws-load-balancer-backend-protocol'] = 'http'
            if reselb == 'alb':
                mysvcannot['kubernetes.io/ingress.class'] = 'alb'
                if elbface == True:
                    mysvcannot['alb.ingress.kubernetes.io/scheme'] = 'internet-facing'
                if elbface == False:
                    mysvcannot['alb.ingress.kubernetes.io/scheme'] = 'internal'
                mysublist = self.vpc.select_subnets(subnet_group_name=ressubgrp,one_per_az=True).subnet_ids
                mysubstrlist = ', '.join(['"{}"'.format(value) for value in mysublist])
                #mysvcannot['alb.ingress.kubernetes.io/subnets'] = mysubstrlist
                # create security group for LB
                self.lbsg = ec2.SecurityGroup(
                    self,
                    f"{construct_id}MyLBsg",
                    allow_all_outbound=True,
                    vpc=self.vpc
                )
                if allowall == True:
                    self.lbsg.add_ingress_rule(
                        ec2.Peer.any_ipv4,
                        ec2.Port.all_traffic()
                    )
                    if self.vpc.stack == 'Ipv6':
                        self.lbsg.add_ingress_rule(
                            ec2.Peer.any_ipv6,
                            ec2.Port.all_traffic()
                        )
                if preflst == True:
                    # get prefix list from file to allow traffic from the office
                    srcprefix = zonemap['Mappings']['RegionMap'][region]['PREFIXLIST']        
                    self.lbsg.add_ingress_rule(
                        ec2.Peer.prefix_list(srcprefix),
                        ec2.Port.all_traffic()
                    )
                if type(allowall) == int or type(allowall) == float:
                    self.lbsg.add_ingress_rule(
                        ec2.Peer.any_ipv4(),
                        ec2.Port.tcp(allowall)
                    )
                    if self.vpc.stack == 'Ipv6':
                        self.lbsg.add_ingress_rule(
                            ec2.Peer.any_ipv6(),
                            ec2.Port.tcp(allowall)
                        )
                mysvcannot['alb.ingress.kubernetes.io/security-groups'] = self.lbsg.security_group_id
                if self.vpc.stack == 'Ipv6':
                    mysvcannot['alb.ingress.kubernetes.io/ip-address-type'] = 'dualstack'
                else:
                    mysvcannot['alb.ingress.kubernetes.io/ip-address-type'] = 'ipv4'
                mysvcannot['alb.ingress.kubernetes.io/listen-ports'] = '[{"HTTP": 80}, {"HTTPS": ' + str(reslbport) + '}]'
                mysvcannot['alb.ingress.kubernetes.io/target-type'] = 'ip'
                mysvcannot['alb.ingress.kubernetes.io/backend-protocol-version'] = 'HTTP2'
                mysvcannot['alb.ingress.kubernetes.io/actions.ssl-redirect'] = '{"Type": "redirect", "RedirectConfig": { "Protocol": "HTTPS", "Port": "443", "StatusCode": "HTTP_301" } }'
                mysvcannot['alb.ingress.kubernetes.io/certificate-arn'] = self.cert.certificate_arn
                self.myingress = {
                    'apiVersion': 'extensions/v1beta1',
                    'kind': 'Ingress',
                    'metadata': { 
                        'name': f"{construct_id}mysvc",
                        'labels': appLabel,
                        'annotations': mysvcannot
                    },
                    'spec': {
                        'rules': [
                            {
                                'http': {
                                    'paths' : [
                                        {
                                            'path' : '/*',
                                            'backend' : {
                                                'serviceName' : f"{construct_id}mysvc",
                                                'servicePort' : restgport
                                            },
                                        }
                                    ]
                                }
                            }
                        ]
                    }
                }
                output = yaml.dump(self.myingress)
                print(output)
                
                # https://docs.aws.amazon.com/cdk/api/latest/python/aws_cdk.aws_eks/README.html
                
            # deploy 
            self.manif = eks.KubernetesManifest(
                self,
                f"{construct_id}Manifest",
                cluster=self.eksclust,
                manifest=[self.mydeploy, self.mysvc, self.myingress]
            )
            # show the ELB name
            # core.CfnOutput(
            #     self,
            #     f"{construct_id}:ALB DNS",
            #     value=self.eksclust.get_service_load_balancer_address(f"{construct_id}mysvc")
            # )


