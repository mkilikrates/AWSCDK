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
    cloud_assembly_schema as schema,
    core
)
import multistack.ekselb as MyChart
import cdk8s as cdk8s
yamloutdir = './cdk.out/'
account = os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"])
region = os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])
resconf = "resourcesmap.cfg"
with open(resconf) as resfile:
    resmap = json.load(resfile)

class MyAppStack(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, res, preflst, allowall, ipstack, vpc = ec2.Vpc, allowsg = ec2.SecurityGroup, ekscluster = eks.Cluster, elbsg = ec2.SecurityGroup, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.eksclust = ekscluster
        self.vpc = vpc
        self.ipstack = ipstack
        self.allowsg = allowsg
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
        appLabel = { 'app': f"{resname}.{appdomain}"}
        self.mysvcacc = self.eksclust.add_service_account(
            f"{construct_id}-{resname}-svcacc",
            name=f"{construct_id}-{resname}-svcacc",
            namespace=('default')
        )
        # # get hosted zone id
        self.hz = r53.HostedZone.from_lookup(
            self,
            f"{construct_id}:Domain",
            domain_name=appdomain,
            private_zone=False
        )
        # service account for external dns controller
        self.dnsvcacc = self.eksclust.add_service_account(
            "external-dns",
            name="external-dns",
            namespace=('default')
        )
        # external dns controller
        if elbface == True:
            domtype = "public"
        if elbface == False:
            domtype = "private"
        self.eksclust.add_cdk8s_chart(
            "cdk8sAwsExternalDns",
            chart=MyChart.extdns(cdk8s.App(),f"external-dns-{appdomain}", domain = appdomain, domaintype = domtype, svcaccount = self.dnsvcacc, namespace='default')
        ).node.add_dependency(self.dnsvcacc)

        #generate public certificate
        self.cert = acm.Certificate(
            self,
            f"{construct_id}:Certificate",
            domain_name=f"{resname}.{appdomain}",
            validation=acm.CertificateValidation.from_dns(self.hz)
        )
        # check if want to want copy files to nginx test
        self.mysvcacc.add_to_principal_policy(
            statement=iam.PolicyStatement(
                actions=[
                    "s3:GetObject",
                    "s3:ListBucket"
                ],
                resources=[
                    f"arn:aws:s3:::{ress3}",
                    f"arn:aws:s3:::{ress3}/{ress3pfx}/*"
                ],
                effect=iam.Effect.ALLOW,
            )
        )
        mysvcannot = {}
        if reselb == 'alb':
            # https://kubernetes-sigs.github.io/aws-load-balancer-controller/v2.1/guide/ingress/annotations/
            mysvcannot['kubernetes.io/ingress.class'] = reselb
            mysvcannot['alb.ingress.kubernetes.io/listen-ports'] = '[{"HTTP": 80}, {"HTTPS": ' + str(reslbport) + '}]'
            mysvcannot['alb.ingress.kubernetes.io/certificate-arn'] = self.cert.certificate_arn
            mysvcannot['alb.ingress.kubernetes.io/backend-protocol'] = "HTTP"
            mysvcannot['alb.ingress.kubernetes.io/success-codes'] = "200-499"
            mysvcannot['alb.ingress.kubernetes.io/actions.ssl-redirect'] = '{"Type": "redirect", "RedirectConfig": { "Protocol": "HTTPS", "Port": "443", "StatusCode": "HTTP_301"}}'
            if elbface == True:
                mysvcannot['alb.ingress.kubernetes.io/scheme'] = 'internet-facing'
            if elbface == False:
                mysvcannot['alb.ingress.kubernetes.io/scheme'] = 'internal'
            if self.ipstack == 'Ipv6':
                mysvcannot['alb.ingress.kubernetes.io/ip-address-type'] = 'dualstack'
            else:
                mysvcannot['alb.ingress.kubernetes.io/ip-address-type'] = 'ipv4'
            if elbsg != '':
                mysvcannot['alb.ingress.kubernetes.io/security-groups'] = elbsg.security_group_id
        if reselb == 'nlb':
            # https://kubernetes-sigs.github.io/aws-load-balancer-controller/v2.1/guide/service/annotations/
            mysvcannot['service.beta.kubernetes.io/aws-load-balancer-type'] = reselb
            mysvcannot['service.beta.kubernetes.io/backend-protocol'] = "tcp"
            if 'CROSSAZ' in resmap['Mappings']['Resources'][res]:
                rescrossaz = resmap['Mappings']['Resources'][res]['CROSSAZ']
                mysvcannot['service.beta.kubernetes.io/aws-load-balancer-cross-zone-load-balancing-enabled'] = f"{rescrossaz}"
            if elbface == True:
                mysvcannot['service.beta.kubernetes.io/scheme'] = 'internet-facing'
            if elbface == False:
                mysvcannot['service.beta.kubernetes.io/scheme'] = 'internal'
            if self.ipstack == 'Ipv6':
                mysvcannot['service.beta.kubernetes.io/ip-address-type'] = 'dualstack'
            else:
                mysvcannot['service.beta.kubernetes.io/ip-address-type'] = 'ipv4'
        if reselb == 'nlb-ip':
            # https://kubernetes-sigs.github.io/aws-load-balancer-controller/v2.1/guide/service/annotations/
            mysvcannot['service.beta.kubernetes.io/aws-load-balancer-type'] = reselb
            mysvcannot['service.beta.kubernetes.io/backend-protocol'] = "tcp"
            if 'CROSSAZ' in resmap['Mappings']['Resources'][res]:
                rescrossaz = resmap['Mappings']['Resources'][res]['CROSSAZ']
                mysvcannot['service.beta.kubernetes.io/aws-load-balancer-cross-zone-load-balancing-enabled'] = f"{rescrossaz}"
            if 'TGTGRATT' in resmap['Mappings']['Resources'][res]:
                tgtgrattlist = resmap['Mappings']['Resources'][res]['TGTGRATT']
                mysvcannot['service.beta.kubernetes.io/aws-load-balancer-target-group-attributes'] = tgtgrattlist
            if elbface == True:
                mysvcannot['service.beta.kubernetes.io/scheme'] = 'internet-facing'
            if elbface == False:
                mysvcannot['service.beta.kubernetes.io/scheme'] = 'internal'
            if self.ipstack == 'Ipv6':
                mysvcannot['service.beta.kubernetes.io/ip-address-type'] = 'dualstack'
            else:
                mysvcannot['service.beta.kubernetes.io/ip-address-type'] = 'ipv4'
        mysvcannot['external-dns.alpha.kubernetes.io/hostname'] = f"{resname}.{appdomain}"
        #print(mysvcannot)
        ########################################### Works
        # # define app chart
        # self.manifest = MyChart.nginxs3(
        #         cdk8s.App(),
        #         f"chart-{resname}",
        #         clustername = self.eksclust.cluster_name,
        #         svcaccname = f"{construct_id}-{resname}-svcacc",
        #         svcannot = mysvcannot,
        #         res = res,
        # )
        # # apply chart
        # self.chart = self.eksclust.add_cdk8s_chart(
        #     f"Manifest-{resname}",
        #     chart=self.manifest
        # )
        # core.CfnOutput(
        #     self,
        #     f"{construct_id}:ALB DNS",
        #     value=self.eksclust.get_service_load_balancer_address(f"{construct_id}mysvc")
        # )
        
        # manual deploy since ck8s not has support for initcontainers or ssl-redirect yet
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
                                'volumeMounts': [ { 'name': 'www', 'mountPath' : '/usr/share/nginx/html', "readOnly": True } ]
                            }
                        ],
                        'initContainers': [
                            {
                                'name': f"{construct_id}s3cp",
                                'image': 'amazon/aws-cli',
                                'args' : [ "s3", "cp", "--recursive", f"s3://{ress3}/{ress3pfx}/", "/www/"],
                                'volumeMounts': [ { 'name': 'www', 'mountPath' : '/www', "readOnly": False } ]
                            }
                        ],
                        'volumes': [ { 'name': 'www', 'emptyDir': {} } ]
                    }
                }
            }
        }
        if reselb == 'alb':
            # add annotations to service
            self.mysvc = {
                'apiVersion': 'v1',
                'kind': 'Service',
                'metadata': { 
                    'name': f"{construct_id}-{resname}",
                },
                'spec': {
                    'type': "NodePort",
                    'ports': [
                        {
                            'port': restgport,
                            'targetPort': restgport
                        }
                    ],
                    'selector': appLabel
                }
            }
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
                                            'serviceName' : "ssl-redirect",
                                            'servicePort' : "use-annotation"
                                        },
                                    },
                                    {
                                        'path' : '/*',
                                        'backend' : {
                                            'serviceName' : f"{construct_id}-{resname}",
                                            'servicePort' : restgport
                                        },
                                    }
                                ]
                            }
                        }
                    ]
                }
            }
            # deploy alb
            self.manif = eks.KubernetesManifest(
                self,
                f"{construct_id}Manifest",
                cluster=self.eksclust,
                manifest=[self.mydeploy, self.mysvc, self.myingress]
            )
        if reselb == 'nlb' or reselb == 'nlb-ip':
            # add annotations to service
            self.mysvc = {
                'apiVersion': 'v1',
                'kind': 'Service',
                'metadata': { 
                    'name': f"{construct_id}-{resname}",
                    'labels': appLabel,
                    'annotations': mysvcannot
                },
                'spec': {
                    'externalTrafficPolicy' : 'Cluster',
                    'type': "LoadBalancer",
                    'ports': [
                        {
                            'port': restgport,
                            'targetPort': restgport
                        }
                    ],
                    'selector': appLabel
                }
            }
            # deploy alb
            self.manif = eks.KubernetesManifest(
                self,
                f"{construct_id}Manifest",
                cluster=self.eksclust,
                manifest=[self.mydeploy, self.mysvc]
            )
            # show the ELB name
            # core.CfnOutput(
            #     self,
            #     f"{construct_id}:ALB DNS",
            #     value=self.eksclust.get_service_load_balancer_address(f"{construct_id}mysvc")
            # )



