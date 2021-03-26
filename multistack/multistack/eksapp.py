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
    def __init__(self, scope: core.Construct, construct_id: str, res, preflst, allowall, ipstack, vpc = ec2.Vpc, allowsg = ec2.SecurityGroup, ekscluster = eks.Cluster, **kwargs) -> None:
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
        appLabel = { 'app': f"{construct_id}-{resname}"}
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
        # create security group for LB
        self.lbsg = ec2.SecurityGroup(
            self,
            f"{construct_id}MyLBsg",
            allow_all_outbound=True,
            vpc=self.vpc
        )
        # add egress rule
        ec2.CfnSecurityGroupEgress(
            self,
            f"{construct_id}EgressAllIpv4",
            ip_protocol="-1",
            cidr_ip="0.0.0.0/0",
            group_id=self.lbsg.security_group_id
        )
        if self.ipstack == 'Ipv6':
            ec2.CfnSecurityGroupEgress(
                self,
                f"{construct_id}EgressAllIpv6",
                ip_protocol="-1",
                cidr_ipv6="::/0",
                group_id=self.lbsg.security_group_id
            )
        # add ingress rule
        if self.allowsg != '':
            self.lbsg.add_ingress_rule(
                self.allowsg,
                ec2.Port.all_traffic()
            )
        if preflst == True:
            srcprefix = self.map.find_in_map(core.Aws.REGION, 'PREFIXLIST')
            self.lbsg.add_ingress_rule(
                ec2.Peer.prefix_list(srcprefix),
                ec2.Port.all_traffic()
            )
        if allowall == True:
            self.lbsg.add_ingress_rule(
                ec2.Peer.any_ipv4,
                ec2.Port.all_traffic()
            )
            if self.ipstack == 'Ipv6':
                self.lbsg.add_ingress_rule(
                    ec2.Peer.any_ipv6,
                    ec2.Port.all_traffic()
                )
        if type(allowall) == int or type(allowall) == float:
            self.lbsg.add_ingress_rule(
                ec2.Peer.any_ipv4(),
                ec2.Port.tcp(allowall)
            )
            if self.ipstack == 'Ipv6':
                self.lbsg.add_ingress_rule(
                    ec2.Peer.any_ipv6(),
                    ec2.Port.tcp(allowall)
                )
        mysvcannot = {}
        if reselb == 'alb':
            mysvcannot['kubernetes.io/ingress.class'] = 'alb'
            mysvcannot['alb.ingress.kubernetes.io/listen-ports'] = '[{"HTTP": 80}, {"HTTPS": ' + str(reslbport) + '}]'
            mysvcannot['alb.ingress.kubernetes.io/actions.ssl-redirect'] = '{"Type": "redirect", "RedirectConfig": { "Protocol": "HTTPS", "Port": "443", "StatusCode": "HTTP_301" } }'
            mysvcannot['alb.ingress.kubernetes.io/certificate-arn'] = self.cert.certificate_arn
            if elbface == True:
                mysvcannot['alb.ingress.kubernetes.io/scheme'] = 'internet-facing'
            if elbface == False:
                mysvcannot['alb.ingress.kubernetes.io/scheme'] = 'internal'
            if self.ipstack == 'Ipv6':
                mysvcannot['alb.ingress.kubernetes.io/ip-address-type'] = 'dualstack'
            else:
                mysvcannot['alb.ingress.kubernetes.io/ip-address-type'] = 'ipv4'
        ########################################### Works
        # define app chart
        self.manifest = MyChart.nginxs3(
                cdk8s.App(),
                f"chart-{resname}",
                clustername = self.eksclust.cluster_name,
                svcaccname = f"{construct_id}-{resname}-svcacc",
                svcannot = mysvcannot,
                res = res,
        )
        # apply chart
        self.chart = self.eksclust.add_cdk8s_chart(
            f"Manifest-{resname}",
            chart=self.manifest,
        )
        # core.CfnOutput(
        #     self,
        #     f"{construct_id}:ALB DNS",
        #     value=self.eksclust.get_service_load_balancer_address(f"{construct_id}mysvc")
        # )

        # # Define deployment
        # self.chartdeploy = MyChart.deployment(
        #     cdk8s.App(),
        #     f"{construct_id}-chartdeploy",
        #     svcaccname = f"{construct_id}-{resname}-svcacc",
        #     res = res,
        #     labels=appLabel
        # )
        # # Apply deployment
        # self.deployment = self.eksclust.add_cdk8s_chart(
        #     f"{construct_id}-deployment",
        #     chart=self.chartdeploy
        # )
        # # Define service
        # self.chartservice = MyChart.service(
        #     cdk8s.App(),
        #     f"{construct_id}-chartservice",
        #     res = res
        # )
        # # Apply deploserviceyment
        # self.service = self.eksclust.add_cdk8s_chart(
        #     f"{construct_id}-service",
        #     chart=self.chartservice
        # )
        # # Define ingress alb
        # self.chartingress = MyChart.ingress(
        #     cdk8s.App(),
        #     f"{construct_id}-chartingress",
        #     res = res
        # )
        # # Apply deploserviceyment
        # self.ingress = self.eksclust.add_cdk8s_chart(
        #     f"{construct_id}-ingress",
        #     chart=self.chartingress
        # )
        # myinit = {
        #     'initContainers': [
        #         {
        #             'name': f"{construct_id}s3cp",
        #             'image': 'amazon/aws-cli',
        #             'args' : [
        #                 's3',
        #                 'cp',
        #                 '--recursive',
        #                 f"s3://{ress3}/{ress3pfx}",
        #                 "/www/"
        #             ],
        #         }
        #     ],
        # }



        
            # create a deployment using serviceaccount and initContainers to copy content to be served
            # appLabel = { 'app': f"{construct_id}-{resname}"}
            # self.mydeploy = {
            #     'apiVersion': 'apps/v1',
            #     'kind': 'Deployment',
            #     'metadata': { 'name': f"{construct_id}-{resname}" },
            #     'spec': {
            #         'replicas': desircap,
            #         'selector': { 'matchLabels': appLabel },
            #         'template': {
            #             'metadata': { 'labels': appLabel },
            #             'spec':{
            #                 'serviceAccountName': self.mysvcacc.service_account_name,
            #                 'containers': [
            #                     {
            #                         'name': f"{construct_id}-{resname}",
            #                         'image': 'nginx',
            #                         'ports': [ { 'containerPort': restgport }],
            #                         'volumeMounts': [ { 'name': 'www', 'mountPath' : '/usr/share/nginx/html' } ]
            #                     }
            #                 ],
            #                 'initContainers': [
            #                     {
            #                         'name': f"{construct_id}s3cp",
            #                         'image': 'amazon/aws-cli',
            #                         'args' : [
            #                             's3',
            #                             'cp',
            #                             '--recursive',
            #                             f"s3://{self.bucketname}/images/",
            #                             "/www/"
            #                         ],
            #                         'volumeMounts': [ { 'name': 'www', 'mountPath' : '/www' } ]
            #                     }
            #                 ],
            #                 'volumes': [ { 'name': 'www', 'emptyDir': {} } ]
            #             }
            #         }
            #     }
            # }
            # output = yaml.dump(self.mydeploy)
            # print(output)
            # # add annotations to service
            # mysvcannot = {}
            # self.mysvc = {
            #     'apiVersion': 'v1',
            #     'kind': 'Service',
            #     'metadata': { 
            #         'name': f"{construct_id}mysvc",
            #         'annotations': mysvcannot
            #     },
            #     'spec': {
            #         'type': "LoadBalancer",
            #         'ports': [
            #             {
            #                 'port': reslbport,
            #                 'targetPort': restgport
            #             }
            #         ],
            #         'selector': appLabel
            #     }
            # }
            # output = yaml.dump(self.mysvc)
            # print(output)

            # if ressubgrp == 'Private':
            #     mysvcannot['service.beta.kubernetes.io/aws-load-balancer-internal'] = 'true'
            # if reselb == 'clb':
            #     mysvcannot['service.beta.kubernetes.io/aws-load-balancer-ssl-cert'] = self.cert.certificate_arn
            #     mysvcannot['service.beta.kubernetes.io/aws-load-balancer-backend-protocol'] = 'http'
            # if reselb == 'alb':
            #     mysvcannot['kubernetes.io/ingress.class'] = 'alb'
            #     if elbface == True:
            #         mysvcannot['alb.ingress.kubernetes.io/scheme'] = 'internet-facing'
            #     if elbface == False:
            #         mysvcannot['alb.ingress.kubernetes.io/scheme'] = 'internal'
            #     mysublist = self.vpc.select_subnets(subnet_group_name=ressubgrp,one_per_az=True).subnet_ids
            #     mysubstrlist = ', '.join(['"{}"'.format(value) for value in mysublist])
            #     #mysvcannot['alb.ingress.kubernetes.io/subnets'] = mysubstrlist
                # mysvcannot['alb.ingress.kubernetes.io/security-groups'] = self.lbsg.security_group_id
                # if self.vpc.stack == 'Ipv6':
                #     mysvcannot['alb.ingress.kubernetes.io/ip-address-type'] = 'dualstack'
                # else:
                #     mysvcannot['alb.ingress.kubernetes.io/ip-address-type'] = 'ipv4'
                # mysvcannot['alb.ingress.kubernetes.io/listen-ports'] = '[{"HTTP": 80}, {"HTTPS": ' + str(reslbport) + '}]'
                # mysvcannot['alb.ingress.kubernetes.io/target-type'] = 'ip'
                # mysvcannot['alb.ingress.kubernetes.io/backend-protocol-version'] = 'HTTP2'
                # mysvcannot['alb.ingress.kubernetes.io/actions.ssl-redirect'] = '{"Type": "redirect", "RedirectConfig": { "Protocol": "HTTPS", "Port": "443", "StatusCode": "HTTP_301" } }'
                # mysvcannot['alb.ingress.kubernetes.io/certificate-arn'] = self.cert.certificate_arn
                # self.myingress = {
                #     'apiVersion': 'extensions/v1beta1',
                #     'kind': 'Ingress',
                #     'metadata': { 
                #         'name': f"{construct_id}mysvc",
                #         'labels': appLabel,
                #         'annotations': mysvcannot
                #     },
                #     'spec': {
                #         'rules': [
                #             {
                #                 'http': {
                #                     'paths' : [
                #                         {
                #                             'path' : '/*',
                #                             'backend' : {
                #                                 'serviceName' : f"{construct_id}mysvc",
                #                                 'servicePort' : restgport
                #                             },
                #                         }
                #                     ]
                #                 }
                #             }
                #         ]
                #     }
                # }
                # output = yaml.dump(self.myingress)
                # print(output)
                
                # https://docs.aws.amazon.com/cdk/api/latest/python/aws_cdk.aws_eks/README.html
                
            # deploy 
            # self.manif = eks.KubernetesManifest(
            #     self,
            #     f"{construct_id}Manifest",
            #     cluster=self.eksclust,
            #     manifest=[self.mydeploy, self.mysvc, self.myingress]
            # )
            # show the ELB name
            # core.CfnOutput(
            #     self,
            #     f"{construct_id}:ALB DNS",
            #     value=self.eksclust.get_service_load_balancer_address(f"{construct_id}mysvc")
            # )



