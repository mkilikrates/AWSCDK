import os
import json
from aws_cdk import (
    aws_ec2 as ec2,
    aws_autoscaling as asg,
    aws_elasticloadbalancing as clb,
    aws_elasticloadbalancingv2 as elb,
    aws_elasticloadbalancingv2_targets as lbtargets,
    aws_cloudwatch as cw,
    aws_certificatemanager as acm,
    aws_route53 as r53,
    aws_route53_targets as r53tgs,
    aws_iam as iam,
    core,
)
account = os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"])
region = os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])
resconf = "resourcesmap.cfg"
with open(resconf) as resfile:
    resmap = json.load(resfile)
with open('zonemap.cfg') as zonefile:
    zonemap = json.load(zonefile)
class alb(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, res, preflst, allowall, ipstack, vpc = ec2.Vpc, allowsg = ec2.SecurityGroup, tgrt = asg.AutoScalingGroup, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.vpc = vpc
        self.ipstack = ipstack
        allowsg = allowsg
        tgrt = tgrt
        # get config for resource
        res = res
        appname = resmap['Mappings']['Resources'][res]['NAME']
        elbface = resmap['Mappings']['Resources'][res]['INTERNET']
        ressubgrp = resmap['Mappings']['Resources'][res]['SUBNETGRP']
        restype = resmap['Mappings']['Resources'][res]['Type']
        rescrossaz = resmap['Mappings']['Resources'][res]['CROSSAZ']
        reslbport = resmap['Mappings']['Resources'][res]['LBPORT']
        restgport = resmap['Mappings']['Resources'][res]['TGPORT']
        resmon = resmap['Mappings']['Resources'][res]['MONITOR']
        if 'DOMAIN' in resmap['Mappings']['Resources'][res]:
            appdomain = resmap['Mappings']['Resources'][res]['DOMAIN']
            # get hosted zone id
            self.hz = r53.HostedZone.from_lookup(
                self,
                f"{construct_id}:Domain",
                domain_name=appdomain,
                private_zone=False
            )
            # generate public certificate
            if reslbport == 443:
                self.cert = acm.Certificate(
                    self,
                    f"{construct_id}:Certificate",
                    domain_name=f"{appname}.{appdomain}",
                    validation=acm.CertificateValidation.from_dns(self.hz)
                )
        else:
            appdomain = ''
        if elbface == True:
            if self.ipstack == 'Ipv6':
                lbstack = elb.IpAddressType.DUAL_STACK
            else:
                lbstack = elb.IpAddressType.IPV4
        else:
            lbstack = elb.IpAddressType.IPV4
        if restype == 'clb':
            # create security group for LB
            self.lbsg = ec2.SecurityGroup(
                self,
                f"{construct_id}:MyLBsg",
                allow_all_outbound=True,
                vpc=self.vpc
            )
            self.elb = clb.LoadBalancer(
                self,
                f"{construct_id}-CLB",
                vpc=self.vpc,
                cross_zone=rescrossaz,
                subnet_selection=ec2.SubnetSelection(subnet_group_name=ressubgrp,one_per_az=True),
                internet_facing=elbface
            )
            core.CfnOutput(
                self,
                f"{construct_id}:ALB DNS",
                value=self.elb.load_balancer_dns_name
            )
            # configure listener
            self.elblistnrs = self.elb.add_listener(
                external_port=reslbport,
                internal_port=restgport
            )
            # need to fix this part
            # self.tgrp = self.elb.add_target(
            #     target=tgrt
            # )

        if restype == 'alb':
            # create security group for LB
            self.lbsg = ec2.SecurityGroup(
                self,
                f"{construct_id}:MyLBsg",
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
            #create alb
            self.elb = elb.ApplicationLoadBalancer(
                self,
                f"{construct_id}-ALB",
                vpc=self.vpc,
                internet_facing=elbface,
                ip_address_type=(lbstack),
                vpc_subnets=ec2.SubnetSelection(subnet_group_name=ressubgrp,one_per_az=True),
                security_group=self.lbsg
            )
            core.CfnOutput(
                self,
                f"{construct_id}:ALB DNS",
                value=self.elb.load_balancer_dns_name
            )
            # configure listener
            if reslbport == 443:
                self.elblistnrs = self.elb.add_listener(
                    f"{construct_id}:Listener_https",
                    port=reslbport,
                    protocol=elb.ApplicationProtocol.HTTPS,
                    certificate_arns=[self.cert.certificate_arn]
                )
                #redir http traffic to https
                self.elb.add_redirect(
                    source_port=80,
                    source_protocol=elb.ApplicationProtocol.HTTP,
                    target_port=reslbport,
                    target_protocol=elb.ApplicationProtocol.HTTPS
                )
            else:
                self.elblistnrs = self.elb.add_listener(
                    f"{construct_id}:Listener_http",
                    port=reslbport,
                    protocol=elb.ApplicationProtocol.HTTP
                )
            # allow ingress access 
            if allowall == True:
                self.elblistnrs.connections.allow_default_port_from(
                other=ec2.Peer.any_ipv4(),
                description="Allow from anyone on LB port"
                )
                if self.ipstack == 'Ipv6':
                    self.elblistnrs.connections.allow_default_port_from(
                        other=ec2.Peer.any_ipv6(),
                        description="Allow from anyone on LB port"
                    )
            if preflst == True:
                # get prefix list from file to allow traffic from the office
                srcprefix = zonemap['Mappings']['RegionMap'][region]['PREFIXLIST']        
                self.elblistnrs.connections.allow_default_port_from(
                    other=ec2.Peer.prefix_list(srcprefix),
                    description="Allow from prefix list on LB port"
                )
            # allow egress access to target
            self.tgrp = self.elblistnrs.add_targets(
                f"{construct_id}:My Default Fleet",
                port=restgport,
                targets=[tgrt]
            )
            if resmon == True:
                # create alarm for UnHealthyHostCount
                self.alarmtargrunhealth = self.tgrp.metric("UnHealthyHostCount")
                cw.Alarm(
                    self,
                    f"{construct_id}:UnHealthyHostCount",
                    metric=self.alarmtargrunhealth,
                    evaluation_periods=1,
                    threshold=0,
                    comparison_operator=cw.ComparisonOperator.GREATER_THAN_THRESHOLD
                )
        if restype == 'nlb':
            #create nlb
            self.elb = elb.NetworkLoadBalancer(
                self,
                f"{construct_id}-NLB",
                cross_zone_enabled=rescrossaz,
                vpc=self.vpc,
                internet_facing=elbface,
                deletion_protection=False,
                load_balancer_name=f"{construct_id}-NLB",
                vpc_subnets=ec2.SubnetSelection(subnet_group_name=ressubgrp,one_per_az=True)
            )
            core.CfnOutput(
                self,
                f"{construct_id}:NLB DNS",
                value=self.elb.load_balancer_dns_name
            )
            # configure listener
            if reslbport == 443:
                self.elblistnrs = self.elb.add_listener(
                    f"{construct_id}:Listener_https",
                    port=reslbport,
                    protocol=elb.Protocol('TLS'),
                    certificates=[elb.ListenerCertificate(self.cert.certificate_arn)]
                )
            else:
                if 'PROTO' in resmap['Mappings']['Resources'][res]:
                    proto = resmap['Mappings']['Resources'][res]['PROTO']
                    if proto == 'TCP':
                        protocol = elb.Protocol('TCP')
                    elif proto == 'UDP':
                        protocol = elb.Protocol('UDP')
                else:
                    protocol = elb.Protocol('TCP')
                self.elblistnrs = self.elb.add_listener(
                    f"{construct_id}:Listener",
                    port=reslbport,
                    protocol=protocol,
                )
            # allow egress access to target
            self.tgrp = self.elblistnrs.add_targets(
                f"{construct_id}:My Default Fleet",
                port=restgport,
                targets=[tgrt]
            )
            if 'Principals' in resmap['Mappings']['Resources'][res]:
                resprinc = resmap['Mappings']['Resources'][res]['Principals']
                if type(resprinc) == str:
                    principal = []
                    principal.append(iam.ArnPrincipal(resprinc))
                if type(resprinc) == list:
                    for each in resprinc:
                        principal.append(iam.ArnPrincipal(each))
                if 'AUTOACCEPT' in resmap['Mappings']['Resources'][res]:
                    resaccept = resmap['Mappings']['Resources'][res]['AUTOACCEPT']
                else:
                    resaccept = True
                self.vpcendpointsrv = ec2.VpcEndpointService(
                    self,
                    f"{construct_id}:VPCEndpointService",
                    vpc_endpoint_service_load_balancers=[self.elb],
                    acceptance_required=resaccept,
                    allowed_principals=principal
                )
                core.CfnOutput(
                    self,
                    f"{construct_id}:VPCEndpointServiceName",
                    value=self.vpcendpointsrv.vpc_endpoint_service_name
                )
            if resmon == True:
                # create alarm for UnHealthyHostCount
                self.alarmtargrunhealth = self.tgrp.metric_un_healthy_host_count()
                cw.Alarm(
                    self,
                    f"{construct_id}:UnHealthyHostCount",
                    metric=self.alarmtargrunhealth,
                    evaluation_periods=1,
                    threshold=0,
                    comparison_operator=cw.ComparisonOperator.GREATER_THAN_THRESHOLD
                )
        if appdomain != '':
            # create alias record target elb
            r53.ARecord(
                self,
                f"{construct_id}:fqdn",
                zone=self.hz,
                record_name=f"{appname}.{appdomain}",
                target=r53.RecordTarget.from_alias(r53tgs.LoadBalancerTarget(self.elb))
            )
            core.CfnOutput(
                self,
                f"{construct_id}:APP DNS",
                value=f"{appname}.{appdomain}"
            )
