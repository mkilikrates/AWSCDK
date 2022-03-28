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
    def __init__(self, scope: core.Construct, construct_id: str, res, preflst, allowall, ipstack, tgrtip, domain, certif, vpc = ec2.Vpc, allowsg = ec2.SecurityGroup, tgrt = asg.AutoScalingGroup, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.vpc = vpc
        self.ipstack = ipstack
        allowsg = allowsg
        tgrt = tgrt
        # get config for resource
        res = res
        if 'NAME' in resmap['Mappings']['Resources'][res]:
            resname = resmap['Mappings']['Resources'][res]['NAME']
        else:
            resname = None
        if 'APPDOMAIN' in resmap['Mappings']['Resources'][res]:
            appdomain = resmap['Mappings']['Resources'][res]['APPDOMAIN']
            self.hz = r53.HostedZone.from_lookup(
                self,
                f"{construct_id}:Domain",
                domain_name=appdomain,
                private_zone=False
            )
        else:
            appdomain = None
        if 'URL' in resmap['Mappings']['Resources'][res]:
            appurl = resmap['Mappings']['Resources'][res]['URL']
        else:
            appurl = None
        if 'INTERNET' in resmap['Mappings']['Resources'][res]:
            elbface = resmap['Mappings']['Resources'][res]['INTERNET']
            if  elbface == True:
                if self.ipstack == 'Ipv6':
                    lbstack = elb.IpAddressType.DUAL_STACK
                else:
                    lbstack = elb.IpAddressType.IPV4
            else:
                lbstack = elb.IpAddressType.IPV4
        else:
            lbstack = elb.IpAddressType.IPV4
        if 'SUBNETGRP' in resmap['Mappings']['Resources'][res]:
            ressubgrp = ec2.SubnetSelection(subnet_group_name=resmap['Mappings']['Resources'][res]['SUBNETGRP'],one_per_az=True)
        else:
            ressubgrp = None
        if 'Type' in resmap['Mappings']['Resources'][res]:
            restype = resmap['Mappings']['Resources'][res]['Type']
        else:
            restype = 'alb'
        if 'CROSSAZ' in resmap['Mappings']['Resources'][res]:
            rescrossaz = resmap['Mappings']['Resources'][res]['CROSSAZ']
        else:
            rescrossaz = None
        if 'LBPORT' in resmap['Mappings']['Resources'][res]:
            reslbport = resmap['Mappings']['Resources'][res]['LBPORT']
        else:
            reslbport = None
        if 'TGPORT' in resmap['Mappings']['Resources'][res]:
            restgport = resmap['Mappings']['Resources'][res]['TGPORT']
        else:
            restgport = None
        if 'Idle' in resmap['Mappings']['Resources'][res]:
            residle = resmap['Mappings']['Resources'][res]['Idle']
        else:
            residle = None
        if 'MONITOR' in resmap['Mappings']['Resources'][res]:
            resmon = resmap['Mappings']['Resources'][res]['MONITOR']
        else:
            resmon = False
        if 'CLIPRESIP' in resmap['Mappings']['Resources'][res]:
            lbpresip = resmap['Mappings']['Resources'][res]['CLIPRESIP']
        else:
            lbpresip = False
        if 'SSL' in resmap['Mappings']['Resources'][res]:
            appssl = resmap['Mappings']['Resources'][res]['SSL']
        else:
            appssl = False
        if 'HTTP2' in resmap['Mappings']['Resources'][res]:
            http2 = resmap['Mappings']['Resources'][res]['HTTP2']
        else:
            http2 = False
        # check for ssl certificate
        if 'CERTARN' in resmap['Mappings']['Resources'][res]:
            certificates = []
            for cert in resmap['Mappings']['Resources'][res]['CERTARN']:
                certificates.append(elb.ListenerCertificate.from_arn(cert))
        elif certif != []:
            certificates = []
            for cert in certif:
                certificates.append(elb.ListenerCertificate.from_arn(cert))
        if restype == 'clb':
            # create security group for LB
            self.lbsg = ec2.SecurityGroup(
                self,
                f"{construct_id}:MyLBsg",
                allow_all_outbound=True,
                vpc=self.vpc
            )
            # configure listener
            self.elblistnrs = clb.LoadBalancerListener(
                external_port=reslbport,
                internal_port=restgport
            )
            self.elb = clb.LoadBalancer(
                self,
                f"{construct_id}-CLB",
                vpc=self.vpc,
                cross_zone=rescrossaz,
                subnet_selection=ressubgrp,
                internet_facing=elbface,
                listeners=self.elblistnrs
            )
            core.CfnOutput(
                self,
                f"{construct_id}:ALB DNS",
                value=self.elb.load_balancer_dns_name
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
                ip_address_type=lbstack,
                vpc_subnets=ressubgrp,
                security_group=self.lbsg,
                http2_enabled=http2,
                idle_timeout=residle,
                load_balancer_name=resname
            )
            core.CfnOutput(
                self,
                f"{construct_id}:ALB DNS",
                value=self.elb.load_balancer_dns_name
            )
            # configure listener
            if reslbport != None:
                if reslbport == 443:
                    self.elblistnrs = elb.ApplicationListener(
                        self,
                        f"{construct_id}:Listener_https",
                        load_balancer=self.elb,
                        port=reslbport,
                        protocol=elb.ApplicationProtocol.HTTPS,
                        certificates=certificates,
                    )
                    #redir http traffic to https
                    self.elb.add_redirect(
                        source_port=80,
                        source_protocol=elb.ApplicationProtocol.HTTP,
                        target_port=reslbport,
                        target_protocol=elb.ApplicationProtocol.HTTPS
                    )
                if type(reslbport) == list:
                    for each in reslbport:
                        if each == 443:
                            self.elblistnrs = elb.ApplicationListener(
                                self,
                                f"{construct_id}:Listener_https",
                                load_balancer=self.elb,
                                port=each,
                                protocol=elb.ApplicationProtocol.HTTPS,
                                certificates=certificates,
                            )
                            #redir http traffic to https
                            self.elb.add_redirect(
                                source_port=80,
                                source_protocol=elb.ApplicationProtocol.HTTP,
                                target_port=reslbport,
                                target_protocol=elb.ApplicationProtocol.HTTPS
                            )
                else:
                    self.elblistnrs = elb.ApplicationListener(
                        f"{construct_id}:Listener_http",
                        load_balancer=self.elb,
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
            if tgrt != '':
                self.tgrp = elb.ApplicationTargetGroup(
                    self,
                    f"{construct_id}TargetGroup",
                    target_type=elb.TargetType.INSTANCE,
                    vpc=self.vpc,
                    port=restgport,
                    targets=[tgrt]
                )
                self.elblistnrs.add_target_groups(
                    f"{construct_id}:My Default Fleet",
                    target_groups=[self.tgrp]
                )

            if tgrtip != '':
                self.tgrp = elb.ApplicationTargetGroup(
                    self,
                    f"{construct_id}TargetGroup",
                    target_type=elb.TargetType.IP,
                    vpc=self.vpc,
                    port=restgport,
                )
                for tgip in tgrtip:
                    self.tgrp.add_target(lbtargets.IpTarget(ip_address=tgip,availability_zone="all"))
                self.elblistnrs.add_targets(
                    f"{construct_id}:My Default Fleet",
                    port=restgport,
                    targets=self.tgrp
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
            # allow egress access to target
            if tgrt != '':
                # configure listener
                if type(reslbport) == str:
                    if reslbport == 443:
                        self.elblistnrs = elb.NetworkListener(
                            f"{construct_id}:Listener_https",
                            load_balancer=self.elb,
                            port=reslbport,
                            protocol=elb.Protocol('TLS'),
                            certificates=certificates
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
                        self.elblistnrs = elb.NetworkListener(
                            f"{construct_id}:Listener",
                            load_balancer=self.elb,
                            port=reslbport,
                            protocol=protocol,
                        )
                    self.tgrp = self.elblistnrs.add_targets(
                        f"{construct_id}:My Default Fleet",
                        port=restgport,
                        targets=[tgrt]
                    )

                if type(reslbport) == list:
                    index = 0
                    while index < (len(reslbport)):
                        if reslbport[index] == 443:
                            elb.NetworkListener(
                                self,
                                f"{construct_id}:Listener_https",
                                load_balancer=self.elb,
                                port=reslbport[index],
                                protocol=elb.Protocol('TLS'),
                                certificates=certificates,
                                default_target_groups=elb.NetworkTargetGroup(
                                    self,
                                    f"{construct_id}:My Default Fleet{index}",
                                    port=restgport[index],
                                    targets=[tgrt],
                                    vpc=self.vpc
                                )
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
                            elb.NetworkListener(
                                self,
                                f"{construct_id}:Listener{index}",
                                load_balancer=self.elb,
                                port=reslbport[index],
                                protocol=protocol,
                                certificates=None,
                                default_action=None,
                                ssl_policy=None,
                                alpn_policy=None,
                                default_target_groups=[elb.NetworkTargetGroup(
                                    self,
                                    f"{construct_id}:My Default Fleet{index}",
                                    port=restgport[index],
                                    preserve_client_ip=lbpresip,
                                    protocol=protocol,
                                    targets=[tgrt],
                                    vpc=self.vpc
                                )]
                            )
                        index = index + 1
                if 'HC' in resmap['Mappings']['Resources'][res]:
                    hc = resmap['Mappings']['Resources'][res]['HC']
                else:
                    hc = False
                if 'HCPORT' in resmap['Mappings']['Resources'][res]:
                    hcport = resmap['Mappings']['Resources'][res]['HCPORT']
                else:
                    hcport = 'traffic-port'
                if 'HCPROTO' in resmap['Mappings']['Resources'][res]:
                    hcproto = resmap['Mappings']['Resources'][res]['HCPROTO']
                    if hcproto == 'TCP':
                        hcproto = elb.Protocol.TCP
                    elif hcproto == 'UDP':
                        hcproto = elb.Protocol.UDP
                    elif hcproto == 'TCP_UDP':
                        hcproto = elb.Protocol.TCP_UDP
                    elif hcproto == 'HTTP':
                        hcproto = elb.Protocol.HTTP
                    elif hcproto == 'HTTPS':
                        hcproto = elb.Protocol.HTTPS
                    elif hcproto == 'TLS':
                        hcproto = elb.Protocol.TLS
                    if resmap['Mappings']['Resources'][res]['HCPROTO'] == 'HTTP' or resmap['Mappings']['Resources'][res]['HCPROTO'] == 'HTTPS':
                        if 'HCPath' in resmap['Mappings']['Resources'][res]:
                            hcpath = resmap['Mappings']['Resources'][res]['HCPath']
                        else:
                            hcpath = '/'
                else:
                    hcpath = None
                    hcproto = None
                if 'HCGRPC' in resmap['Mappings']['Resources'][res]:
                    hcgrpc = resmap['Mappings']['Resources'][res]['HCGRPC']
                else:
                    hcgrpc = None
                if 'HCHTTP' in resmap['Mappings']['Resources'][res]:
                    hchttp = resmap['Mappings']['Resources'][res]['HCHTTP']
                else:
                    hchttp = None
                if 'HCCount' in resmap['Mappings']['Resources'][res]:
                    hccount = resmap['Mappings']['Resources'][res]['HCCount']
                else:
                    hccount = 3
                if 'HCUnCount' in resmap['Mappings']['Resources'][res]:
                    hcuncount = resmap['Mappings']['Resources'][res]['HCUnCount']
                else:
                    hcuncount = 3
                if 'HCInt' in resmap['Mappings']['Resources'][res]:
                    hcint = core.Duration.seconds(resmap['Mappings']['Resources'][res]['HCInt'])
                else:
                    hcint = core.Duration.seconds(30)
                if 'HCtmt' in resmap['Mappings']['Resources'][res]:
                    hctmt = core.Duration.seconds(resmap['Mappings']['Resources'][res]['HCtmt'])
                else:
                    hctmt = core.Duration.seconds(10)
                if hc == True:
                    self.tgrp.configure_health_check(
                        enabled=hc,
                        port=str(hcport),
                        protocol=hcproto,
                        healthy_grpc_codes=hcgrpc,
                        healthy_http_codes=hchttp,
                        healthy_threshold_count=hccount,
                        unhealthy_threshold_count=hcuncount,
                        interval=hcint,
                        path=hcpath,
                        timeout=hctmt
                    )
            if tgrtip != '':
                self.tgrp = elb.NetworkTargetGroup(
                    self,
                    f"{construct_id}TargetGroup",
                    target_type=elb.TargetType.IP,
                    vpc=self.vpc,
                    port=restgport,
                    preserve_client_ip=lbpresip
                )
                for tgip in tgrtip:
                    self.tgrp.add_target(lbtargets.IpTarget(ip_address=tgip,availability_zone="all"))
                # configure listener
                if reslbport == 443:
                    self.elblistnrs = elb.NetworkListener(
                        self,
                        f"{construct_id}:Listener_https",
                        load_balancer=self.elb,
                        port=reslbport,
                        protocol=elb.Protocol.TLS,
                        certificates=certificates,
                        default_target_groups=[self.tgrp]
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
                    self.elblistnrs = elb.NetworkListener(
                        f"{construct_id}:Listener",
                        load_balancer=self.elb,
                        port=reslbport,
                        protocol=protocol,
                        default_target_groups=[self.tgrp]
                    )

            if 'Principals' in resmap['Mappings']['Resources'][res]:
                resprinc = resmap['Mappings']['Resources'][res]['Principals']
                if type(resprinc) == str:
                    principal = []
                    principal.append(iam.ArnPrincipal(resprinc))
                if type(resprinc) == list:
                    principal = []
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
                if appdomain != None and appurl != None:
                    self.vpcendpointsrvdns = r53.VpcEndpointServiceDomainName(
                        self,
                        f"{construct_id}:VPCEndpointServiceDomain",
                        domain_name=f"{appurl}",
                        endpoint_service=self.vpcendpointsrv,
                        public_hosted_zone=self.hz
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
        if domain != '':
            self.hz = domain
        if appdomain != None and appurl != None:
            # create alias record target elb
            r53.ARecord(
                self,
                f"{construct_id}:fqdn",
                zone=self.hz,
                record_name=f"{appurl}",
                target=r53.RecordTarget.from_alias(r53tgs.LoadBalancerTarget(self.elb))
            )
            self.elbdns = core.CfnOutput(
                self,
                f"{construct_id}:APP DNS",
                value=f"{appurl}"
            )
