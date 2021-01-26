import os
import json
from aws_cdk import (
    aws_ec2 as ec2,
    aws_autoscaling as asg,
    aws_elasticloadbalancingv2 as elb,
    aws_elasticloadbalancingv2_targets as lbtargets,
    aws_cloudwatch as cw,
    aws_certificatemanager as acm,
    aws_route53 as r53,
    aws_route53_targets as r53tgs,
    core,
)
account = os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"])
region = os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])
resconf = "resourcesmap.cfg"
with open(resconf) as resfile:
    resmap = json.load(resfile)
with open('zonemap.cfg') as zonefile:
    zonemap = json.load(zonefile)
class asglb(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, vpc = ec2.Vpc, bastionsg = ec2.SecurityGroup, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.vpc = vpc
        self.bastionsg = bastionsg
        # get config for resource
        res = 'nginxfe'
        ressubgrp = resmap['Mappings']['Resources'][res]['SUBNETGRP']
        ressize = resmap['Mappings']['Resources'][res]['SIZE']
        mykey = resmap['Mappings']['Resources'][res]['KEY'] + region
        usrdatafile = resmap['Mappings']['Resources'][res]['USRFILE']
        usrdata = open(usrdatafile, "r").read()
        # create security group for Auto Scale Group
        self.asgsg = ec2.SecurityGroup(
            self,
            f"{construct_id}:MyASGsg",
            allow_all_outbound=True,
            vpc=self.vpc
        )
        # add egress rule
        if self.vpc.stack == 'Ipv6':
            ec2.CfnSecurityGroupEgress(
                self,
                f"{construct_id}:ASGEgressAllIpv6",
                ip_protocol="-1",
                cidr_ipv6="::/0",
                group_id=self.asgsg.security_group_id
            )
        else:
            ec2.CfnSecurityGroupEgress(
                self,
                f"{construct_id}:ASGEgressAllIpv4",
                ip_protocol="-1",
                cidr_ip="0.0.0.0/0",
                group_id=self.asgsg.security_group_id
            )
        # add ingress rule
        self.asgsg.add_ingress_rule(
            bastionsg,
            ec2.Port.all_traffic()
        )
        # create Auto Scalling Group
        self.asg = asg.AutoScalingGroup(
            self,
            f"{construct_id}:MyASG",
            instance_type=ec2.InstanceType(ressize),
            machine_image=ec2.AmazonLinuxImage(
                user_data=ec2.UserData.custom(usrdata),
                edition=ec2.AmazonLinuxEdition.STANDARD,
                generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2
            ),
            vpc=self.vpc,
            security_group=self.asgsg,
            key_name=mykey,
            desired_capacity=2,
            min_capacity=0,
            max_capacity=2,
            vpc_subnets=ec2.SubnetSelection(subnet_group_name=ressubgrp,one_per_az=True),
        )
        self.asg.scale_on_schedule(
            "PrescaleInTheMorning",
            schedule=asg.Schedule.cron(hour="9", minute="0"),
            desired_capacity=2
        )
        self.asg.scale_on_schedule(
            "AllowDownscalingAtNight",
            schedule=asg.Schedule.cron(hour="20", minute="0"),
            desired_capacity=0
        )
        # get config for resource
        res = 'albfe'
        appname = resmap['Mappings']['Resources'][res]['NAME']
        appdomain = resmap['Mappings']['Resources'][res]['DOMAIN']
        albface = resmap['Mappings']['Resources'][res]['INTERNET']
        ressubgrp = resmap['Mappings']['Resources'][res]['SUBNETGRP']
        #create alb
        if albface == 'True':
            if self.vpc.stack == 'Ipv6':
                lbstack = elb.IpAddressType.DUAL_STACK
                ec2.CfnSecurityGroupIngress(
                    self,
                    f"{construct_id}:ASGIngresshttpsIpv6",
                    ip_protocol="6",
                    cidr_ipv6="::/0",
                    from_port=443,
                    to_port=443,
                    group_id=self.asgsg.security_group_id
                )
            else:
                lbstack = elb.IpAddressType.IPV4
        ec2.CfnSecurityGroupIngress(
            self,
            f"{construct_id}:ASGIngresshttpsIpv4",
            ip_protocol="6",
            cidr_ip="0.0.0.0/0",
            from_port=443,
            to_port=443,
            group_id=self.asgsg.security_group_id
        )
        self.alb = elb.ApplicationLoadBalancer(
            self,
            f"{construct_id}:myALB",
            vpc=self.vpc,
            internet_facing=True,
            ip_address_type=(lbstack),
            vpc_subnets=ec2.SubnetSelection(subnet_group_name=ressubgrp,one_per_az=True),
        )
        core.CfnOutput(
            self,
            f"{construct_id}:ALB DNS",
            value=self.alb.load_balancer_dns_name
        )
        # get hosted zone id
        self.hz = r53.HostedZone.from_lookup(
            self,
            f"{construct_id}:Domain",
            domain_name=appdomain,
            private_zone=False
        )
        r53.ARecord(
            self,
            f"{construct_id}:fqdn",
            zone=self.hz,
            record_name=f"{appname}.{appdomain}",
            target=r53.RecordTarget.from_alias(r53tgs.LoadBalancerTarget(self.alb))
        )
        # generate public certificate
        self.cert = acm.Certificate(
            self,
            f"{construct_id}:Certificate",
            domain_name=f"{appname}.{appdomain}",
            validation=acm.CertificateValidation.from_dns(self.hz)
        )
        # configure listener
        self.elblistnrs = self.alb.add_listener(
            f"{construct_id}:Listener_https",
            port=443,
            protocol=elb.ApplicationProtocol.HTTPS,
            certificate_arns=[self.cert.certificate_arn]
        )
        #redir http traffic to https
        self.alb.add_redirect(
            source_port=80,
            source_protocol=elb.ApplicationProtocol.HTTP,
            target_port=443,
            target_protocol=elb.ApplicationProtocol.HTTPS
        )
        # allow access
        self.elblistnrs.connections.allow_from(
            self.alb,
            ec2.Port.tcp(443)
        )
        self.elblistnrs.connections.allow_default_port_from(
            other=ec2.Peer.any_ipv6(),
            description="Allow from anyone on port 443"
        )
        self.tgrp = self.elblistnrs.add_targets(
            f"{construct_id}:My Default Fleet",
            port=80,
            targets=[self.asg]
        )
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
