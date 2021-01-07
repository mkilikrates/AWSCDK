import os
import json
from aws_cdk import (
    aws_ec2 as ec2,
    aws_autoscaling as asg,
    aws_elasticloadbalancingv2 as elb,
    aws_elasticloadbalancingv2_targets as lbtargets,
    aws_cloudwatch as cw,
    core,
)
account = os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"])
region = os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])
resconf = "resourcesmap.cfg"
with open(resconf) as resfile:
    resmap = json.load(resfile)
with open('zonemap.cfg') as zonefile:
    zonemap = json.load(zonefile)

class asgalbpublicv6(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, vpc = ec2.Vpc, bastionsg = ec2.SecurityGroup, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.vpc = vpc
        self.bastionsg = bastionsg
        # create security group for Auto Scale Group
        self.asgsg = ec2.SecurityGroup(
            self,
            "MyASGsg",
            allow_all_outbound=True,
            vpc=self.vpc
        )
        # add egress rule
        ec2.CfnSecurityGroupEgress(
            self,
            "ASGEgressAllIpv6",
            ip_protocol="-1",
            cidr_ipv6="::/0",
            group_id=self.asgsg.security_group_id
        )
        ec2.CfnSecurityGroupEgress(
            self,
            "ASGEgressAllIpv4",
            ip_protocol="-1",
            cidr_ip="0.0.0.0/0",
            group_id=self.asgsg.security_group_id
        )
        # add ingress rule
        self.asgsg.add_ingress_rule(
            bastionsg,
            ec2.Port.all_traffic()
        )
        # get config for resource
        res = 'nginx'
        ressize = resmap['Mappings']['Resources'][res]['SIZE']
        mykey = resmap['Mappings']['Resources'][res]['KEY'] + region
        usrdatafile = resmap['Mappings']['Resources'][res]['USRFILE']
        usrdata = open(usrdatafile, "r").read()
        # create Auto Scalling Group
        self.asg = asg.AutoScalingGroup(
            self,
            "MyASG",
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
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE),
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
        #create alb
        self.alb = elb.ApplicationLoadBalancer(
            self,
            "myALB",
            vpc=self.vpc,
            internet_facing=True,
            ip_address_type=elb.IpAddressType("DUAL_STACK"),
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC,one_per_az=True)
        )
        core.CfnOutput(
            self,
            "ALB DNS",
            value=self.alb.load_balancer_dns_name
        )
        # get config for resource
        res = 'alb'
        certarn = resmap['Mappings']['Resources'][res]['CERTARN']
        self.elblistnrs = self.alb.add_listener(
            "Listener_https",
            port=443,
            protocol=elb.ApplicationProtocol.HTTPS,
            certificate_arns=[certarn]
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
            'My Default Fleet',
            port=80,
            targets=[self.asg]
        )
        # create alarm for UnHealthyHostCount
        self.alarmtargrunhealth = self.tgrp.metric("UnHealthyHostCount")
        cw.Alarm(
            self,
            "UnHealthyHostCount",
            metric=self.alarmtargrunhealth,
            evaluation_periods=1,
            threshold=0,
            comparison_operator=cw.ComparisonOperator.GREATER_THAN_THRESHOLD
        )
class asgalbpublicv4(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, vpc = ec2.Vpc, bastionsg = ec2.SecurityGroup, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.vpc = vpc
        self.bastionsg = bastionsg
        # create security group for Auto Scale Group
        self.asgsg = ec2.SecurityGroup(
            self,
            "MyASGsg",
            allow_all_outbound=True,
            vpc=self.vpc
        )
        # add egress rule
        ec2.CfnSecurityGroupEgress(
            self,
            "ASGEgressAllIpv4",
            ip_protocol="-1",
            cidr_ip="0.0.0.0/0",
            group_id=self.asgsg.security_group_id
        )
        # add ingress rule
        self.asgsg.add_ingress_rule(
            bastionsg,
            ec2.Port.all_traffic()
        )
        # get config for resource
        res = 'nginx'
        ressize = resmap['Mappings']['Resources'][res]['SIZE']
        mykey = resmap['Mappings']['Resources'][res]['KEY'] + region
        usrdatafile = resmap['Mappings']['Resources'][res]['USRFILE']
        usrdata = open(usrdatafile, "r").read()
        # create Auto Scalling Group
        self.asg = asg.AutoScalingGroup(
            self,
            "MyASG",
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
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE),
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
        #create alb
        self.alb = elb.ApplicationLoadBalancer(
            self,
            "myALB",
            vpc=self.vpc,
            internet_facing=True,
            ip_address_type=elb.IpAddressType("IPV4"),
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC,one_per_az=True)
        )
        core.CfnOutput(
            self,
            "ALB DNS",
            value=self.alb.load_balancer_dns_name
        )
        # get config for resource
        res = 'alb'
        certarn = resmap['Mappings']['Resources'][res]['CERTARN']
        self.elblistnrs = self.alb.add_listener(
            "Listener_https",
            port=443,
            protocol=elb.ApplicationProtocol.HTTPS,
            certificate_arns=[certarn]
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
            'My Default Fleet',
            port=80,
            targets=[self.asg]
        )
        # create alarm for UnHealthyHostCount
        self.alarmtargrunhealth = self.tgrp.metric("UnHealthyHostCount")
        cw.Alarm(
            self,
            "UnHealthyHostCount",
            metric=self.alarmtargrunhealth,
            evaluation_periods=1,
            threshold=0,
            comparison_operator=cw.ComparisonOperator.GREATER_THAN_THRESHOLD
        )
