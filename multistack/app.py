#!/usr/bin/env python3
import os
from aws_cdk import core
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_ssm as ssm
from aws_cdk.aws_cloudfront import Distribution, FailoverStatusCode
from multistack.vpc_empty import VPC as VPC
from multistack.bastion import BastionStack as bastion
from multistack.vpcflow import flowlogs
from multistack.vpcendpoints import VPCEStack as vpce
from multistack.tgw_vgw import mygw
from multistack.asg import main as asg
from multistack.elb import alb
from multistack.rds import myrds as rds
from multistack.vpn import cvpn, s2svpn
from multistack.ec2_eip import EIP as eip
from multistack.decodevpn import S2SVPNS3 as vpns3
from multistack.ds import myds
from multistack.r53res import rslv
from multistack.eks import EksStack as eks
from multistack.ecs import EcsStack as ecs
from multistack.sns import main as sns
from multistack.elasticache import main as ecache
from multistack.opensearch import main as search
from multistack.efs import main as efs
from multistack.eksapp import (
    MyAppStack as eksapp,
    AppStack as simpleapp
    )
from multistack.netfw import internetfw as netfw
from multistack.ec2 import InstanceStack as instance
from multistack.eksctrl import (
    eksDNSHelm as eksdns,
    ELBCont as ekselb,
    ekscwinsights as eksinsights,
    eksNGINXMNF as eksnginx
    )
from multistack.cloudfront import CloudFrontStack as cf
from multistack.servicediscovery import ServiceDiscovery as sd
region = os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])
remoteregion = 'eu-west-1'
account = os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"])
myenv = core.Environment(account = os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"]), region = os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"]))
myenv2 = core.Environment(account = os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"]), region = remoteregion)
route = 'bgp'
gwtype = 'tgw'
ipstack = 'Ipv4'
app = core.App()


# env 1
VPCStack = VPC(app, "MYVPC", env=myenv, res = 'vpc', cidrid = 0, natgw = 3, maxaz = 3, ipstack = ipstack)
#ECStack = ecs(app, "WORDPRESS", env=myenv, res = 'ecsbe', preflst = False, allowsg = '', allowall = True, ipstack = ipstack, srvdisc = '', vpc = VPCStack.vpc)
#RDSStack = rds(app, "DB", env=myenv, res = 'rdsauroramysqlsservlesscl', preflst = True, allowall = False, ipstack = ipstack, vpc = VPCStack.vpc, allowsg = ECStack.ecssg)
#RDSStack.add_dependency(target=VPCStack)
ECacheStack = ecache(app, "wpmemcache", env=myenv, res = 'memcachet3micromultiaz', preflst = False, allowsg = '', allowall = True, ipstack = ipstack, vpc = VPCStack.vpc)
ECacheStack.add_dependency(target=VPCStack)
OSearchStack = search(app, "wpsearchdomain", env=myenv, res = 'opensearch', preflst = False, allowsg = '', allowall = True, maxaz = 3, ipstack = ipstack, vpc = VPCStack.vpc)
EFSStack = search(app, "wpefs", env=myenv, res = 'wpefs', preflst = False, allowsg = '', allowall = True, ipstack = ipstack, vpc = VPCStack.vpc)

# stack list
#EIPStack = eip(app, "MY-EIP", env=myenv, allocregion = remoteregion)
#VPCStack = VPC(app, "VPC", env=myenv, res = 'vpc', cidrid = 0, natgw = 3, maxaz = 3, ipstack = ipstack)
#BationStack = bastion(app, "MY-Bastion", env=myenv, res = 'bastionsimplepub', preflst = True, allowsg = '', allowall = '', ipstack = ipstack, vpc = VPCStack.vpc)
#GatewayStack = mygw(app, "MY-GATEWAY", env=myenv, gwtype = gwtype, gwid = '', res = 'tgw', route = route, ipstack = ipstack, vpc = VPCStack.vpc, vpcname = 'vpc', bastionsg = '', tgwstack = '', cross = False)
#GatewayStack.add_dependency(target=VPCStack)
#NetFWStack = netfw(app, "MYNETFW", env=myenv, vpcname = 'fwvpcsubnets', res = 'netfwsinglevpc', vpc = VPCStack.vpc, ipstack = ipstack, vpcstackname = VPCStack.stack_name)
#NetFWStack.add_dependency(target=GatewayStack)
#FlowLogsStack = flowlogs(app, "MY-VPCFLOW", env=myenv, logfor = 'default', vpcid = VPCStack.vpc.vpc_id)
#FlowLogsStack.add_dependency(target=NetFWStack)
#BationStack.add_dependency(target=GatewayStack)
#SDStack = sd(app, "My-SD", env=myenv, res = 'ecsbe', ipstack = ipstack, elb = '', vpc = VPCStack.vpc)
#ECStack = ecs(app, "myecs", env=myenv, res = 'ecsbe', preflst = False, allowsg = '', allowall = True, ipstack = ipstack, srvdisc = SDStack.servicename, vpc = VPCStack.vpc)
#ELBStack = alb(app, "MY-ELB", env=myenv, res = 'elbfe', preflst = False, tgrtip = '', allowsg = '', allowall = 443, ipstack = ipstack, tgrt = ASGStack.asg, vpc = VPCStack.vpc)
#ADStack = myds(app, "MYDS", env=myenv, res = 'dirserv', vpc = VPCStack.vpc)
#ADStack.add_dependency(target=VPCStack)
#R53RsvStack = rslv(app, "r53resolver", env=myenv, res = 'r53rslvout', preflst = False, allowsg = '', allowall = '', ipstack = ipstack, vpc = VPCStack.vpc, dsid = ADStack.ds)
#R53RsvStack.add_dependency(target=ADStack)
#RDSStack = rds(app, "MYRDS", env=myenv, res = 'rdsauroramysqlsmallcl', preflst = True, allowall = False, ipstack = ipstack, vpc = VPCStack.vpc, allowsg = InstanceStack.ec2sg)
#CVPNStack = cvpn(app, "MY-CVPN", env=myenv, res = 'cvpn', auth = ['active_directory'], vpc = VPCStack.vpc, dirid = ADStack.ds.ref)
#CVPNStack.add_dependency(target=R53RsvStack)
#EKStack = eks(app, "myeks", env=myenv, res = 'myekspriv', preflst = True, allowsg = '', allowall = '', ipstack = ipstack, role = '', vpc = VPCStack2.vpc)
#EKStack.add_dependency(target=FlowLogsStack2)
#EKSDNSStack = eksdns(app, "dns-controller", env=myenv, ekscluster = EKStack.eksclust)
#EKSDNSStack.add_dependency(target=EKStack)
#EKSInsightsStack = eksinsights(app, "insights", env=myenv, ekscluster = EKStack.eksclust)
#EKSInsightsStack.add_dependency(target=EKStack)
#EKSELBStack = ekselb(app, "aws-elb-controller", env=myenv, ekscluster = EKStack.eksclust)
#EKSELBStack.add_dependency(target=EKSDNSStack)
#EKSNginxCtrlStack = eksnginx(app, "nginx-controller", res = 'eksnginxfe', env=myenv, ekscluster = EKStack.eksclust, vpc=VPCStack.vpc)
#EKSNginxCtrlStack.add_dependency(target=EKSELBStack)
#EKSAppStack = eksapp(app, "nginxs3", env=myenv, res = 'eksalbbe', preflst = False, allowsg = '', allowall = '', ekscluster = EKStack.eksclust, ipstack = ipstack, vpc = VPCStack2.vpc, elbsg = EKStack.lbsg)
#EKSAppStack.add_dependency(EKSELBStack)
#EKSAppStack.add_dependency(EKSDNSStack)
#AppStack = simpleapp(app, "ekstestapp", env=myenv, res = 'ekstestapp', preflst = False, allowsg = '', allowall = '', ekscluster = EKStack.eksclust, ipstack = ipstack, vpc = VPCStack.vpc, elbsg = EKStack.lbsg)
#AppStack.add_dependency(target=EKSNginxCtrlStack)
#DistributionStack = cf(app, "cfdistribution", env=myenv, res = 'elbfe', origin = ELBStack.elb.load_balancer_dns_name)
#VPCStack2 = VPC(app, "MY-VPC2", env=myenv, res = 'vpcsec', cidrid = 1, natgw = 0, maxaz = 3, ipstack = ipstack)
#BationStack2 = bastion(app, "MY-BASTION2", env=myenv, res = 'bastionsimplepriv', preflst = True, allowsg = '', allowall = '', ipstack = ipstack, vpc = VPCStack2.vpc)
#S2SVPNStack = s2svpn(app, "MY-VPN", env=myenv, gwtype = gwtype, route = route, res = 'vpncase', funct = '', ipfamily = 'ipv4', gwid = GatewayStack.gw, cgwaddr = EIPStack.mycustomresource, tgwrt = '', tgwprop = '', tgwrtfunct = '', staticrt = '', remoteregion = remoteregion)
#S2SVPNStack.add_dependency(GatewayStack)
#S3VPNStack = vpns3(app, "MY-S2SVPNS3", env=myenv2, route = route, vpnid = '', remoteregion = region, funct ='', res = 'vpnciscocsrbgp', vpc = VPCStack2.vpc, vpnstackname = 'MY-VPN')
#S3VPNStack.add_dependency(S2SVPNStack)
#VpcEndpointsStack = vpce(app, "MY-VPCENDPOINTS", env=myenv, res = 'myEndpoints', preflst = False, allowsg = '', allowall = '', ipstack = ipstack, vpcsrvpolice = '', vpcsrvtype = '', vpcsrvsubgrp = '', vpcsrvname = '', vpcsrvprivdomain = '', vpcsrvport ='', vpc = VPCStack.vpc, vpcstack = VPCStack.stack_name)
#VpcEndpointsStack.add_dependency(ECStack)
#InstanceStack = instance(app, "My-linux", env=myenv, res = 'bastion', preflst = True, allowsg = '', instpol = '', userdata = '', eipall = '', allowall = False, ipstack = ipstack, vpc = VPCStack.vpc, ds = '')
#InstanceStack.add_dependency(target=VpcEndpointsStack)
#VPNSRVStack2 = instance(app, "My-VPNSRV", env=myenv2, res = 'vpnciscocsrbgp', preflst = True, allowsg = '', instpol = '', userdata = { "Secrets" : S3VPNStack.mycustomresource.get_att_string('USRDATA')}, eipall = S3VPNStack.mycustomresource.get_att_string('EIPAllocid'), allowall = '', ipstack = ipstack, vpc = VPCStack2.vpc, ds = '')
#InstanceStack2 = instance(app, "My-windows", env=myenv, res = 'winhost', preflst = False, allowsg = '', instpol = '', userdata = '', eipall = '', allowall = True, ipstack = ipstack, vpc = VPCStack.vpc, ds = '')
#InstanceStack2.add_dependency(target=VpcEndpointsStack)
#BationStack = bastion(app, "MY-Bastion", env=myenv, res = 'bastionsimplepub', preflst = True, allowsg = '', allowall = '', ipstack = ipstack, vpc = VPCStack.vpc)
#BationStack.add_dependency(target=GatewayStack2)
#ASGStack = asg(app, "MY-ASG", env=myenv, res = 'nginxbe', preflst = False, allowall = True, ipstack = ipstack, allowsg = '', stackusrdata = '', snstopic = '', vpc = VPCStack.vpc)
#ASGStack.add_dependency(target=BationStack)
#SNSStack = sns(app, "MY-SNSTopic", env=myenv, res = "mysns")

app.synth()
