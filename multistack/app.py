#!/usr/bin/env python3
import os
from aws_cdk import core
from aws_cdk.aws_cloudfront import Distribution
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
from multistack.eksapp import (
    MyAppStack as eksapp,
    AppStack as simpleapp
    )
from multistack.netfw import internetfw as netfw
from multistack.ec2 import InstanceStack as instance
from multistack.eksctrl import (
    eksDNS as eksdns,
    eksELB as ekselb,
    eksING as eksing,
    eksNGINXMNF as eksnginx
    )
from multistack.cloudfront import CloudFrontStack as cf
region = os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])
remoteregion = os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])
account = os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"])
myenv = core.Environment(account = os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"]), region = os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"]))
myenv2 = core.Environment(account = os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"]), region = remoteregion)

route = 'static'
gwtype = 'tgw'
ipstack = 'Ipv4'
app = core.App()
VPCStack = VPC(app, "MY-VPC", env=myenv, res = 'vpc', cidrid = 0, natgw = 2, maxaz = 2, ipstack = ipstack)
#VpcEndpointsStack = vpce(app, "MY-VPCENDPOINTS", env=myenv, res = 's3Endpoint', preflst = False, allowsg = '', allowall = '', ipstack = ipstack, vpc = VPCStack.vpc, vpcstack = VPCStack.stack_name)
#GatewayStack = mygw(app, "MY-GATEWAY", env=myenv, gwtype = gwtype, gwid = '', res = 'tgw', route = route, ipstack = ipstack, vpc = VPCStack.vpc, vpcname = 'inspectvpc', bastionsg = '', tgwstack = '', cross = False)
#GatewayStack.add_dependency(target=VPCStack)
#NetFWStack = netfw(app, "MYNETFW", env=myenv, vpcname = 'inspectvpc', res = 'netfwtgw', vpc = VPCStack.vpc, ipstack = ipstack, vpcstackname = VPCStack.stack_name)
#NetFWStack.add_dependency(target=VPCStack)
#FlowLogsStack = flowlogs(app, "MY-VPCFLOW", env=myenv, logfor = 'default', vpcid = VPCStack.vpc.vpc_id)
#FlowLogsStack.add_dependency(target=NetFWStack)
BationStack = bastion(app, "MY-BASTION", env=myenv, res = 'bastion', preflst = True, allowsg = '', allowall = '', ipstack = ipstack, vpc = VPCStack.vpc)
BationStack.add_dependency(target=VPCStack)
#ADStack = myds(app, "MYDS", env=myenv, res = 'dirserv', vpc = VPCStack2.vpc)
#ADStack.add_dependency(target=FlowLogsStack2)
#R53RsvStack = rslv(app, "r53resolver", env=myenv, res = 'r53rslvout', preflst = False, allowsg = '', allowall = '', ipstack = ipstack, vpc = VPCStack2.vpc, dsid = ADStack.ds)
#R53RsvStack.add_dependency(target=ADStack)
#InstanceStack = instance(app, "My-instance", env=myenv, res = 'winhost', preflst = True, allowsg = '', instpol = '', eipall = '', allowall = '', ipstack = ipstack, vpc = VPCStack.vpc)
#InstanceStack.add_dependency(target=NetFWStack)
ASGStack = asg(app, "MY-ASG", env=myenv, res = 'apachephphttp2be', preflst = True, allowall = 80, ipstack = ipstack, allowsg = BationStack.bastionsg, vpc = VPCStack.vpc)
#RDSStack = rds(app, "MYRDS", env=myenv, res = 'rdsaurorapostgrsmall', vpc = VPCStack2.vpc, bastionsg = BationStack.bastionsg)
#CVPNStack = cvpn(app, "MY-CVPN", env=myenv, res = 'cvpn', auth = ['mutual', 'federated'], vpc = VPCStack2.vpc, dirid = '')
#EKStack = eks(app, "myeks", env=myenv, res = 'myekspriv', preflst = True, allowsg = '', allowall = '', ipstack = ipstack, role = '', vpc = VPCStack2.vpc)
#EKStack.add_dependency(target=FlowLogsStack2)
#EKSDNSStack = eksdns(app, "dns-controller", env=myenv, ekscluster = EKStack.eksclust)
#EKSDNSStack.add_dependency(target=EKStack)
#EKSELBStack = ekselb(app, "aws-elb-controller", env=myenv, ekscluster = EKStack.eksclust)
#EKSELBStack.add_dependency(target=EKSDNSStack)
#EKSINGStack = eksing(app, "aws-elb-controller", env=myenv, ekscluster = EKStack.eksclust)
#EKSINGStack.add_dependency(target=EKStack)
## use one or other 
#EKSNginxCtrlStack = eksnginx(app, "nginx-controller", res = 'eksnginxfe', env=myenv, ekscluster = EKStack.eksclust, vpc=VPCStack.vpc)
#EKSNginxCtrlStack.add_dependency(target=EKSELBStack)
#EKSAppStack = eksapp(app, "nginxs3", env=myenv, res = 'eksalbbe', preflst = False, allowsg = '', allowall = '', ekscluster = EKStack.eksclust, ipstack = ipstack, vpc = VPCStack2.vpc, elbsg = EKStack.lbsg)
#EKSAppStack.add_dependency(EKSELBStack)
#EKSAppStack.add_dependency(EKSDNSStack)
#AppStack = simpleapp(app, "ekstestapp", env=myenv, res = 'ekstestapp', preflst = False, allowsg = '', allowall = '', ekscluster = EKStack.eksclust, ipstack = ipstack, vpc = VPCStack.vpc, elbsg = EKStack.lbsg)
#AppStack.add_dependency(target=EKSNginxCtrlStack)
#ECStack = ecs(app, "myecs", env=myenv, res = 'eksnlbbe', preflst = False, allowsg = BationStack.bastionsg, allowall = 443, ipstack = ipstack, vpc = VPCStack2.vpc)
ELBStack = alb(app, "MY-ELB", env=myenv, res = 'nlbfe', preflst = False, allowsg = BationStack.bastionsg, allowall = 80, ipstack = ipstack, tgrt = ASGStack.asg, vpc = VPCStack.vpc)
#DistributionStack = cf(app, "cfdistribution", env=myenv, res = 'elbfe', origin = ELBStack.elb.load_balancer_dns_name)
#VPCStack2 = VPC(app, "MY-VPC2", env=myenv, res = 'vpcsec', cidrid = 1, natgw = 0, maxaz = 3, ipstack = ipstack)
#BationStack2 = bastion(app, "MY-BASTION2", env=myenv, res = 'bastionsimplepriv', preflst = True, allowsg = '', allowall = '', ipstack = ipstack, vpc = VPCStack2.vpc)
#EIPStack = eip(app, "MY-EIP", env=myenv, allocregion = remoteregion)
#EIPStack.add_dependency(BationStack2)
#S2SVPNStack = s2svpn(app, "MY-VPN", env=myenv, gwtype = gwtype, route = route, res = 'vpncase', funct = '', ipfamily = 'ipv4', gwid = GatewayStack.gw, cgwaddr = EIPStack.mycustomresource, tgwrt = '', tgwprop = '', tgwrtfunct = '', staticrt = ["10.16.0.0/24", "10.15.15.0/24", "10.25.1.0/24", "10.15.1.0/24", "172.31.0.0/16"])
#S2SVPNStack.add_dependency(GatewayStack)
#VPCStack3 = VPC(app, "MY-VPC3", env=myenv, res = 'vpcpub', cidrid = 2, natgw = 0, maxaz = 1, ipstack = ipstack)
#VPCStack3.add_dependency(S2SVPNStack)
#S3VPNStack = vpns3(app, "MY-S2SVPNS3", env=myenv, route = route, vpnid = core.Fn.import_value(f"{S2SVPNStack.stack_name}:VPNid"), vpnregion = '', funct ='', res = 'vpnsrvcase', vpc = VPCStack.vpc)
#S3VPNStack.add_dependency(S2SVPNStack)
app.synth()
