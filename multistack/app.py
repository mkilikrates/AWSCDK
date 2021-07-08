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
remoteregion = 'eu-west-1'
myenv = core.Environment(account = os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"]), region = os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"]))
myenv2 = core.Environment(account = os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"]), region = remoteregion)
route = 'bgp'
gwtype = 'tgw'
ipstack = 'Ipv4'
app = core.App()
VPCStack = VPC(app, "MY-VPC", env=myenv, res = 'vpc', cidrid = 0, natgw = 2, maxaz = 2, ipstack = ipstack)
#FlowLogsStack = flowlogs(app, "MY-VPCFLOW", env=myenv, logfor = 'default', vpcid = VPCStack.vpc.vpc_id)
#FlowLogsStack.add_dependency(target=VPCStack)
#ADStack = myds(app, "MYDS", env=myenv, res = 'dirserv', vpc = VPCStack.vpc)
#ADStack.add_dependency(target=FlowLogsStack)
#R53RsvStack = rslv(app, "r53resolver", env=myenv, res = 'r53rslvout', preflst = False, allowsg = '', allowall = '', ipstack = ipstack, vpc = VPCStack.vpc, dsid = ADStack.ds)
# R53RsvStack.add_dependency(target=ADStack)
#NetFWStack = netfw(app, "MYNETFW", env=myenv, vpcname = 'inspectvpc', res = 'netfwtgw', vpc = VPCStack.vpc)
#GatewayStack = mygw(app, "MY-GATEWAY", env=myenv, gwtype = gwtype, gwid = '', res = 'tgwnetfw', route = route, ipstack = ipstack, vpc = VPCStack.vpc, vpcname = 'inspectvpc', bastionsg = '', tgwstack = '', cross = False)
#VpcEndpointsStack = vpce(app, "MY-VPCENDPOINTS", env=myenv, res = 's3Endpoint', preflst = False, allowsg = '', allowall = '', ipstack = ipstack, vpc = VPCStack.vpc, vpcstack = VPCStack.stack_name)
InstanceStack = instance(app, "My-instance", env=myenv, res = 'winbast', preflst = True, allowsg = '', instpol = '', eipall = '', allowall = '', ipstack = ipstack, vpc = VPCStack.vpc)
#BationStack = bastion(app, "MY-BASTION", env=myenv, res = 'bastion', preflst = True, allowsg = '', allowall = '', ipstack = ipstack, vpc = VPCStack.vpc)
#BationStack.add_dependency(target=VpcEndpointsStack)
#ASGStack = asg(app, "MY-ASG", env=myenv, res = 'nginxbe', preflst = False, allowall = '', ipstack = ipstack, allowsg = BationStack.bastionsg, vpc = VPCStack.vpc)
#ASGStack.add_dependency(target=VpcEndpointsStack)
#RDSStack = rds(app, "MYRDS", env=myenv, res = 'rdsaurorapostgrsmall', vpc = VPCStack2.vpc, bastionsg = BationStack.bastionsg)
#CVPNStack = cvpn(app, "MY-CVPN", env=myenv, res = 'cvpn', auth = ['mutual', 'federated'], vpc = VPCStack2.vpc, dirid = '')
#EKStack = eks(app, "myeks", env=myenv, res = 'myekspubec2', preflst = True, allowsg = BationStack.bastionsg, allowall = '', ipstack = ipstack, role = '', vpc = VPCStack.vpc)
#EKSDNSStack = eksdns(app, "dns-controller", env=myenv, ekscluster = EKStack.eksclust)
#EKSDNSStack.add_dependency(target=EKStack)
#EKSELBStack = ekselb(app, "aws-elb-controller", env=myenv, ekscluster = EKStack.eksclust)
#EKSELBStack.add_dependency(target=EKSDNSStack)
#EKSINGStack = eksing(app, "aws-elb-controller", env=myenv, ekscluster = EKStack.eksclust)
#EKSINGStack.add_dependency(target=EKStack)
## use one or other 
#EKSNginxCtrlStack = eksnginx(app, "nginx-controller", res = 'eksnginxfe', env=myenv, ekscluster = EKStack.eksclust, vpc=VPCStack.vpc)
#EKSNginxCtrlStack.add_dependency(target=EKSELBStack)
#EKSAppStack = eksapp(app, "nginxs3", env=myenv, res = 'eksnginxfe', preflst = False, allowsg = '', allowall = '', ekscluster = EKStack.eksclust, ipstack = ipstack, vpc = VPCStack.vpc, elbsg = EKStack.lbsg)
#EKSAppStack.add_dependency(EKSNginxCtrlStack)
#EKSAppStack.add_dependency(EKSDNSStack)
#AppStack = simpleapp(app, "ekstestapp", env=myenv, res = 'ekstestapp', preflst = False, allowsg = '', allowall = '', ekscluster = EKStack.eksclust, ipstack = ipstack, vpc = VPCStack.vpc, elbsg = EKStack.lbsg)
#AppStack.add_dependency(target=EKSNginxCtrlStack)
#ECStack = ecs(app, "myecs", env=myenv, res = 'eksnlbbe', preflst = False, allowsg = BationStack.bastionsg, allowall = 443, ipstack = ipstack, vpc = VPCStack2.vpc)
#ELBStack = alb(app, "MY-ELB", env=myenv, res = 'elbfe', preflst = False, allowsg = '', allowall = 443, ipstack = ipstack, tgrt = ASGStack.asg, vpc = VPCStack.vpc)
#DistributionStack = cf(app, "cfdistribution", env=myenv, res = 'elbfe', origin = ELBStack.elb.load_balancer_dns_name)
#VPCStack2 = VPC(app, "MY-VPC2", env=myenv, res = 'vpcsec', cidrid = 1, natgw = 0, maxaz = 3, ipstack = ipstack)
#BationStack2 = bastion(app, "MY-BASTION2", env=myenv, res = 'bastionsimplepriv', preflst = True, allowsg = '', allowall = '', ipstack = ipstack, vpc = VPCStack2.vpc)
#EIPStack = eip(app, "MY-EIP", env=myenv, allocregion = remoteregion)
#EIPStack.add_dependency(BationStack2)
#S2SVPNStack = s2svpn(app, "MY-VPN", env=myenv, gwtype = gwtype, route = route, res = 'vpncust', funct = '', ipfamily = 'ipv4', gwid = GatewayStack.gw, cgwaddr = EIPStack.mycustomresource, tgwrt = core.Fn.import_value(f"{GatewayStack.stack_name}:tgwrtSentToFWout"), tgwprop = core.Fn.import_value(f"{GatewayStack.stack_name}:tgwrtVPCsout"), tgwrtfunct = '', staticrt = [])
#VPCStack3 = VPC(app, "MY-VPC3", env=myenv, res = 'vpcpub', cidrid = 2, natgw = 0, maxaz = 1, ipstack = ipstack)
#VPCStack3.add_dependency(S2SVPNStack)
#S3VPNStack = vpns3(app, "MY-S2SVPNS3", env=myenv, route = route, vpnid = core.Fn.import_value(f"{S2SVPNStack.stack_name}:VPNid"), vpnregion = remoteregion, funct ='', res = 'vpnsrvstrswbgp', vpc = VPCStack3.vpc)
app.synth()
