#!/usr/bin/env python3
import os
from aws_cdk import core
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
from multistack.eks import EksStack as eks
from multistack.ecs import EcsStack as ecs
from multistack.eksapp import MyAppStack as eksapp
from multistack.eksctrl import (
    eksDNS as eksdns,
    eksELB as ekselb
    )
from multistack.netfw import (
    internetfw as netfw,
    fwroutes as netfwrt
    )
myenv = core.Environment(account = os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"]), region = os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"]))
myenv2 = core.Environment(account = os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"]), region = 'us-east-1')
remoteregion = 'us-east-1'
route = 'bgp'
gwtype = 'tgw'
ipstack = 'Ipv4'
app = core.App()
VPCStack = VPC(app, "MY-VPC", env=myenv, res = 'inspectvpc', cidrid = 0, natgw = 3, maxaz = 3, ipstack = ipstack)
#FlowLogsStack = flowlogs(app, "MY-VPCFLOW", env=myenv, vpc = VPCStack.vpc)
NetFWStack = netfw(app, "MYNETFW", env=myenv, vpc = VPCStack.vpc)
GatewayStack = mygw(app, "MY-GATEWAY", env=myenv, gwtype = gwtype, gwid = '', res = 'tgwnetfw', route = route, ipstack = ipstack, vpc = VPCStack.vpc, vpcname = 'inspectvpc', bastionsg = '', tgwstack = '')
VPCStack2 = VPC(app, "MY-VPC2", env=myenv, res = 'vpcsec', cidrid = 1, natgw = 0, maxaz = 3, ipstack = ipstack)
GatewayStack2 = mygw(app, "MY-GATEWAY2", env=myenv, gwtype = gwtype, gwid = 'tgw-026aa30aa18280d8d', res = 'tgwnetfw', route = route, ipstack = ipstack, vpc = VPCStack2.vpc, vpcname = 'vpcsec', bastionsg = '', tgwstack = GatewayStack)
VPCStack3 = VPC(app, "MY-VPC3", env=myenv, res = 'vpcsec', cidrid = 2, natgw = 0, maxaz = 3, ipstack = ipstack)
GatewayStack3 = mygw(app, "MY-GATEWAY3", env=myenv, gwtype = gwtype, gwid = 'tgw-026aa30aa18280d8d', res = 'tgwnetfw', route = route, ipstack = ipstack, vpc = VPCStack3.vpc, vpcname = 'vpcsec', bastionsg = '', tgwstack = GatewayStack)
ASGStack = asg(app, "MY-ASG", env=myenv, res = 'bastion', preflst = True, allowall = '', ipstack = ipstack, allowsg = '', vpc = VPCStack.vpc)
ASGStack2 = asg(app, "MY-ASG2", env=myenv, res = 'bastionsimpleiso', preflst = '', allowall = True, ipstack = ipstack, allowsg = '', vpc = VPCStack2.vpc)
ASGStack3 = asg(app, "MY-ASG3", env=myenv, res = 'bastionsimpleiso', preflst = '', allowall = True, ipstack = ipstack, allowsg = '', vpc = VPCStack3.vpc)
#VpcEndpointsStack = vpce(app, "MY-VPCENDPOINTS", env=myenv, res = 'EKSEndpoints', preflst = False, allowsg = '', allowall = '', ipstack = ipstack, vpc = VPCStack.vpc, vpcstack = VPCStack.stack_name)
#FlowLogsStack2 = flowlogs(app, "MY-VPCFLOW2", env=myenv, vpc = VPCStack2.vpc)
#BationStack = bastion(app, "MY-BASTION", env=myenv, res = 'bastionsimplepub', preflst = True, allowsg = '', allowall = '', ipstack = ipstack, vpc = VPCStack.vpc)
#BationStack2 = bastion(app, "MY-BASTION2", env=myenv, res = 'bastion', preflst = True, allowsg = '', allowall = '', ipstack = ipstack, vpc = VPCStack2.vpc)
#EIPStack = eip(app, "MY-EIP", env=myenv, allocregion = remoteregion)
#GatewayStack2 = mygw(app, "MY-GATEWAY2", env=myenv, gwtype = gwtype, gwid = GatewayStack.gw.ref, res = 'tgw', route = route, ipstack = ipstack, vpc = VPCStack2.vpc, bastionsg = BationStack2.bastionsg)
#S2SVPNStack = s2svpn(app, "MY-VPN", env=myenv, gwtype = gwtype, route = route, res = 'vpncust', funct = '', ipfamily = 'ipv4', gwid = GatewayStack.gw, cgwaddr = EIPStack.mycustomresource)
#S3VPNStack = vpns3(app, "MY-S2SVPNS3", env=myenv, route = route, vpnid = S2SVPNStack.mycustomvpn, res = 's3bucket', vpc = VPCStack.vpc)
#RDSStack = rds(app, "MYRDS", env=myenv, res = 'rdsaurorapostgrsmall', vpc = VPCStack.vpc, bastionsg = BationStack.bastionsg)
#ADStack = myds(app, "MYDS", env=myenv, res = 'dirserv', vpc = VPCStack.vpc)
#CVPNStack = cvpn(app, "MY-CVPN", env=myenv, res = 'cvpnmutual', auth = ['mutual'], vpc = VPCStack.vpc)
#NetFWRouteStack = netfwrt(app, "MYNETFWRT", env=myenv, vpc = VPCStack.vpc, netfw = NetFWStack.netfirewall, netfwnum = NetFWStack.endpointnumber)
#EKStack = eks(app, "myeks", env=myenv, res = 'myeksprivec2', preflst = True, allowsg = BationStack.bastionsg, allowall = '', ipstack = ipstack, role = BationStack.bastion.role.role_arn, vpc = VPCStack.vpc)
#EKSDNSStack = eksdns(app, "dns-controller", env=myenv, ekscluster = EKStack.eksclust)
#EKSELBStack = ekselb(app, "aws-elb-controller", env=myenv, ekscluster = EKStack.eksclust)
#EKSAppStack = eksapp(app, "nginxs3", env=myenv, res = 'eksnlbfe', preflst = False, allowsg = BationStack.bastionsg, allowall = '', ekscluster = EKStack.eksclust, ipstack = ipstack, vpc = VPCStack.vpc, elbsg = EKStack.lbsg)
#ECStack = ecs(app, "myecs", env=myenv, res = 'myecsAsgpriv', preflst = False, allowsg = BationStack.bastionsg, allowall = 443, ipstack = ipstack, vpc = VPCStack.vpc)
#ELBStack = alb(app, "MY-ELB", env=myenv, res = 'elbfe', preflst = False, allowsg = '', allowall = 443, ipstack = ipstack, tgrt = ECStack.srvc, vpc = VPCStack.vpc)
app.synth()
