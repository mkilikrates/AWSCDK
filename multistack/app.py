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
from multistack.eksapp import MyAppStack as eksapp
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
VPCStack = VPC(app, "MY-VPC", env=myenv, res = 'vpc', cidrid = 0, natgw = 1, maxaz = 3, ipstack = ipstack)
FlowLogsStack = flowlogs(app, "MY-VPCFLOW", env=myenv, vpc = VPCStack.vpc)
#VpcEndpointsStack = vpce(app, "MY-VPCENDPOINTS", env=myenv, res = 's3Endpoint', preflst = True, allowsg = '', allowall = '', ipstack = ipstack, vpc = VPCStack.vpc, vpcstack = VPCStack.stack_name)
BationStack = bastion(app, "MY-BASTION", env=myenv, res = 'bastion', preflst = True, allowsg = '', allowall = '', ipstack = ipstack, vpc = VPCStack.vpc)
#ASGStack = asg(app, "MY-ASG", env=myenv, res = 'apachephphttp2dmz', preflst = True, allowall = '', ipstack = ipstack, allowsg = BationStack.bastionsg, vpc = VPCStack.vpc)
#EIPStack = eip(app, "MY-EIP", env=myenv, allocregion = remoteregion)
#GatewayStack = mygw(app, "MY-GATEWAY", env=myenv, gwtype = gwtype, gwid = '', res = 'tgw', route = route, ipstack = ipstack, vpc = VPCStack.vpc, bastionsg = BationStack.bastionsg)
#S2SVPNStack = s2svpn(app, "MY-VPN", env=myenv, gwtype = gwtype, route = route, res = 'vpncust', funct = '', ipfamily = 'ipv4', gwid = GatewayStack.gw, cgwaddr = EIPStack.mycustomresource)
#S3VPNStack = vpns3(app, "MY-S2SVPNS3", env=myenv, route = route, vpnid = S2SVPNStack.mycustomvpn, res = 's3bucket', vpc = VPCStack.vpc)
#ELBStack = alb(app, "MY-ELB", env=myenv, res = 'elbfe', preflst = False, allowsg = '', allowall = 443, ipstack = ipstack, tgrt = ASGStack.asg, vpc = VPCStack.vpc)
#RDSStack = rds(app, "MYRDS", env=myenv, res = 'rdsaurorapostgrsmall', vpc = VPCStack.vpc, bastionsg = BationStack.bastionsg)
#ADStack = myds(app, "MYDS", env=myenv, res = 'dirserv', vpc = VPCStack.vpc)
#CVPNStack = cvpn(app, "MY-CVPN", env=myenv, res = 'cvpnmutual', auth = ['mutual'], vpc = VPCStack.vpc)
#NetFWStack = netfw(app, "MYNETFW", env=myenv, vpc = VPCStack.vpc)
#NetFWRouteStack = netfwrt(app, "MYNETFWRT", env=myenv, vpc = VPCStack.vpc, netfw = NetFWStack.netfirewall, netfwnum = NetFWStack.endpointnumber)
EKStack = eks(app, "myeks", env=myenv, res = 'myeksprivec2', preflst = True, allowsg = BationStack.bastionsg, allowall = '', ipstack = ipstack, vpc = VPCStack.vpc)
EKSAppStack2 = eksapp(app, "nginxs3", env=myenv, res = 'eksnlbbe', preflst = False, allowsg = BationStack.bastionsg, allowall = '', ekscluster = EKStack.eksclust, ipstack = ipstack, vpc = VPCStack.vpc, elbsg = EKStack.lbsg)
app.synth()
