#!/usr/bin/env python3
import os
from aws_cdk import core

from multistack.vpc_empty import VPC as VPC
from multistack.bastion import bastion as bastion
from multistack.vpcflow import flowlogs
from multistack.vpcendpoints import vpcebasicv4 as vpce
from multistack.tgw_vgw import mygw
from multistack.asg import main as asg
from multistack.elb import alb
from multistack.rds import mariamazpub as rds
from multistack.vpn import cvpn, s2svpn
from multistack.ec2_eip import EIP as eip
from multistack.decodevpn import S2SVPNS3 as vpns3
from multistack.netfw import (
    internetfw as netfw,
    fwroutes as netfwrt
    )
myenv = core.Environment(account = os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"]), region = os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"]))
myenv2 = core.Environment(account = os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"]), region = 'us-east-1')
remoteregion = 'us-east-1'
route = 'bgp'
app = core.App()
VPCStack = VPC(app, "MY-VPC", env=myenv, res = 'vpc', cidrid = 0, natgw = 1, maxaz = 2, stack = 'Ipv4')
VpcEndpointsStack = vpce(app, "MY-VPCENDPOINTS", env=myenv, vpc = VPCStack.vpc, vpcstack = VPCStack.stack_name)
BationStack = bastion(app, "MY-BASTION", env=myenv, res = 'bastionsimple', preflst = True, allowsg = '', allowall = '', vpc = VPCStack.vpc)
ASGStack = asg(app, "MY-ASG", env=myenv, res = 'bastionsimple', preflst = True, allowsg = BationStack.bastionsg, allowall = '', vpc = VPCStack.vpc).add_dependency(VpcEndpointsStack)
#VPCStack2 = VPC(app, "MY-VPC2", env=myenv2, res = 'vpc', cidrid = 0, natgw = 1, maxaz = 3, stack = 'Ipv4')
#BationStack2 = bastion(app, "MY-BASTION2", env=myenv2, res = 'bastionsimple', preflst = True, allowsg = '', allowall = '', vpc = VPCStack2.vpc)
#EIPStack = eip(app, "MY-EIP", env=myenv, allocregion = remoteregion)
#GatewayStack = mygw(app, "MY-GATEWAY", env=myenv, gwtype = 'vgw', gwid = '', route = route, vpc = VPCStack.vpc, bastionsg = BationStack.bastionsg)
#S2SVPNStack = s2svpn(app, "MY-VPN", env=myenv, gwtype = 'vgw', route = route, gwid = GatewayStack.gw, cgwaddr = EIPStack.mycustomresource)
#S3VPNStack = vpns3(app, "MY-S2SVPNS3", env=myenv, route = route, vpnid = S2SVPNStack.vpn, res = 's3bucket', vpc = VPCStack.vpc)
#ASGStack = asg(app, "MY-ASG", env=myenv, res = 'bastionsimple', preflst = True, allowsg = '', allowall = '', vpc = VPCStack.vpc)
#ELBStack = alb(app, "MY-ELB", env=myenv, res = 'albfe', preflst = False, allowsg = '', allowall = 443, tgrt = ASGStack.asg, vpc = VPCStack.vpc)
#VPCStack2 = VPC(app, "MY-VPC2", env=myenv, region='us-east-1', cidrid = 0, natgw = 1, maxaz = 2)
#FlowLogsStack = flowlogs(app, "MY-VPCFLOW", env=myenv, vpc = VPCStack.vpc)
#GatewayStack2 = tgw2(app, "MY-GATEWAY2", env=myenv, vpc = VPCStack2.vpc, bastionsg = BationStack2.bastionsg, tgwid = GatewayStack.tgw)
#RDSStack = rds(app, "MY-RDS", env=myenv, vpc = VPCStack.vpc, bastionsg = BationStack.bastionsg)
#CVPNStack = cvpn(app, "MY-CVPN", env=myenv, auth = ['federated'], vpc = VPCStack.vpc)
#NetFWStack = netfw(app, "MYNETFW", env=myenv, vpc = VPCStack.vpc)
#NetFWRouteStack = netfwrt(app, "MYNETFWRT", env=myenv, vpc = VPCStack.vpc, netfw = NetFWStack.netfirewall, netfwnum = NetFWStack.endpointnumber)
app.synth()
