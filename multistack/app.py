#!/usr/bin/env python3
import os
from aws_cdk import core

from multistack.vpc_empty import VPC as VPC
from multistack.bastion import bastion as bastion
from multistack.vpcflow import flowlogs
from multistack.vpcendpoints import vpcefreev4 as vpce
from multistack.tgw_vgw import vgwv4 as tgw
from multistack.tgw_vgw import attachtgwv6 as tgw2
from multistack.asbelb import asgalbisolate as asgalb
from multistack.rds import mariamazpub as rds
from multistack.vpn import cvpnfed as cvpn
from multistack.ec2_eip import EIP as eip
from multistack.netfw import internetfw as netfw

app = core.App()
VPCStack = VPC(app, "MY-VPC", env=core.Environment(account=os.environ.get("CDK_DEPLOY_ACCOUNT",os.environ["CDK_DEFAULT_ACCOUNT"]), region=os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])), cidrid = 0, natgw = 2, maxaz = 2, stack = 'Ipv6')
#VPCStack2 = VPC(app, "MY-VPC2", env=core.Environment(account=os.environ.get("CDK_DEPLOY_ACCOUNT",os.environ["CDK_DEFAULT_ACCOUNT"]), region=os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])), cidrid = 1, natgw = 2, maxaz = 2)
#VPCStack2 = VPC(app, "MY-VPC2", env=core.Environment(account=os.environ.get("CDK_DEPLOY_ACCOUNT",os.environ["CDK_DEFAULT_ACCOUNT"]), region='us-east-1', cidrid = 0, natgw = 1, maxaz = 2)
#FlowLogsStack = flowlogs(app, "MY-VPCFLOW", env=core.Environment(account=os.environ.get("CDK_DEPLOY_ACCOUNT",os.environ["CDK_DEFAULT_ACCOUNT"]), region=os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])), vpc = VPCStack.vpc)
#VpcEndpointsStack = vpce(app, "MY-VPCENDPOINTS", env=core.Environment(account=os.environ.get("CDK_DEPLOY_ACCOUNT",os.environ["CDK_DEFAULT_ACCOUNT"]), region=os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])), vpc = VPCStack.vpc, vpcstack = VPCStack.stack_name)
BationStack = bastion(app, "MY-BASTION", env=core.Environment(account=os.environ.get("CDK_DEPLOY_ACCOUNT",os.environ["CDK_DEFAULT_ACCOUNT"]), region=os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])), vpc = VPCStack.vpc, resource = 'bastion')
#BationStack2 = bastion(app, "MY-BASTION2", env=core.Environment(account=os.environ.get("CDK_DEPLOY_ACCOUNT",os.environ["CDK_DEFAULT_ACCOUNT"]), region=os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])), vpc = VPCStack2.vpc)
#GatewayStack = tgw(app, "MY-GATEWAY", env=core.Environment(account=os.environ.get("CDK_DEPLOY_ACCOUNT",os.environ["CDK_DEFAULT_ACCOUNT"]), region=os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])), vpc = VPCStack.vpc, bastionsg = BationStack.bastionsg)
#GatewayStack2 = tgw2(app, "MY-GATEWAY2", env=core.Environment(account=os.environ.get("CDK_DEPLOY_ACCOUNT",os.environ["CDK_DEFAULT_ACCOUNT"]), region=os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])), vpc = VPCStack2.vpc, bastionsg = BationStack2.bastionsg, tgwid = GatewayStack.tgw)
#ASGALBStack = asgalb(app, "MY-ASGELB", env=core.Environment(account=os.environ.get("CDK_DEPLOY_ACCOUNT",os.environ["CDK_DEFAULT_ACCOUNT"]), region=os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])), vpc = VPCStack.vpc, bastionsg = BationStack.bastionsg)
#RDSStack = rds(app, "MY-RDS", env=core.Environment(account=os.environ.get("CDK_DEPLOY_ACCOUNT",os.environ["CDK_DEFAULT_ACCOUNT"]), region=os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])), vpc = VPCStack.vpc, bastionsg = BationStack.bastionsg)
#CVPNStack = cvpn(app, "MY-CVPN", env=core.Environment(account=os.environ.get("CDK_DEPLOY_ACCOUNT",os.environ["CDK_DEFAULT_ACCOUNT"]), region=os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])), vpc = VPCStack.vpc)
#EIPStack = eip(app, "MY-EIP", env=core.Environment(account=os.environ.get("CDK_DEPLOY_ACCOUNT",os.environ["CDK_DEFAULT_ACCOUNT"]), region=os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])), allocregion = 'us-east-1')
#NetFWStack = netfw(app, "MY-NETFW", env=core.Environment(account=os.environ.get("CDK_DEPLOY_ACCOUNT",os.environ["CDK_DEFAULT_ACCOUNT"]), region=os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])))
app.synth()
