#!/usr/bin/env python3
import os
from aws_cdk import core

from multistack.vpc_empty import VPCv6 as VPC
from multistack.bastion import bastionv6 as bastion
from multistack.vpcflow import flowlogs
from multistack.vpcendpoints import vpcebasicv6 as vpce
from multistack.tgw_vgw import tgwv6 as tgw
from multistack.asbelb import asgalbpublicv6 as asgalb

app = core.App()
VPCStack = VPC(app, "MY-VPC", env=core.Environment(account=os.environ.get("CDK_DEPLOY_ACCOUNT",os.environ["CDK_DEFAULT_ACCOUNT"]), region=os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])))
FlowLogsStack = flowlogs(app, "MY-VPCFLOW", env=core.Environment(account=os.environ.get("CDK_DEPLOY_ACCOUNT",os.environ["CDK_DEFAULT_ACCOUNT"]), region=os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])), vpc = VPCStack.vpc)
VpcEndpointsStack = vpce(app, "MY-VPCENDPOINTS", env=core.Environment(account=os.environ.get("CDK_DEPLOY_ACCOUNT",os.environ["CDK_DEFAULT_ACCOUNT"]), region=os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])), vpc = VPCStack.vpc)
BationStack = bastion(app, "MY-BASTION", env=core.Environment(account=os.environ.get("CDK_DEPLOY_ACCOUNT",os.environ["CDK_DEFAULT_ACCOUNT"]), region=os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])), vpc = VPCStack.vpc)
GatewayStack = tgw(app, "MY-GATEWAY", env=core.Environment(account=os.environ.get("CDK_DEPLOY_ACCOUNT",os.environ["CDK_DEFAULT_ACCOUNT"]), region=os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])), vpc = VPCStack.vpc, bastionsg = BationStack.bastionsg)
ASGALBStack = asgalb(app, "MY-ASGELB", env=core.Environment(account=os.environ.get("CDK_DEPLOY_ACCOUNT",os.environ["CDK_DEFAULT_ACCOUNT"]), region=os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])), vpc = VPCStack.vpc, bastionsg = BationStack.bastionsg)

app.synth()
