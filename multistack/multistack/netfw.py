import os
import json
from aws_cdk import (
    aws_ec2 as ec2,
    aws_networkfirewall as netfw,
    core,
)
account = os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"])
region = os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])
class internetfw(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, vpc = ec2.Vpc, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.vpc = vpc
        netfwrlgrpcap = 10
        # create rules to fw internet traffic to statefull rules
        self.netfwspolicy = netfw.CfnFirewallPolicy(
			self, 
            f"{construct_id}NetworkFirewallPolicy",
			firewall_policy_name=f"{construct_id}NetworkFirewallPolicy",
			firewall_policy=netfw.CfnFirewallPolicy.FirewallPolicyProperty(
				stateless_default_actions=netfw.CfnFirewallPolicy.StatelessActionsProperty(
					stateless_actions=["aws:pass"]
				),
				stateless_fragment_default_actions=netfw.CfnFirewallPolicy.StatelessActionsProperty(
        			stateless_actions=["aws:pass"])
			)
        )
        self.netfwspolicy.add_property_override('FirewallPolicy.StatelessDefaultActions', ["aws:pass"])
        self.netfwspolicy.add_property_override('FirewallPolicy.StatelessFragmentDefaultActions', ["aws:pass"])
        core.CfnOutput(
            self,
            f"{construct_id}OutNetworkFirewallPolicy",
            value=self.netfwspolicy.attr_firewall_policy_arn,
            export_name=f"{construct_id}:NetworkFirewallPolicy"
        )
        # self.netfwprop = netfw.CfnFirewall(
        #     self,
        #     f"{construct_id}MyNetFW",
        #     firewall_name=f"{construct_id}MyNetFW",
        #     firewall_policy_arn=self.netfwspolicy.attr_firewall_policy_arn,
        #     subnet_mappings=[
        #         netfw.CfnFirewall.SubnetMappingProperty(
        #             subnet_id=ec2.SubnetSelection(
        #                 subnet_type=ec2.SubnetType.ISOLATED,subnet_group_name='Endpoints',one_per_az=True
        #             )
        #         )
        #     ],
        #     vpc_id=self.vpc.vpc_id,
        #     delete_protection=False,
        #     description=('My Firewall-' + region),
        #     firewall_policy_change_protection=False,
        #     subnet_change_protection=False,
        #     tags=[
        #         {
        #             'key':'TagTest',
        #             'value': 'blabla'
        #         }
        #     ]
        # )
        self.incomingrt = ec2.CfnRouteTable(
            self,
            f"{construct_id}IncomeRouteTable",
            vpc_id=self.vpc.vpc_id
        )
        ec2.CfnGatewayRouteTableAssociation(
            self,
            f"{construct_id}IncomeRouteTableAssociation",
            gateway_id=self.vpc.internet_gateway_id,
            route_table_id=self.incomingrt.ref
        )
        mypubrts = {}
        mysetpubrts = {}
        for id in enumerate(self.vpc.availability_zones):
            mypubrts[id] = []
            for subnet in self.vpc.public_subnets:
                mypubrts[id].append(subnet.route_table)
                mysetpubrts[id] = set(mypubrts[id])
