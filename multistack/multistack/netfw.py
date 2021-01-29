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
        self.incomingrt = ec2.CfnRouteTable(
            self,
            f"{construct_id}IncomeRouteTable",
            vpc_id=self.vpc.vpc_id
        )
        # edge association
        ec2.CfnGatewayRouteTableAssociation(
            self,
            f"{construct_id}IncomeRouteTableAssociation",
            gateway_id=self.vpc.internet_gateway_id,
            route_table_id=self.incomingrt.ref
        )
        # mypubrts = {}
        # mysetpubrts = {}
        # for id in enumerate(self.vpc.availability_zones):
        #     mypubrts[id] = []
        #     for subnet in self.vpc.public_subnets:
        #         mypubrts[id].append(subnet.route_table)
        #         mysetpubrts[id] = set(mypubrts[id])

        # self.netfwrulegrp = netfw.CfnRuleGroup.RuleGroupProperty(
        #     rule_variables=None,
        #     rules_source=netfw.CfnRuleGroup.RulesSourceProperty(
        #         rules_source_list=None,
        #         stateful_rules=None,
        #         stateless_rules_and_custom_actions=netfw.CfnRuleGroup.StatelessRulesAndCustomActionsProperty(
        #             stateless_rules=[
        #                 netfw.CfnRuleGroup.StatelessRuleProperty(
        #                     priority=10,
        #                     rule_definition=[
        #                         netfw.CfnRuleGroup.RuleDefinitionProperty(
        #                             actions=["aws:forward_to_sfe"],
        #                             match_attributes=netfw.CfnRuleGroup.MatchAttributesProperty(
        #                                 destination_ports=[
        #                                     netfw.CfnRuleGroup.PortRangeProperty(
        #                                         from_port=80,
        #                                         to_port=80
        #                                     ),
        #                                     netfw.CfnRuleGroup.PortRangeProperty(
        #                                         from_port=443,
        #                                         to_port=443
        #                                     )
        #                                 ],
        #                                 destinations=[
        #                                     netfw.CfnRuleGroup.AddressesProperty(
        #                                         addresses=('0.0.0.0/0')
        #                                     ),
        #                                     netfw.CfnRuleGroup.AddressesProperty(
        #                                         addresses=('::/0')
        #                                     ),
        #                                 ],
        #                                 sources=[
        #                                     netfw.CfnRuleGroup.AddressesProperty(
        #                                         addresses=self.vpc.vpc_cidr_block
        #                                     ),
        #                                     netfw.CfnRuleGroup.AddressesProperty(
        #                                         addresses=core.Fn.select(
        #                                             0,
        #                                             self.vpc.vpc_ipv6_cidr_blocks
        #                                         )
        #                                     )
        #                                 ],
        #                                 source_ports=[
        #                                     netfw.CfnRuleGroup.PortRangeProperty(
        #                                         from_port=0,
        #                                         to_port=65535
        #                                     )
        #                                 ]
        #                             )
        #                         )
        #                     ]
        #                 )
        #             ]
        #         )
        #     )
        # )
        # # create rule group
        # self.netfwrulegrpstateless = netfw.CfnRuleGroup(
        #     self,
        #     f"{construct_id}MyNetFWRuleGrpStateless",
        #     capacity=netfwrlgrpcap,
        #     rule_group_name=(
        #         f"{construct_id}MyNetFWRuleGrpStateless"
        #     ),
        #     type=(
        #         "STATELESS"
        #     ),
        #     description=(
        #         "Stateless Rule Group"
        #     ),
        #     rule_group=[self.netfwrulegrp]
        # )
        #create firewall policy
        self.netfwspolicy = netfw.CfnFirewallPolicy(
			self,
            f"{construct_id}NetworkFirewallPolicy",
			firewall_policy_name=f"{construct_id}NetworkFirewallPolicy",
			firewall_policy=netfw.CfnFirewallPolicy.FirewallPolicyProperty(
				stateless_default_actions=netfw.CfnFirewallPolicy.StatelessActionsProperty(
					stateless_actions=["aws:pass"]
				),
				stateless_fragment_default_actions=netfw.CfnFirewallPolicy.StatelessActionsProperty(
        			stateless_actions=["aws:pass"]
                )
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
        self.netfwprop = netfw.CfnFirewall(
            self,
            f"{construct_id}MyNetFW",
            firewall_name=f"{construct_id}MyNetFW",
            firewall_policy_arn=self.netfwspolicy.attr_firewall_policy_arn,
            subnet_mappings=[
                netfw.CfnFirewall.SubnetMappingProperty(
                    subnet_id = subnet_id
                ) for subnet_id in self.vpc.select_subnets(
                    subnet_group_name='Endpoints'
                ).subnet_ids
            ],
            vpc_id=self.vpc.vpc_id,
            delete_protection=False,
            description=('My Firewall-' + region),
            firewall_policy_change_protection=False,
            subnet_change_protection=False,
        )
        core.CfnOutput(
            self,
            f"{construct_id}OutNetworkFirewallId",
            value=self.netfwprop.attr_firewall_id,
            export_name=f"{construct_id}:NetworkFirewallId"
        )
        core.CfnOutput(
            self,
            f"{construct_id}OutNetworkFirewallArn",
            value=self.netfwprop.attr_firewall_arn,
            export_name=f"{construct_id}:NetworkFirewallArn"
        )
        for index, endpointid in enumerate(self.netfwprop.attr_endpoint_ids):
            core.CfnOutput(
                self,
                f"{construct_id}OutNetwFwEnd{id}AZ",
                value=core.Fn.select(
                    1,
                    core.Fn.split(
                        ":",
                        core.Fn.select(
                                index,
                                self.netfwprop.attr_endpoint_ids,
                        )
                    )
                ),
                export_name=f"{construct_id}NetwFwEnd{id}AZ"
            )
            core.CfnOutput(
                self,
                f"{construct_id}OutNetwFwEnd{id}AZid",
                value=core.Fn.select(
                    2,
                    core.Fn.split(
                        ":",
                        core.Fn.select(
                                index,
                                self.netfwprop.attr_endpoint_ids,
                        )
                    )
                ),
                export_name=f"{construct_id}NetwFwEnd{id}AZid"
            )

