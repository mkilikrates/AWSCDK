import os
import json
import logging
from aws_cdk import (
    aws_ec2 as ec2,
    aws_networkfirewall as netfw,
    core,
)
account = os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"])
region = os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])
resconf = "resourcesmap.cfg"
with open(resconf) as resfile:
    resmap = json.load(resfile)
with open('zonemap.cfg') as zonefile:
    zonemap = json.load(zonefile)
class internetfw(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, vpc = ec2.Vpc, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.vpc = vpc
        netfwrlgrpcap = 100
        # create stateless rulegroup
        self.netfwstatelessrulegrp = netfw.CfnRuleGroup.RuleGroupProperty(
            rule_variables=None,
            rules_source=netfw.CfnRuleGroup.RulesSourceProperty(
                stateless_rules_and_custom_actions=netfw.CfnRuleGroup.StatelessRulesAndCustomActionsProperty(
                    stateless_rules=[
                        netfw.CfnRuleGroup.StatelessRuleProperty(
                            priority=10,
                            rule_definition=netfw.CfnRuleGroup.RuleDefinitionProperty(
                                actions=["aws:forward_to_sfe"],
                                match_attributes=netfw.CfnRuleGroup.MatchAttributesProperty(
                                    destination_ports=[
                                        netfw.CfnRuleGroup.PortRangeProperty(
                                            from_port=80,
                                            to_port=80
                                        ),
                                        netfw.CfnRuleGroup.PortRangeProperty(
                                            from_port=443,
                                            to_port=443
                                        )
                                    ],
                                    destinations=[
                                        netfw.CfnRuleGroup.AddressProperty(
                                            address_definition=('0.0.0.0/0')
                                        ),
                                        # netfw.CfnRuleGroup.AddressesProperty(
                                        #     addresses=('::/0')
                                        # ),
                                    ],
                                    sources=[
                                        netfw.CfnRuleGroup.AddressProperty(
                                            address_definition=('0.0.0.0/0')
                                        ),
                                        # netfw.CfnRuleGroup.AddressesProperty(
                                        #     addresses=core.Fn.select(
                                        #         0,
                                        #         self.vpc.vpc_ipv6_cidr_blocks
                                        #     )
                                        # )
                                    ],
                                    source_ports=[
                                        netfw.CfnRuleGroup.PortRangeProperty(
                                            from_port=0,
                                            to_port=65535
                                        )
                                    ],
                                    protocols=[6,17]
                                )
                            )
                        ),
                        netfw.CfnRuleGroup.StatelessRuleProperty(
                            priority=15,
                            rule_definition=netfw.CfnRuleGroup.RuleDefinitionProperty(
                                actions=["aws:pass"],
                                match_attributes=netfw.CfnRuleGroup.MatchAttributesProperty(
                                    destinations=[
                                        netfw.CfnRuleGroup.AddressProperty(
                                            address_definition=('0.0.0.0/0')
                                        ),
                                        # netfw.CfnRuleGroup.AddressesProperty(
                                        #     addresses=('::/0')
                                        # ),
                                    ],
                                    sources=[
                                        netfw.CfnRuleGroup.AddressProperty(
                                            address_definition=('0.0.0.0/0')
                                        ),
                                        # netfw.CfnRuleGroup.AddressesProperty(
                                        #     addresses=core.Fn.select(
                                        #         0,
                                        #         self.vpc.vpc_ipv6_cidr_blocks
                                        #     )
                                        # )
                                    ]
                                )
                            )
                        )
                    ]
                )
            )
        )
        self.netfwstatefulrulegrp = netfw.CfnRuleGroup.RuleGroupProperty(
            rule_variables=None,
            rules_source=netfw.CfnRuleGroup.RulesSourceProperty(
                rules_source_list=netfw.CfnRuleGroup.RulesSourceListProperty(
                    generated_rules_type='DENYLIST',
                    targets=[
                        '.google',
                        '.google.com'
                    ],
                    target_types=[
                        'HTTP_HOST',
                        'TLS_SNI'
                    ]
                )
            )
        )
        # create rule group Stateless
        self.netfwrulegrpstateless = netfw.CfnRuleGroup(
            self,
            f"{construct_id}MyNetFWRuleGrpStateless",
            capacity=netfwrlgrpcap,
            rule_group_name=(
                f"{construct_id}MyNetFWRuleGrpStateless"
            ),
            type=(
                "STATELESS"
            ),
            description=(
                "Stateless Rule Group"
            ),
            rule_group=self.netfwstatelessrulegrp
        )
        core.CfnOutput(
            self,
            f"{construct_id}OutNetFwStatelessGrp",
            value=self.netfwrulegrpstateless.attr_rule_group_arn,
            export_name=f"{construct_id}-NetFwStatelessGrp"
        )
        # create rule group Stateful
        self.netfwrulegrpstateful = netfw.CfnRuleGroup(
            self,
            f"{construct_id}MyNetFWRuleGrpStateful",
            capacity=netfwrlgrpcap,
            rule_group_name=(
                f"{construct_id}MyNetFWRuleGrpStateful"
            ),
            type=(
                "STATEFUL"
            ),
            description=(
                "Stateful Rule Group"
            ),
            rule_group=self.netfwstatefulrulegrp
        )
        core.CfnOutput(
            self,
            f"{construct_id}OutNetFwStatefulGrp",
            value=self.netfwrulegrpstateful.attr_rule_group_arn,
            export_name=f"{construct_id}-NetFwStatefulGrp"
        )
        #create firewall policy
        self.netfwspolicy = netfw.CfnFirewallPolicy(
			self,
            f"{construct_id}NetworkFirewallPolicy",
			firewall_policy_name=f"{construct_id}NetworkFirewallPolicy",
			firewall_policy=netfw.CfnFirewallPolicy.FirewallPolicyProperty(
                stateless_default_actions=["aws:forward_to_sfe"], 
                stateless_fragment_default_actions=["aws:forward_to_sfe"],
                stateless_rule_group_references=[
                    netfw.CfnFirewallPolicy.StatelessRuleGroupReferenceProperty(
                        priority=10,
                        resource_arn=self.netfwrulegrpstateless.attr_rule_group_arn
                    )
                ],
                stateful_rule_group_references=[
                    netfw.CfnFirewallPolicy.StatefulRuleGroupReferenceProperty(
                        resource_arn=self.netfwrulegrpstateful.attr_rule_group_arn
                    )
                ]
            )
        )
        self.netfwspolicy.add_property_override('FirewallPolicy.StatelessDefaultActions', ["aws:forward_to_sfe"])
        self.netfwspolicy.add_property_override('FirewallPolicy.StatelessFragmentDefaultActions', ["aws:forward_to_sfe"])

        core.CfnOutput(
            self,
            f"{construct_id}OutNetworkFirewallPolicy",
            value=self.netfwspolicy.attr_firewall_policy_arn,
            export_name=f"{construct_id}-NetworkFirewallPolicy"
        )
        # create network-firewall
        self.netfirewall = netfw.CfnFirewall(
            self,
            f"{construct_id}MyNetFW",
            firewall_name=f"{construct_id}MyNetFW",
            firewall_policy_arn=self.netfwspolicy.attr_firewall_policy_arn,
            subnet_mappings=[
                netfw.CfnFirewall.SubnetMappingProperty(
                    subnet_id = subnet_id
                ) for subnet_id in self.vpc.select_subnets(
                    subnet_group_name='InternetOut'
                ).subnet_ids
            ],
            vpc_id=self.vpc.vpc_id,
            delete_protection=False,
            description=f"My Firewall-{region}",
            firewall_policy_change_protection=False,
            subnet_change_protection=False,
        )
        core.CfnOutput(
            self,
            f"{construct_id}OutNetworkFirewallId",
            value=self.netfirewall.attr_firewall_id,
            export_name=f"{construct_id}-NetworkFirewallId"
        )
        core.CfnOutput(
            self,
            f"{construct_id}OutNetworkFirewallArn",
            value=self.netfirewall.attr_firewall_arn,
            export_name=f"{construct_id}-NetworkFirewallArn"
        )
        # # create route table for incoming traffic
        # self.incomingrt = ec2.CfnRouteTable(
        #     self,
        #     f"{construct_id}IncomeRouteTable",
        #     vpc_id=self.vpc.vpc_id
        # )
        # # edge association
        # ec2.CfnGatewayRouteTableAssociation(
        #     self,
        #     f"{construct_id}IncomeRouteTableAssociation",
        #     gateway_id=self.vpc.internet_gateway_id,
        #     route_table_id=self.incomingrt.ref
        # )

        endpointlist = self.netfirewall.attr_endpoint_ids
        index = 0
        while index <= (len(endpointlist) + 1):
            fwendpoint_az = core.Fn.select(0, core.Fn.split(":", core.Fn.select(index, self.netfirewall.attr_endpoint_ids)))
            fwendpoint_id = core.Fn.select(1, core.Fn.split(":", core.Fn.select(index, self.netfirewall.attr_endpoint_ids)))
            core.CfnOutput(
                self,
                f"{construct_id}OutNetwFwEnd-{index}",
                value=f"{fwendpoint_id}:{fwendpoint_az}",
                export_name=f"NetwFwEnd{index}"
            ).override_logical_id(new_logical_id=f"fwendpoint{index}")
            index = index + 1

