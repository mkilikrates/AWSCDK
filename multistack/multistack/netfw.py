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
        self.ipv4internetfwrule = netfw.CfnRuleGroup.StatelessRuleProperty(
            priority=10,
            rule_definition=netfw.CfnRuleGroup.RuleDefinitionProperty(
                actions=(
                    "aws:forward_to_sfe"
                ),
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
                        netfw.CfnRuleGroup.AddressesProperty(
                            addresses=('0.0.0.0/0')
                        )
                    ],
                    protocols=[
                        6
                    ],
                    source_ports=[
                        netfw.CfnRuleGroup.PortRangeProperty(
                            from_port=0,
                            to_port=65535
                        ),
                    ],
                    sources=[
                        netfw.CfnRuleGroup.AddressesProperty(
                            addresses=vpc.vpc_cidr_block_associations
                        )
                    ]
                )
            )
        )
        self.ipv6internetfwrule = netfw.CfnRuleGroup.StatelessRuleProperty(
            priority=15,
            rule_definition=netfw.CfnRuleGroup.RuleDefinitionProperty(
                actions=(
                    "aws:forward_to_sfe"
                ),
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
                        netfw.CfnRuleGroup.AddressesProperty(
                            addresses=('::/0')
                        )
                    ],
                    protocols=[
                        6
                    ],
                    source_ports=[
                        netfw.CfnRuleGroup.PortRangeProperty(
                            from_port=0,
                            to_port=65535
                        ),
                    ],
                    sources=[
                        netfw.CfnRuleGroup.AddressesProperty(
                            addresses=vpc.vpc_cidr_block_associations
                        )
                    ]
                )
            )
        )
        # create rule group
        self.netfwrulegrpstateless = netfw.CfnRuleGroup(
            self,
            f"{construct_id}:MyNetFWRuleGrpStateless",
            capacity=netfwrlgrpcap,
            rule_group_name=(
                f"{construct_id}:MyNetFWRuleGrpStateless"
            ),
            type=(
                "STATELESS"
            ),
            description=(
                "Stateless Rule Group"
            ),
            #rule_group=netfw.CfnRuleGroup.RulesSourceProperty(
            #    stateless_rules_and_custom_actions=netfw.CfnRuleGroup.StatelessRulesAndCustomActionsProperty(
            #        stateless_rules=[
            #            self.ipv4internetfwrule
            #        ],
            #        custom_actions=None
            #    )
            #)
        )
        core.CfnOutput(
            self,
            f"{construct_id}:OutMyNetFWRuleGrpStateless",
            value=self.netfwrulegrpstateless.attr_rule_group_arn,
            export_name=f"{construct_id}:MyNetFWRuleGrpStateless"
        )
        
        self.netfwspolicy = netfw.CfnFirewallPolicy(
            self,
            f"{construct_id}:MyNetFWPol",
            firewall_policy_name=f"{construct_id}:MyNetFWPol",
            description='My test Policy',
            firewall_policy=netfw.CfnFirewallPolicy.FirewallPolicyProperty(
                stateless_rule_group_references=[self.netfwrulegrpstateless.attr_rule_group_arn],
                stateless_default_actions=["aws:pass"],
                stateless_fragment_default_actions=["aws:pass"],
                stateful_rule_group_references=[self.netfwrulegrpstateful.attr_rule_group_arn],
            )
        )