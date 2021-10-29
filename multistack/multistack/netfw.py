import os
import json
import logging
from aws_cdk import (
    aws_ec2 as ec2,
    aws_networkfirewall as netfw,
    aws_lambda as lambda_,
    aws_lambda_python as lpython,
    aws_iam as iam,
    aws_logs as log,
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
    def __init__(self, scope: core.Construct, construct_id: str, res, ipstack, vpcname = str, vpcstackname = str, vpc = ec2.Vpc, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.vpc = vpc
        self.ipstack = ipstack
        netfwrlgrpcap = 100
        # get config for resource
        res = res
        resname = resmap['Mappings']['Resources'][res]['NAME']
        ressubgrp = resmap['Mappings']['Resources'][res]['SUBNETGRP']
        if 'INTNTIN' in resmap['Mappings']['Resources'][res]:
            resincoming = resmap['Mappings']['Resources'][res]['INTNTIN']
        else:
            resincoming = False
        if 'LOGS' in resmap['Mappings']['Resources'][res]:
            reslogs = resmap['Mappings']['Resources'][res]['LOGS']
        else:
            reslogs = ''
        # create stateless rulegroup
        if 'STATELESSGRP' in resmap['Mappings']['Resources'][res]:
            stateless_rule_group_references = []
            rule_pri = 10
            for statelessname in resmap['Mappings']['Resources'][res]['STATELESSGRP']:
                mystatelessrulelst = []
                for rule in resmap['Mappings']['Resources'][statelessname]['Rules']:
                    mystatelessruleatt = {}
                    if 'SRC' in rule:
                        sources = []
                        src = rule['SRC']
                        if type(src) == str:
                            if src == 'VPC':
                                sources.append(netfw.CfnRuleGroup.AddressProperty(address_definition=(self.vpc.vpc_cidr_block)))
                            else:
                                sources.append(netfw.CfnRuleGroup.AddressProperty(address_definition=(src)))
                        else:
                            for rulesrc in rule['SRC']:
                                sources.append(netfw.CfnRuleGroup.AddressProperty(address_definition=(rulesrc)))
                        mystatelessruleatt['sources'] = sources
                    if 'SRCPT' in rule:
                        srcpt = rule['SRCPT']
                        source_ports = []
                        if type(srcpt) == str:
                            if '-' in srcpt:
                                pt = srcpt.split('-')
                                source_ports.append(netfw.CfnRuleGroup.PortRangeProperty(from_port=int(pt[0]), to_port=int(pt[1])))
                            else:
                                source_ports.append(netfw.CfnRuleGroup.PortRangeProperty(from_port=int(srcpt), to_port=int(srcpt)))
                        else:
                            for srcpt in rule['SRCPT']:
                                if '-' in srcpt:
                                    pt = srcpt.split('-')
                                    source_ports.append(netfw.CfnRuleGroup.PortRangeProperty(from_port=int(pt[0]), to_port=int(pt[1])))
                                else:
                                    source_ports.append(netfw.CfnRuleGroup.PortRangeProperty(from_port=int(srcpt), to_port=int(srcpt)))
                        mystatelessruleatt['source_ports'] = source_ports
                    if 'DST' in rule:
                        destinations = []
                        dst = rule['DST']
                        if type(dst) == str:
                            if dst == 'VPC':
                                destinations.append(netfw.CfnRuleGroup.AddressProperty(address_definition=(self.vpc.vpc_cidr_block)))
                            else:
                                destinations.append(netfw.CfnRuleGroup.AddressProperty(address_definition=(dst)))
                        else:
                            for ruledst in rule['DST']:
                                destinations.append(netfw.CfnRuleGroup.AddressProperty(address_definition=(ruledst)))
                        mystatelessruleatt['destinations'] = destinations
                    if 'DSTPT' in rule:
                        dstpt = rule['DSTPT']
                        destination_ports = []
                        if type(dstpt) == str:
                            if '-' in dstpt:
                                pt = dstpt.split('-')
                                destination_ports.append(netfw.CfnRuleGroup.PortRangeProperty(from_port=int(pt[0]), to_port=int(pt[1])))
                            else:
                                destination_ports.append(netfw.CfnRuleGroup.PortRangeProperty(from_port=int(dstpt), to_port=int(dstpt)))
                        else:
                            for dstpt in rule['DSTPT']:
                                if '-' in dstpt:
                                    pt = dstpt.split('-')
                                    destination_ports.append(netfw.CfnRuleGroup.PortRangeProperty(from_port=int(pt[0]), to_port=int(pt[1])))
                                else:
                                    destination_ports.append(netfw.CfnRuleGroup.PortRangeProperty(from_port=int(dstpt), to_port=int(dstpt)))
                        mystatelessruleatt['destination_ports'] = destination_ports
                    if 'PROTO' in rule:
                        protocols = []
                        if type(rule['PROTO']) == int:
                                protocols.append(rule['PROTO'])
                        else:
                            for proto in rule['PROTO']:
                                protocols.append(proto)
                        mystatelessruleatt['protocols'] = protocols
                    if 'TFLAGS' in rule:
                        tcp_flags = rule['TFLAGS']
                        mystatelessruleatt['tcp_flags'] = tcp_flags
                    mystatelessrulelst.append(netfw.CfnRuleGroup.StatelessRuleProperty(
                        priority= rule['PRI'],
                        rule_definition=netfw.CfnRuleGroup.RuleDefinitionProperty(
                            actions=[rule['Actions']],
                            match_attributes=netfw.CfnRuleGroup.MatchAttributesProperty(**mystatelessruleatt)
                            )
                        )
                    )
                self.netfwstatelessrulegrp = netfw.CfnRuleGroup.RuleGroupProperty(
                    rule_variables=None,
                    rules_source=netfw.CfnRuleGroup.RulesSourceProperty(
                        stateless_rules_and_custom_actions=netfw.CfnRuleGroup.StatelessRulesAndCustomActionsProperty(
                            stateless_rules=mystatelessrulelst
                        )
                    )
                )
                self.netfwrulegrpstateless = netfw.CfnRuleGroup(
                    self,
                    f"{construct_id}{statelessname}",
                    capacity=netfwrlgrpcap,
                    rule_group_name=f"{construct_id}{statelessname}",
                    type="STATELESS",
                    description=f"Stateless Rule Group {statelessname}",
                    rule_group=self.netfwstatelessrulegrp
                )
                core.CfnOutput(
                    self,
                    f"{construct_id}Out{statelessname}",
                    value=self.netfwrulegrpstateless.attr_rule_group_arn,
                    export_name=f"{construct_id}-{statelessname}"
                )
                stateless_rule_group_references.append(netfw.CfnFirewallPolicy.StatelessRuleGroupReferenceProperty(priority=rule_pri, resource_arn=self.netfwrulegrpstateless.attr_rule_group_arn))
                rule_pri = rule_pri + 10
        # create stateful rulegroup
        if 'STATEFULGRP' in resmap['Mappings']['Resources'][res]:
            stateful_rule_group_references = []
            for statefulname in resmap['Mappings']['Resources'][res]['STATEFULGRP']:
                if 'IPSET' in resmap['Mappings']['Resources'][statefulname]:
                    mystatefulipset = {}
                    for ipset in resmap['Mappings']['Resources'][statefulname]['IPSET']:
                        ipsetvar = ipset['VARIABLE']
                        if ipset['DEFINITION'] == 'VPC':
                            definition = [self.vpc.vpc_cidr_block]
                        else:
                            definition = ipset['DEFINITION']
                        mystatefulipset[ipsetvar] = {"Definition" : definition}
                    # myrulevariable = netfw.CfnRuleGroup.IPSetProperty(ipsetvar, definition=definition)
                    myrulevariable = netfw.CfnRuleGroup.RuleVariablesProperty(ip_sets=mystatefulipset)
                else:
                    myrulevariable = None
                # until fix
                myrulevariable = {}
                if 'DOMAINALLOW' in resmap['Mappings']['Resources'][statefulname]:
                    resdomainallow = resmap['Mappings']['Resources'][statefulname]['DOMAINALLOW']
                else:
                    resdomainallow = ''
                if 'DOMAINDENY' in resmap['Mappings']['Resources'][statefulname]:
                    resdomaindeny = resmap['Mappings']['Resources'][statefulname]['DOMAINDENY']
                else:
                    resdomaindeny = ''
                if resdomaindeny != '':
                    self.netfwstatefulrulegrpdomain = netfw.CfnRuleGroup.RuleGroupProperty(
                        rule_variables=myrulevariable,
                        rules_source=netfw.CfnRuleGroup.RulesSourceProperty(
                            rules_source_list=netfw.CfnRuleGroup.RulesSourceListProperty(
                                generated_rules_type='DENYLIST',
                                targets=resdomaindeny,
                                target_types=[
                                    'HTTP_HOST',
                                    'TLS_SNI'
                                ]
                            )
                        )
                    )
                    self.netfwrulegrpstatefuldomain = netfw.CfnRuleGroup(
                        self,
                        f"{construct_id}MyNetFWRuleGrpStatefulDomainDeny",
                        capacity=netfwrlgrpcap,
                        rule_group_name=f"{construct_id}MyNetFWRuleGrpStatefulDomainDeny",
                        type="STATEFUL",
                        description="Stateful Rule Group Domain Deny",
                        rule_group=self.netfwstatefulrulegrpdomain
                    )
                    # add rule group to police
                    stateful_rule_group_references.append(netfw.CfnFirewallPolicy.StatefulRuleGroupReferenceProperty(resource_arn=self.netfwrulegrpstatefuldomain.attr_rule_group_arn))
                    if 'IPSET' in resmap['Mappings']['Resources'][statefulname]:
                        self.netfwrulegrpstatefuldomain.add_property_override("RuleGroup.RuleVariables.IPSets", mystatefulipset)

                    core.CfnOutput(
                        self,
                        f"{construct_id}OutNetFwStatefulGrpDomainDeny",
                        value=self.netfwrulegrpstatefuldomain.attr_rule_group_arn,
                        export_name=f"{construct_id}-NetFwStatefulGrpDomainDeny"
                    )
                elif resdomainallow != '':
                    self.netfwstatefulrulegrpdomain = netfw.CfnRuleGroup.RuleGroupProperty(
                        rule_variables=myrulevariable,
                        rules_source=netfw.CfnRuleGroup.RulesSourceProperty(
                            rules_source_list=netfw.CfnRuleGroup.RulesSourceListProperty(
                                generated_rules_type='ALLOWLIST',
                                targets=resdomainallow,
                                target_types=[
                                    'HTTP_HOST',
                                    'TLS_SNI'
                                ]
                            )
                        )
                    )
                    self.netfwrulegrpstatefuldomain = netfw.CfnRuleGroup(
                        self,
                        f"{construct_id}MyNetFWRuleGrpStatefulDomainAllow",
                        capacity=netfwrlgrpcap,
                        rule_group_name=f"{construct_id}MyNetFWRuleGrpStatefulDomainAllow",
                        type="STATEFUL",
                        description="Stateful Rule Group Domain Allow",
                        rule_group=self.netfwstatefulrulegrpdomain
                    )
                    core.CfnOutput(
                        self,
                        f"{construct_id}OutNetFwStatefulGrpDomainAllow",
                        value=self.netfwrulegrpstatefuldomain.attr_rule_group_arn,
                        export_name=f"{construct_id}-NetFwStatefulGrpDomainAlow"
                    )
                    # add rule group to police
                    stateful_rule_group_references.append(netfw.CfnFirewallPolicy.StatefulRuleGroupReferenceProperty(resource_arn=self.netfwrulegrpstatefuldomain.attr_rule_group_arn))
                    if 'IPSET' in resmap['Mappings']['Resources'][statefulname]:
                        self.netfwrulegrpstatefuldomain.add_property_override("RuleGroup.RuleVariables.IPSets", mystatefulipset)
                if 'Rules' in resmap['Mappings']['Resources'][statefulname]:
                    mystatefulrulelst = []
                    ruleindex = 1
                    for rule in resmap['Mappings']['Resources'][statefulname]['Rules']:
                        mystatefulrulelst.append(netfw.CfnRuleGroup.StatefulRuleProperty(
                            action=rule['Actions'],
                            header=netfw.CfnRuleGroup.HeaderProperty(
                                destination=rule['DST'],
                                destination_port=rule['DSTPT'],
                                direction=rule['DIR'],
                                protocol=rule['PROTO'],
                                source=rule['SRC'],
                                source_port=rule['SRCPT']
                            ),
                            rule_options=[netfw.CfnRuleGroup.RuleOptionProperty(
                                keyword=f"sid:{ruleindex}"
                            )]
                        ))
                        ruleindex = ruleindex + 1
                    self.netfwstatefulrulegrphd = netfw.CfnRuleGroup.RuleGroupProperty(
                        rule_variables=None,
                        rules_source=netfw.CfnRuleGroup.RulesSourceProperty(
                            stateful_rules=mystatefulrulelst
                        )
                    )
                    self.netfwrulegrpstatefulhd = netfw.CfnRuleGroup(
                        self,
                        f"{construct_id}MyNetFWRuleGrpStatefulHeader",
                        capacity=netfwrlgrpcap,
                        rule_group_name=f"{construct_id}MyNetFWRuleGrpStatefulHeader",
                        type="STATEFUL",
                        description="Stateful Rule Group Header Rules",
                        rule_group=self.netfwstatefulrulegrphd
                    )
                    core.CfnOutput(
                        self,
                        f"{construct_id}OutNetFwStatefulGrpHeader",
                        value=self.netfwrulegrpstatefulhd.attr_rule_group_arn,
                        export_name=f"{construct_id}-NetFwStatefulGrpHeader"
                    )
                    # add rule group to police
                    stateful_rule_group_references.append(netfw.CfnFirewallPolicy.StatefulRuleGroupReferenceProperty(resource_arn=self.netfwrulegrpstatefulhd.attr_rule_group_arn))
                    if 'IPSET' in resmap['Mappings']['Resources'][statefulname]:
                        self.netfwrulegrpstatefulhd.add_property_override("RuleGroup.RuleVariables.IPSets", mystatefulipset)
        else:
            stateful_rule_group_references = None
        # create a lambda to deal with NetFW Endpoint routes
        # create Police for lambda function
        self.mylambdapolicy = iam.PolicyStatement(
            actions=[
                "ec2:DescribeSubnets",
                "ec2:DescribeRouteTables",
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:DescribeLogGroups",
                "logs:DescribeLogStreams",
                "logs:PutLogEvents"
            ],
            resources=["*"],
            effect=iam.Effect.ALLOW
        )
        self.mylambdarole = iam.Role(
            self,
            "LambdaRole",
            assumed_by=iam.ServicePrincipal(
                'lambda.amazonaws.com'
            ),
            description=(
                'Role for Lambda to Get VPC Route table as Custom Resources in CloudFormation'
            )
        )
        self.mylambdarole.add_to_policy(self.mylambdapolicy)
        # Create Lambda Function
        self.mylambda = lpython.PythonFunction(
            self,
            f"{construct_id}:Lambda",
            handler="lambda_handler",
            timeout=core.Duration.seconds(90),
            runtime=lambda_.Runtime.PYTHON_3_8,
            description="Lambda to Get VPC Route table as Custom Resources in CloudFormation",
            entry="lambda/GetSubnetRT/",
            role=(self.mylambdarole),
            log_retention=log.RetentionDays.ONE_WEEK
        )
        #create firewall policy
        self.netfwspolicy = netfw.CfnFirewallPolicy(
			self,
            f"{construct_id}NetworkFirewallPolicy",
			firewall_policy_name=f"{construct_id}NetworkFirewallPolicy",
			firewall_policy=netfw.CfnFirewallPolicy.FirewallPolicyProperty(
                stateless_default_actions=["aws:forward_to_sfe"], 
                stateless_fragment_default_actions=["aws:forward_to_sfe"],
                stateless_rule_group_references=stateless_rule_group_references,
                stateful_rule_group_references=stateful_rule_group_references
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
            firewall_name=resname,
            firewall_policy_arn=self.netfwspolicy.attr_firewall_policy_arn,
            subnet_mappings=[
                netfw.CfnFirewall.SubnetMappingProperty(
                    subnet_id = subnet_id
                ) for subnet_id in self.vpc.select_subnets(
                    subnet_group_name=ressubgrp
                ).subnet_ids
            ],
            vpc_id=self.vpc.vpc_id,
            delete_protection=False,
            description=f"My Firewall-{region}",
            firewall_policy_change_protection=False,
            subnet_change_protection=False,
        )
        # enable logs
        if reslogs != '':
            mylogdstcfg = []
            for logcfg in reslogs:
                if 'logGroup' in logcfg['LogDestination']:
                    netfwloggroup = log.LogGroup(
                        self,
                        logcfg['LogDestination']['logGroup'],
                        retention=log.RetentionDays.ONE_WEEK
                    )
                mylogdstcfg.append(netfw.CfnLoggingConfiguration.LogDestinationConfigProperty(
                    log_destination={"logGroup": netfwloggroup.log_group_name},
                    log_destination_type="CloudWatchLogs",
                    log_type=logcfg['LogType']
                ))
            netfw.CfnLoggingConfiguration(
                self,
                f"{construct_id}MyNetFWLogs",
                firewall_arn=self.netfirewall.attr_firewall_arn,
                logging_configuration=netfw.CfnLoggingConfiguration.LoggingConfigurationProperty(
                    log_destination_configs=mylogdstcfg,
                ),
                firewall_name=resname
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
        if resincoming == True:
            # create route table for incoming traffic
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

        endpointlist = self.netfirewall.attr_endpoint_ids
        index = 0
        while index <= (len(endpointlist)+1):
            fwendpoint_az = core.Fn.select(0, core.Fn.split(":", core.Fn.select(index, self.netfirewall.attr_endpoint_ids)))
            fwendpoint_id = core.Fn.select(1, core.Fn.split(":", core.Fn.select(index, self.netfirewall.attr_endpoint_ids)))
            core.CfnOutput(
                self,
                f"{construct_id}OutNetwFwEnd-{index}",
                value=f"{fwendpoint_id}:{fwendpoint_az}",
                export_name=f"NetwFwEnd{index}"
            ).override_logical_id(new_logical_id=f"fwendpoint{index}")
            for subtype in resmap['Mappings']['Resources'][vpcname]['SUBNETS']:
                for each in subtype:
                    for sub in subtype[each]:
                        subname = sub['NAME']
                        if 'NETFWRT' in sub or 'NETFWINC' in sub or 'NETFWSUB' in sub:
                            # Get RTid
                            self.mycustomresource = core.CustomResource(
                                self,
                                f"{construct_id}:GetSubnetRT{each}{subname}{index}",
                                service_token=self.mylambda.function_arn,
                                properties=[
                                    {
                                        "vpc-id" : self.vpc.vpc_id,
                                        "availability-zone" : fwendpoint_az,
                                        "subnet-name" : subname,
                                    }
                                ]
                            )
                            if 'NETFWRT' in sub:
                                idx = 0
                                for rt in sub['NETFWRT']:
                                    ec2.CfnRoute(
                                        self,
                                        f"RTToVPCEnd{index}{each}-{subname}{idx}",
                                        route_table_id=self.mycustomresource.get_att_string("RouteTableId"),
                                        vpc_endpoint_id=fwendpoint_id,
                                        destination_cidr_block=rt
                                    )
                                    idx = idx + 1
                            if 'NETFWINC' in sub and resincoming == True:
                                ec2.CfnRoute(
                                    self,
                                    f"IncomingToVPCEnd{index}{each}-{subname}",
                                    route_table_id=self.incomingrt.ref,
                                    vpc_endpoint_id=fwendpoint_id,
                                    destination_cidr_block=self.mycustomresource.get_att_string("CidrBlock")
                                )
                            if 'NETFWSUB' in sub:
                                idx = 0
                                sb = ec2.SubnetType.PUBLIC
                                idx2 = 0
                                for subnet_id in self.vpc.select_subnets(subnet_type=sb).subnets:
                                    if self.mycustomresource.get_att_string("CidrBlock") != subnet_id.ipv4_cidr_block:
                                        ec2.CfnRoute(
                                            self,
                                            f"RTLocalSubToVPCEnd{index}{each}-{subname}-{idx}-{idx2}",
                                            route_table_id=self.mycustomresource.get_att_string("RouteTableId"),
                                            vpc_endpoint_id=fwendpoint_id,
                                            destination_cidr_block=subnet_id.ipv4_cidr_block
                                        )
                                        idx2 = idx2 + 1
                                sb = ec2.SubnetType.PRIVATE
                                for subnet_id in self.vpc.select_subnets(subnet_type=sb).subnets:
                                    if self.mycustomresource.get_att_string("CidrBlock") != subnet_id.ipv4_cidr_block:
                                        ec2.CfnRoute(
                                            self,
                                            f"RTLocalSubToVPCEnd{index}{each}-{subname}-{idx}-{idx2}",
                                            route_table_id=self.mycustomresource.get_att_string("RouteTableId"),
                                            vpc_endpoint_id=fwendpoint_id,
                                            destination_cidr_block=subnet_id.ipv4_cidr_block
                                        )
                                        idx2 = idx2 + 1
                                sb = ec2.SubnetType.ISOLATED
                                for subnet_id in self.vpc.select_subnets(subnet_type=sb).subnets:
                                    if self.mycustomresource.get_att_string("CidrBlock") != subnet_id.ipv4_cidr_block:
                                        ec2.CfnRoute(
                                            self,
                                            f"RTLocalSubToVPCEnd{index}{each}-{subname}-{idx}-{idx2}",
                                            route_table_id=self.mycustomresource.get_att_string("RouteTableId"),
                                            vpc_endpoint_id=fwendpoint_id,
                                            destination_cidr_block=subnet_id.ipv4_cidr_block
                                        )
                                        idx2 = idx2 + 1
                                    idx = idx + 1
            index = index + 1

