import os
import json
import aws_cdk.core as core
import aws_cdk.aws_ec2 as ec2
import aws_cdk.aws_route53resolver as route53resolver
import aws_cdk.aws_logs as log
import aws_cdk.aws_iam as iam
import aws_cdk.aws_directoryservice as ds
account = core.Aws.ACCOUNT_ID
region = core.Aws.REGION
resconf = "resourcesmap.cfg"
with open(resconf) as resfile:
    resmap = json.load(resfile)
class rslv(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, res, preflst, allowall, ipstack, dsid = ds.CfnMicrosoftAD, vpc = ec2.Vpc, allowsg = ec2.SecurityGroup, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.vpc = vpc
        self.ipstack = ipstack
        # get data for rds resource
        res = res
        resname = resmap['Mappings']['Resources'][res]['NAME']
        restype = resmap['Mappings']['Resources'][res]['Type']
        ressubgrp = resmap['Mappings']['Resources'][res]['SUBNETGRP']

        # create security group for bastion
        self.r53rslvsg = ec2.SecurityGroup(
            self,
            f"{self.stack_name}SG",
            allow_all_outbound=True,
            vpc=self.vpc
        )
        # add ingress rule
        if allowsg != '':
            self.r53rslvsg.add_ingress_rule(
                self.allowsg,
                ec2.Port.all_traffic()
            )
        if preflst == True:
            # get prefix list from file to allow traffic from the office
            with open('zonemap.cfg') as zonefile:
                zonemap = json.load(zonefile)
            self.map = core.CfnMapping(
                self,
                f"{construct_id}Map",
                mapping=zonemap["Mappings"]["RegionMap"]
            )
            srcprefix = self.map.find_in_map(core.Aws.REGION, 'PREFIXLIST')
            self.r53rslvsg.add_ingress_rule(
                ec2.Peer.prefix_list(srcprefix),
                ec2.Port.all_traffic()
            )
        if allowall == True:
            self.r53rslvsg.add_ingress_rule(
                ec2.Peer.any_ipv4,
                ec2.Port.all_traffic()
            )
            if self.ipstack == 'Ipv6':
                self.r53rslvsg.add_ingress_rule(
                    ec2.Peer.any_ipv6,
                    ec2.Port.all_traffic()
                )
        if type(allowall) == int or type(allowall) == float:
            self.r53rslvsg.add_ingress_rule(
                ec2.Peer.any_ipv4(),
                ec2.Port.tcp(allowall)
            )
            self.r53rslvsg.add_ingress_rule(
                ec2.Peer.any_ipv4(),
                ec2.Port.udp(allowall)
            )
            if self.ipstack == 'Ipv6':
                self.r53rslvsg.add_ingress_rule(
                    ec2.Peer.any_ipv6(),
                    ec2.Port.tcp(allowall)
                )
                self.r53rslvsg.add_ingress_rule(
                    ec2.Peer.any_ipv6(),
                    ec2.Port.udp(allowall)
                )
        if 'ISG' in resmap['Mappings']['Resources'][res]:
            for rule in resmap['Mappings']['Resources'][res]['ISG']:
                if 'SRC' in rule:
                    if rule['SRC'] == 'VPC':
                        src = self.vpc.vpc_cidr_block
                    else:
                        src = rule['SRC']
                    peer = ec2.Peer.ipv4(cidr_ip=src)
                if 'SRCv6' in rule:
                    if rule['SRCv6'] == 'VPC':
                        src = core.Fn.select(0, self.vpc.vpc_ipv6_cidr_blocks)
                    else:
                        src = rule['SRCv6']
                    peer = ec2.Peer.ipv6(cidr_ip=src)
                if 'PROTO' in rule:
                    if rule['PROTO'] == 'udp':
                        if 'PORT'in rule:
                            if '-' in rule['PORT']:
                                port = rule['PORT'].split('-')
                                conn = ec2.Port.udp_range(start_port=int(port[0]),end_port=int(port[1]))
                            else:
                                port = rule['PORT']
                                conn = ec2.Port.udp(int(port))
                        else:
                            conn = ec2.Port.all_udp()
                    elif rule['PROTO'] == 'tcp':
                        if 'PORT'in rule:
                            if '-' in rule['PORT']:
                                port = rule['PORT'].split('-')
                                conn = ec2.Port.tcp_range(start_port=int(port[0]),end_port=int(port[1]))
                            else:
                                port = rule['PORT']
                                conn = ec2.Port.tcp(int(port))
                        else:
                            conn = ec2.Port.all_tcp()
                    elif rule['PROTO'] == 'icmp' or rule['PROTO'] == 'icmpv6':
                        if 'PORT'in rule:
                            if rule['PORT'] == '-1':
                                conn = ec2.Port.all_icmp()
                            elif '-' in rule['PORT']:
                                port = rule['PORT'].split('-')
                                if 'SRC' in rule:
                                    conn = ec2.Port.icmp_type_and_code(type=port[0],code=port[1])
                            else:
                                port = rule['PORT']
                                conn = ec2.Port.icmp_type(int(port))
                        else:
                            conn = ec2.Port.all_icmp()
                    else:
                        proto = rule['PROTO']
                        conn = ec2.Protocol(proto)
                else:
                    conn = ec2.Port.all_traffic()
                self.r53rslvsg.add_ingress_rule(
                    peer=peer,
                    connection=conn
                )
        self.r53rslv = route53resolver.CfnResolverEndpoint(
            self,
            f"Route53endpoint{self.stack_name}",
            direction=restype,
            ip_addresses=[
                route53resolver.CfnResolverEndpoint.IpAddressRequestProperty(
                    subnet_id = subnet_id
                ) for subnet_id in self.vpc.select_subnets(
                    subnet_group_name=ressubgrp
                ).subnet_ids
            ],
            security_group_ids=[self.r53rslvsg.security_group_id],
            name=resname
        )

        if 'LOGS' in resmap['Mappings']['Resources'][res]:
            for logg in resmap['Mappings']['Resources'][res]['LOGS']:
                if logg['LogDestinationType'] == 'CloudWatchLogs':
                    # Log Group for Resolver Query Logs
                    self.r53rslvloggroup = log.LogGroup(
                        self,
                        f"{self.stack_name}:R53LogsGroup",
                        retention=log.RetentionDays.ONE_WEEK
                    )
                    self.r53rslvlogpolicy = iam.PolicyStatement(
                        actions=[
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:DescribeLogGroups",
                            "logs:DescribeLogStreams",
                            "logs:PutLogEvents"
                        ],
                        effect=iam.Effect.ALLOW,
                    )
                    # Add all resources to this policy document
                    self.r53rslvlogpolicy.add_all_resources()
                    # Iam Role
                    self.r53rslvlogrole = iam.Role(
                        self,
                        f"{self.stack_name}:R53edptLogsRole",
                        assumed_by=iam.ServicePrincipal('route53.amazonaws.com'),
                        description="Role for Delivery Resolver Query Logs",
                    )
                    # Attach policy to Iam Role
                    self.r53rslvlogrole.add_to_policy(self.r53rslvlogpolicy)
                    # query log config
                    self.r53rslvlog = route53resolver.CfnResolverQueryLoggingConfig(
                        self,
                        f"R53edptlog{self.stack_name}",
                        destination_arn=self.r53rslvloggroup.log_group_arn,
                        name=f"R53edptlog{self.stack_name}"
                    )
                    # query log association
                    self.r53rslvlogassoc = route53resolver.CfnResolverQueryLoggingConfigAssociation(
                        self,
                        f"R53edptlogAssoc{self.stack_name}",
                        resolver_query_log_config_id=self.r53rslvlog.ref,
                        resource_id=self.vpc.vpc_id
                    )
        if dsid != '':
            targetips = []
            index = 0
            while index <= 1:
                ip = core.Fn.import_value(f"MYDSDns{index}")
                targetips.append(route53resolver.CfnResolverRule.TargetAddressProperty(ip=ip,port= "53"))
                index = index + 1
            domainname = dsid.name
            rslvrule = route53resolver.CfnResolverRule(
                    self,
                    f"R53Rule{self.stack_name}{domainname}",
                    domain_name=domainname,
                    rule_type='FORWARD',
                    resolver_endpoint_id=self.r53rslv.attr_resolver_endpoint_id,
                    target_ips=targetips
            )
            route53resolver.CfnResolverRuleAssociation(
                self,
                f"R53Rule{self.stack_name}Ass{domainname}",
                resolver_rule_id = rslvrule.attr_resolver_rule_id,
                vpc_id = self.vpc.vpc_id
            ).add_depends_on(rslvrule)
            rslvrule.override_logical_id(new_logical_id=f"fwd{dsid.short_name}")
        if 'RULES' in resmap['Mappings']['Resources'][res]:
            for rule in resmap['Mappings']['Resources'][res]['RULES']:
                name = rule['NAME']
                domainname = rule['DOMAIN']
                ruletype = rule['RULETYPE']
                targetips = []
                for target in rule['TARGETIPS']:
                    ip = target['IP']
                    port = target['PORT']
                    targetips.append(route53resolver.CfnResolverRule.TargetAddressProperty(ip=ip,port=port))
                rslvrule = route53resolver.CfnResolverRule(
                    self,
                    f"R53Rule{self.stack_name}{name}",
                    domain_name=domainname,
                    rule_type=ruletype,
                    resolver_endpoint_id=self.r53rslv.attr_resolver_endpoint_id,
                    target_ips=targetips
                )
                route53resolver.CfnResolverRuleAssociation(
                    self,
                f"R53Rule{self.stack_name}Ass{name}",
                    resolver_rule_id = rslvrule.attr_resolver_rule_id,
                    vpc_id = self.vpc.vpc_id
                ).add_depends_on(rslvrule)
                rslvrule.override_logical_id(new_logical_id=f"fwd{name}")
