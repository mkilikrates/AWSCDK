import os
import json
from aws_cdk import (
    aws_ec2 as ec2,
    core,
)
account = os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"])
region = os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])
with open('zonemap.cfg') as zonefile:
    zonemap = json.load(zonefile)

class tgwv4(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, vpc = ec2.Vpc, bastionsg = ec2.SecurityGroup, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.vpc = vpc
        self.bastionsg = bastionsg
        # get prefix list from file to allow traffic from the office
        vgasn = int(zonemap['Mappings']['RegionMap'][region]['TGWASN'])
        # create prefix list for RFC1918
        mynet10rfc1918 = ec2.CfnPrefixList.EntryProperty(
            cidr='10.0.0.0/8',
            description='Network 10.0.0.0/8 from RFC1918'
        )
        mynet172rfc1918 = ec2.CfnPrefixList.EntryProperty(
            cidr='172.16.0.0/12',
            description='Network 172.16.0.0/12 from RFC1918'
        )
        mynet192rfc1918 = ec2.CfnPrefixList.EntryProperty(
            cidr='192.168.0.0/16',
            description='Network 192.168.0.0/16 from RFC1918'
        )
        myrfc1918 = ec2.CfnPrefixList(
            self,
            id=f"pl-rfc1918" + region,
            address_family='IPv4',
            max_entries=5,
            prefix_list_name=f"pl-rfc1918" + region,
            entries=[
                mynet10rfc1918,
                mynet172rfc1918,
                mynet192rfc1918
            ]
        )
        # allow traffic from RFC1918 to make tests from bastion
        ec2.CfnSecurityGroupIngress(
            self,
            "MyBastionIngress10",
            ip_protocol="-1",
            source_prefix_list_id=myrfc1918.ref,
            group_id=bastionsg.security_group_id
        )
        # create transit gateway
        self.tgw = ec2.CfnTransitGateway(
            self,
            id=f"TGW-" + region,
            amazon_side_asn=vgasn,
            auto_accept_shared_attachments='enable',
            default_route_table_association='enable',
            default_route_table_propagation='enable',
            multicast_support='enable',
            tags=[
                core.CfnTag(
                    key='Name',
                    value=f"tgw-" + region
                )
            ]
        )
        # attach transit gateway to vpc
        self.tgwattch = ec2.CfnTransitGatewayAttachment(
            self,
            id=f"tgw-vpc-" + region + "-attachment",
            transit_gateway_id=self.tgw.ref,
            vpc_id=self.vpc.vpc_id,
            subnet_ids=[subnet.subnet_id for subnet in self.vpc.isolated_subnets],
            tags=[
                core.CfnTag(
                    key='Name',
                    value=f"tgw-" + self.vpc.vpc_id + "-attachment"
                )
            ]
        )
        # add routes target RFC1918 to tgw
        # Net 10/8
        for subnet in self.vpc.public_subnets:
            ec2.CfnRoute(
                self,
                id=f"vpc-rtpub-" + subnet.availability_zone + "-ne10-tgw",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='10.0.0.0/8',
                transit_gateway_id=self.tgw.ref
            ).add_depends_on(self.tgwattch)
        for subnet in self.vpc.private_subnets:
            ec2.CfnRoute(
                self,
                id=f"vpc-rtpriv-" + subnet.availability_zone + "-ne10-tgw",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='10.0.0.0/8',
                transit_gateway_id=self.tgw.ref
            ).add_depends_on(self.tgwattch)
        for subnet in self.vpc.isolated_subnets:
            ec2.CfnRoute(
                self,
                id=f"vpc-rtisol-" + subnet.availability_zone + "-ne10-tgw",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='10.0.0.0/8',
                transit_gateway_id=self.tgw.ref
            ).add_depends_on(self.tgwattch)
        # Net 172.16/12
        for subnet in self.vpc.public_subnets:
            ec2.CfnRoute(
                self,
                id=f"vpc-rtpub-" + subnet.availability_zone + "-ne172-tgw",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='172.16.0.0/12',
                transit_gateway_id=self.tgw.ref
            ).add_depends_on(self.tgwattch)
        for subnet in self.vpc.private_subnets:
            ec2.CfnRoute(
                self,
                id=f"vpc-rtpriv-" + subnet.availability_zone + "-ne172-tgw",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='172.16.0.0/12',
                transit_gateway_id=self.tgw.ref
            ).add_depends_on(self.tgwattch)
        for subnet in self.vpc.isolated_subnets:
            ec2.CfnRoute(
                self,
                id=f"vpc-rtisol-" + subnet.availability_zone + "-ne172-tgw",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='172.16.0.0/12',
                transit_gateway_id=self.tgw.ref
            ).add_depends_on(self.tgwattch)
        # Net 192.168/16
        for subnet in self.vpc.public_subnets:
            ec2.CfnRoute(
                self,
                id=f"vpc-rtpub-" + subnet.availability_zone + "-ne192-tgw",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='192.168.0.0/16',
                transit_gateway_id=self.tgw.ref
            ).add_depends_on(self.tgwattch)
        for subnet in self.vpc.private_subnets:
            ec2.CfnRoute(
                self,
                id=f"vpc-rtpriv-" + subnet.availability_zone + "-ne192-tgw",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='192.168.0.0/16',
                transit_gateway_id=self.tgw.ref
            ).add_depends_on(self.tgwattch)
        for subnet in self.vpc.isolated_subnets:
            ec2.CfnRoute(
                self,
                id=f"vpc-rtisol-" + subnet.availability_zone + "-ne192-tgw",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='192.168.0.0/16',
                transit_gateway_id=self.tgw.ref
            ).add_depends_on(self.tgwattch)

class attachtgwv4(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, vpc = ec2.Vpc, bastionsg = ec2.SecurityGroup, tgwid = ec2.CfnTransitGateway, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.vpc = vpc
        self.bastionsg = bastionsg
        self.tgw = tgwid
        # create prefix list for RFC1918
        mynet10rfc1918 = ec2.CfnPrefixList.EntryProperty(
            cidr='10.0.0.0/8',
            description='Network 10.0.0.0/8 from RFC1918'
        )
        mynet172rfc1918 = ec2.CfnPrefixList.EntryProperty(
            cidr='172.16.0.0/12',
            description='Network 172.16.0.0/12 from RFC1918'
        )
        mynet192rfc1918 = ec2.CfnPrefixList.EntryProperty(
            cidr='192.168.0.0/16',
            description='Network 192.168.0.0/16 from RFC1918'
        )
        myrfc1918 = ec2.CfnPrefixList(
            self,
            id=f"pl-rfc1918" + region,
            address_family='IPv4',
            max_entries=5,
            prefix_list_name=f"pl-rfc1918" + region,
            entries=[
                mynet10rfc1918,
                mynet172rfc1918,
                mynet192rfc1918
            ]
        )
        # allow traffic from RFC1918 to make tests from bastion
        ec2.CfnSecurityGroupIngress(
            self,
            "MyBastionIngress10",
            ip_protocol="-1",
            source_prefix_list_id=myrfc1918.ref,
            group_id=bastionsg.security_group_id
        )
        # attach transit gateway to vpc
        self.tgwattch = ec2.CfnTransitGatewayAttachment(
            self,
            id=f"tgw-vpc-" + region + "-attachment",
            transit_gateway_id=self.tgw.ref,
            vpc_id=self.vpc.vpc_id,
            subnet_ids=[subnet.subnet_id for subnet in self.vpc.isolated_subnets],
            tags=[
                core.CfnTag(
                    key='Name',
                    value=f"tgw-" + self.vpc.vpc_id + "-attachment"
                )
            ]
        )
        # add routes target RFC1918 to tgw
        # Net 10/8
        for subnet in self.vpc.public_subnets:
            ec2.CfnRoute(
                self,
                id=f"vpc-rtpub-" + subnet.availability_zone + "-ne10-tgw",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='10.0.0.0/8',
                transit_gateway_id=self.tgw.ref
            ).add_depends_on(self.tgwattch)
        for subnet in self.vpc.private_subnets:
            ec2.CfnRoute(
                self,
                id=f"vpc-rtpriv-" + subnet.availability_zone + "-ne10-tgw",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='10.0.0.0/8',
                transit_gateway_id=self.tgw.ref
            ).add_depends_on(self.tgwattch)
        for subnet in self.vpc.isolated_subnets:
            ec2.CfnRoute(
                self,
                id=f"vpc-rtisol-" + subnet.availability_zone + "-ne10-tgw",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='10.0.0.0/8',
                transit_gateway_id=self.tgw.ref
            ).add_depends_on(self.tgwattch)
        # Net 172.16/12
        for subnet in self.vpc.public_subnets:
            ec2.CfnRoute(
                self,
                id=f"vpc-rtpub-" + subnet.availability_zone + "-ne172-tgw",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='172.16.0.0/12',
                transit_gateway_id=self.tgw.ref
            ).add_depends_on(self.tgwattch)
        for subnet in self.vpc.private_subnets:
            ec2.CfnRoute(
                self,
                id=f"vpc-rtpriv-" + subnet.availability_zone + "-ne172-tgw",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='172.16.0.0/12',
                transit_gateway_id=self.tgw.ref
            ).add_depends_on(self.tgwattch)
        for subnet in self.vpc.isolated_subnets:
            ec2.CfnRoute(
                self,
                id=f"vpc-rtisol-" + subnet.availability_zone + "-ne172-tgw",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='172.16.0.0/12',
                transit_gateway_id=self.tgw.ref
            ).add_depends_on(self.tgwattch)
        # Net 192.168/16
        for subnet in self.vpc.public_subnets:
            ec2.CfnRoute(
                self,
                id=f"vpc-rtpub-" + subnet.availability_zone + "-ne192-tgw",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='192.168.0.0/16',
                transit_gateway_id=self.tgw.ref
            ).add_depends_on(self.tgwattch)
        for subnet in self.vpc.private_subnets:
            ec2.CfnRoute(
                self,
                id=f"vpc-rtpriv-" + subnet.availability_zone + "-ne192-tgw",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='192.168.0.0/16',
                transit_gateway_id=self.tgw.ref
            ).add_depends_on(self.tgwattch)
        for subnet in self.vpc.isolated_subnets:
            ec2.CfnRoute(
                self,
                id=f"vpc-rtisol-" + subnet.availability_zone + "-ne192-tgw",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='192.168.0.0/16',
                transit_gateway_id=self.tgw.ref
            ).add_depends_on(self.tgwattch)

class tgwv6(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, vpc = ec2.Vpc, bastionsg = ec2.SecurityGroup, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.vpc = vpc
        self.bastionsg = bastionsg
        # get prefix list from file to allow traffic from the office
        vgasn = int(zonemap['Mappings']['RegionMap'][region]['TGWASN'])
        # create prefix list for RFC1918
        mynet10rfc1918 = ec2.CfnPrefixList.EntryProperty(
            cidr='10.0.0.0/8',
            description='Network 10.0.0.0/8 from RFC1918'
        )
        mynet172rfc1918 = ec2.CfnPrefixList.EntryProperty(
            cidr='172.16.0.0/12',
            description='Network 172.16.0.0/12 from RFC1918'
        )
        mynet192rfc1918 = ec2.CfnPrefixList.EntryProperty(
            cidr='192.168.0.0/16',
            description='Network 192.168.0.0/16 from RFC1918'
        )
        myrfc1918 = ec2.CfnPrefixList(
            self,
            id=f"pl-rfc1918" + region,
            address_family='IPv4',
            max_entries=5,
            prefix_list_name=f"pl-rfc1918" + region,
            entries=[
                mynet10rfc1918,
                mynet172rfc1918,
                mynet192rfc1918
            ]
        )
        # allow traffic from RFC1918 to make tests from bastion
        ec2.CfnSecurityGroupIngress(
            self,
            "MyBastionIngress10",
            ip_protocol="-1",
            source_prefix_list_id=myrfc1918.ref,
            group_id=bastionsg.security_group_id
        )
        # create transit gateway
        self.tgw = ec2.CfnTransitGateway(
            self,
            id=f"TGW-" + region,
            amazon_side_asn=vgasn,
            auto_accept_shared_attachments='enable',
            default_route_table_association='enable',
            default_route_table_propagation='enable',
            multicast_support='enable',
            tags=[
                core.CfnTag(
                    key='Name',
                    value=f"tgw-" + region
                )
            ]
        )
        # attach transit gateway to vpc
        self.tgwattch = ec2.CfnTransitGatewayAttachment(
            self,
            id=f"tgw-vpc-" + region + "-attachment",
            transit_gateway_id=self.tgw.ref,
            vpc_id=self.vpc.vpc_id,
            subnet_ids=[subnet.subnet_id for subnet in self.vpc.isolated_subnets],
            tags=[
                core.CfnTag(
                    key='Name',
                    value=f"tgw-" + self.vpc.vpc_id + "-attachment"
                )
            ]
        )
        # add routes target RFC1918 to tgw
        # Net 10/8
        for subnet in self.vpc.public_subnets:
            ec2.CfnRoute(
                self,
                id=f"vpc-rtpub-" + subnet.availability_zone + "-ne10-tgw",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='10.0.0.0/8',
                transit_gateway_id=self.tgw.ref
            ).add_depends_on(self.tgwattch)
        for subnet in self.vpc.private_subnets:
            ec2.CfnRoute(
                self,
                id=f"vpc-rtpriv-" + subnet.availability_zone + "-ne10-tgw",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='10.0.0.0/8',
                transit_gateway_id=self.tgw.ref
            ).add_depends_on(self.tgwattch)
        for subnet in self.vpc.isolated_subnets:
            ec2.CfnRoute(
                self,
                id=f"vpc-rtisol-" + subnet.availability_zone + "-ne10-tgw",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='10.0.0.0/8',
                transit_gateway_id=self.tgw.ref
            ).add_depends_on(self.tgwattch)
        # Net 172.16/12
        for subnet in self.vpc.public_subnets:
            ec2.CfnRoute(
                self,
                id=f"vpc-rtpub-" + subnet.availability_zone + "-ne172-tgw",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='172.16.0.0/12',
                transit_gateway_id=self.tgw.ref
            ).add_depends_on(self.tgwattch)
        for subnet in self.vpc.private_subnets:
            ec2.CfnRoute(
                self,
                id=f"vpc-rtpriv-" + subnet.availability_zone + "-ne172-tgw",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='172.16.0.0/12',
                transit_gateway_id=self.tgw.ref
            ).add_depends_on(self.tgwattch)
        for subnet in self.vpc.isolated_subnets:
            ec2.CfnRoute(
                self,
                id=f"vpc-rtisol-" + subnet.availability_zone + "-ne172-tgw",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='172.16.0.0/12',
                transit_gateway_id=self.tgw.ref
            ).add_depends_on(self.tgwattch)
        # Net 192.168/16
        for subnet in self.vpc.public_subnets:
            ec2.CfnRoute(
                self,
                id=f"vpc-rtpub-" + subnet.availability_zone + "-ne192-tgw",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='192.168.0.0/16',
                transit_gateway_id=self.tgw.ref
            ).add_depends_on(self.tgwattch)
        for subnet in self.vpc.private_subnets:
            ec2.CfnRoute(
                self,
                id=f"vpc-rtpriv-" + subnet.availability_zone + "-ne192-tgw",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='192.168.0.0/16',
                transit_gateway_id=self.tgw.ref
            ).add_depends_on(self.tgwattch)
        for subnet in self.vpc.isolated_subnets:
            ec2.CfnRoute(
                self,
                id=f"vpc-rtisol-" + subnet.availability_zone + "-ne192-tgw",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='192.168.0.0/16',
                transit_gateway_id=self.tgw.ref
            ).add_depends_on(self.tgwattch)
class attachtgwv6(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, vpc = ec2.Vpc, bastionsg = ec2.SecurityGroup, tgwid = ec2.CfnTransitGateway, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.vpc = vpc
        self.bastionsg = bastionsg
        self.tgw = tgwid
        # create prefix list for RFC1918
        mynet10rfc1918 = ec2.CfnPrefixList.EntryProperty(
            cidr='10.0.0.0/8',
            description='Network 10.0.0.0/8 from RFC1918'
        )
        mynet172rfc1918 = ec2.CfnPrefixList.EntryProperty(
            cidr='172.16.0.0/12',
            description='Network 172.16.0.0/12 from RFC1918'
        )
        mynet192rfc1918 = ec2.CfnPrefixList.EntryProperty(
            cidr='192.168.0.0/16',
            description='Network 192.168.0.0/16 from RFC1918'
        )
        myrfc1918 = ec2.CfnPrefixList(
            self,
            id=f"pl-rfc1918" + region,
            address_family='IPv4',
            max_entries=5,
            prefix_list_name=f"pl-rfc1918" + region,
            entries=[
                mynet10rfc1918,
                mynet172rfc1918,
                mynet192rfc1918
            ]
        )
        # allow traffic from RFC1918 to make tests from bastion
        ec2.CfnSecurityGroupIngress(
            self,
            "MyBastionIngress10",
            ip_protocol="-1",
            source_prefix_list_id=myrfc1918.ref,
            group_id=bastionsg.security_group_id
        )
        # attach transit gateway to vpc
        self.tgwattch = ec2.CfnTransitGatewayAttachment(
            self,
            id=f"tgw-vpc-" + region + "-attachment",
            transit_gateway_id=self.tgw.ref,
            vpc_id=self.vpc.vpc_id,
            subnet_ids=[subnet.subnet_id for subnet in self.vpc.isolated_subnets],
            tags=[
                core.CfnTag(
                    key='Name',
                    value=f"tgw-" + self.vpc.vpc_id + "-attachment"
                )
            ]
        )
        # add routes target RFC1918 to tgw
        # Net 10/8
        for subnet in self.vpc.public_subnets:
            ec2.CfnRoute(
                self,
                id=f"vpc-rtpub-" + subnet.availability_zone + "-ne10-tgw",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='10.0.0.0/8',
                transit_gateway_id=self.tgw.ref
            ).add_depends_on(self.tgwattch)
        for subnet in self.vpc.private_subnets:
            ec2.CfnRoute(
                self,
                id=f"vpc-rtpriv-" + subnet.availability_zone + "-ne10-tgw",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='10.0.0.0/8',
                transit_gateway_id=self.tgw.ref
            ).add_depends_on(self.tgwattch)
        for subnet in self.vpc.isolated_subnets:
            ec2.CfnRoute(
                self,
                id=f"vpc-rtisol-" + subnet.availability_zone + "-ne10-tgw",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='10.0.0.0/8',
                transit_gateway_id=self.tgw.ref
            ).add_depends_on(self.tgwattch)
        # Net 172.16/12
        for subnet in self.vpc.public_subnets:
            ec2.CfnRoute(
                self,
                id=f"vpc-rtpub-" + subnet.availability_zone + "-ne172-tgw",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='172.16.0.0/12',
                transit_gateway_id=self.tgw.ref
            ).add_depends_on(self.tgwattch)
        for subnet in self.vpc.private_subnets:
            ec2.CfnRoute(
                self,
                id=f"vpc-rtpriv-" + subnet.availability_zone + "-ne172-tgw",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='172.16.0.0/12',
                transit_gateway_id=self.tgw.ref
            ).add_depends_on(self.tgwattch)
        for subnet in self.vpc.isolated_subnets:
            ec2.CfnRoute(
                self,
                id=f"vpc-rtisol-" + subnet.availability_zone + "-ne172-tgw",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='172.16.0.0/12',
                transit_gateway_id=self.tgw.ref
            ).add_depends_on(self.tgwattch)
        # Net 192.168/16
        for subnet in self.vpc.public_subnets:
            ec2.CfnRoute(
                self,
                id=f"vpc-rtpub-" + subnet.availability_zone + "-ne192-tgw",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='192.168.0.0/16',
                transit_gateway_id=self.tgw.ref
            ).add_depends_on(self.tgwattch)
        for subnet in self.vpc.private_subnets:
            ec2.CfnRoute(
                self,
                id=f"vpc-rtpriv-" + subnet.availability_zone + "-ne192-tgw",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='192.168.0.0/16',
                transit_gateway_id=self.tgw.ref
            ).add_depends_on(self.tgwattch)
        for subnet in self.vpc.isolated_subnets:
            ec2.CfnRoute(
                self,
                id=f"vpc-rtisol-" + subnet.availability_zone + "-ne192-tgw",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='192.168.0.0/16',
                transit_gateway_id=self.tgw.ref
            ).add_depends_on(self.tgwattch)
