import os
import json
from aws_cdk import (
    aws_ec2 as ec2,
    core,
)
account = os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"])
region = os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])
resconf = "resourcesmap.cfg"
with open(resconf) as resfile:
    resmap = json.load(resfile)
with open('zonemap.cfg') as zonefile:
    zonemap = json.load(zonefile)

class VPC(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, res, stack, cidrid, natgw, maxaz, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.cidrid = int(cidrid)
        self.natgw = int(natgw)
        self.maxaz = int(maxaz)
        self.vpcstack = stack
        res = res
        # get prefix list from file to allow traffic from the office
        vcpcidr = zonemap['Mappings']['RegionMap'][region]['CIDR'][self.cidrid]
        resname = resmap['Mappings']['Resources'][res]['NAME']
        self.sub = []
        for subtype in resmap['Mappings']['Resources'][res]['SUBNETS']:
            if 'PUBLIC' in subtype:
                for sub in subtype['PUBLIC']:
                    self.sub.append(
                        ec2.SubnetConfiguration(
                            name=sub['NAME'],
                            subnet_type=ec2.SubnetType.PUBLIC,
                            cidr_mask=sub['CIDR']
                        )
                    )
            if 'PRIVATE' in subtype:
                for sub in subtype['PRIVATE']:
                    self.sub.append(
                        ec2.SubnetConfiguration(
                            name=sub['NAME'],
                            subnet_type=ec2.SubnetType.PRIVATE,
                            cidr_mask=sub['CIDR']
                        )
                    )
            if 'ISOLATED' in subtype:
                for sub in subtype['ISOLATED']:
                    self.sub.append(
                        ec2.SubnetConfiguration(
                            name=sub['NAME'],
                            subnet_type=ec2.SubnetType.ISOLATED,
                            cidr_mask=sub['CIDR']
                        )
                    )
        # create simple vpc
        self.vpc = ec2.Vpc(self,
            f"{construct_id}:{resname}",
            cidr=vcpcidr,
            max_azs=self.maxaz,
            nat_gateways=self.natgw,
            subnet_configuration=self.sub
        )
        core.CfnOutput(
            self,
            f"{construct_id}:vpcId",
            value=self.vpc.vpc_id,
            export_name=f"{construct_id}:vpcId"
        )
        core.CfnOutput(
            self,
            f"{construct_id}:vpccidr",
            value=self.vpc.vpc_cidr_block,
            export_name=f"{construct_id}:vpccidr"
        )
        core.CfnOutput(
            self,
            f"{construct_id}:vpcdefaultsg",
            value=self.vpc.vpc_default_security_group,
            export_name=f"{construct_id}:vpcdefaultsg"
        )

        if self.vpcstack != 'Ipv4':
            # ipv6 on this vpc
            self.ipv6_block = ec2.CfnVPCCidrBlock(self, "Ipv6",
                vpc_id=self.vpc.vpc_id,
                amazon_provided_ipv6_cidr_block=True
            )
            # Create EgressOnlyInternetGateway
            egressonlygateway = ec2.CfnEgressOnlyInternetGateway(
                self,
                "EgressOnlyInternetGateway",
                vpc_id=self.vpc.vpc_id
            )
            # Sniff out InternetGateway to use to assign ipv6 routes
            for child in self.vpc.node.children:
                if isinstance(child, ec2.CfnInternetGateway):
                    internet_gateway = child
                    break
            else:
                raise Exception("Couldn't find the InternetGateway of the VPC")
            #set counter to iterate with Fn.cidr select
            i = 0
            # Iterate on Public Subnet
            for subnet in self.vpc.public_subnets:
                # set default route to IGW
                subnet.add_route(
                    "DefaultIpv6Route",
                    router_id=internet_gateway.ref,
                    router_type=ec2.RouterType.GATEWAY,
                    destination_ipv6_cidr_block="::/0",
                )
                # allocate ipv6 to each subnet
                assert isinstance(subnet.node.children[0], ec2.CfnSubnet)
                subnet.node.children[0].ipv6_cidr_block = core.Fn.select(
                    i,
                    core.Fn.cidr(
                        core.Fn.select(
                            0,
                            self.vpc.vpc_ipv6_cidr_blocks
                        ),
                        len(self.vpc.public_subnets) + len(self.vpc.private_subnets) + len(self.vpc.isolated_subnets),
                        "64"
                    )
                )
                subnet.node.add_dependency(self.ipv6_block)
                i = i + 1
            # Iterate on Private Subnet
            for subnet in self.vpc.private_subnets:
                # set default route to IGW
                subnet.add_route(
                    "DefaultIpv6Route",
                    router_id=egressonlygateway.ref,
                    router_type=ec2.RouterType.EGRESS_ONLY_INTERNET_GATEWAY,
                    destination_ipv6_cidr_block="::/0",
                )
                # allocate ipv6 to each subnet
                assert isinstance(subnet.node.children[0], ec2.CfnSubnet)
                subnet.node.children[0].ipv6_cidr_block = core.Fn.select(
                    i,
                    core.Fn.cidr(
                        core.Fn.select(
                            0,
                            self.vpc.vpc_ipv6_cidr_blocks
                        ),
                        len(self.vpc.public_subnets) + len(self.vpc.private_subnets) + len(self.vpc.isolated_subnets),
                        "64"
                    )
                )
                subnet.node.children[0].add_deletion_override('Properties.MapPublicIpOnLaunch')
                subnet.node.children[0].assign_ipv6_address_on_creation=True
                subnet.node.add_dependency(self.ipv6_block)
                i = i + 1
            # Iterate on Isolated Subnet
            for subnet in self.vpc.isolated_subnets:
                # allocate ipv6 to each subnet
                assert isinstance(subnet.node.children[0], ec2.CfnSubnet)
                subnet.node.children[0].ipv6_cidr_block = core.Fn.select(
                    i,
                    core.Fn.cidr(
                        core.Fn.select(
                            0,
                            self.vpc.vpc_ipv6_cidr_blocks
                        ),
                        len(self.vpc.public_subnets) + len(self.vpc.private_subnets) + len(self.vpc.isolated_subnets),
                        "64"
                    )
                )
                subnet.node.children[0].add_deletion_override('Properties.MapPublicIpOnLaunch')
                subnet.node.children[0].assign_ipv6_address_on_creation=True
                subnet.node.add_dependency(self.ipv6_block)
                i = i + 1
            core.CfnOutput(
                self,
                f"{construct_id}:vpccidrv6",
                value=core.Fn.select(
                    0,
                    self.vpc.vpc_ipv6_cidr_blocks
                ),
                export_name=f"{construct_id}:vpccidrv6",
            )

