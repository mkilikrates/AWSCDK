import os
import json
import base64
import logging
from aws_cdk import (
    aws_ec2 as ec2,
    aws_iam as iam,
    core
)
logger = logging.getLogger(__name__)
vcpcidr = "10.0.0.0/16"
vpcname = "Myvpcpythontest"
region = os.environ["CDK_DEFAULT_REGION"]
tagName = core.CfnTag(key="Name", value=vpcname)
vpcenv = "production"
tagEnv = core.CfnTag(key="environment", value=vpcenv)
usrdatafile = 'bastion'
usrdata = open(usrdatafile + ".cfg", "r").read()
mykey = "Fedorawrkst-" + region
myrole = 'EC2_Admin_Role'

class MytestvpcStack(core.Stack):

    def __init__(self, scope: core.Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # The code that defines your stack goes here
        # from https://github.com/aws/aws-cdk/issues/894
        myvpc = ec2.Vpc(self,
            vpcname,
            cidr=vcpcidr,
            max_azs=2,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    subnet_type=ec2.SubnetType.PUBLIC,
                    name="Public",
                    cidr_mask=24
                ), 
                ec2.SubnetConfiguration(
                    subnet_type=ec2.SubnetType.PRIVATE,
                    name="Private",
                    cidr_mask=24
                ), 
                ec2.SubnetConfiguration(
                    subnet_type=ec2.SubnetType.ISOLATED,
                    name="Intercon",
                    cidr_mask=24
                )
            ]
        )

        # IPv6 is currently not supported by CDK.
        # This is done manually now, based on:
        # https://gist.github.com/milesjordan/d86942718f8d4dc20f9f331913e7367a

        ipv6_block = ec2.CfnVPCCidrBlock(self, "Ipv6",
            vpc_id=myvpc.vpc_id,
            amazon_provided_ipv6_cidr_block=True
        )

        # We need to sniff out the InternetGateway the VPC is using, as we
        # need to assign this for IPv6 routing too.

        for child in myvpc.node.children:
            if isinstance(child, ec2.CfnInternetGateway):
                internet_gateway = child
                break
        else:
            raise Exception("Couldn't find the InternetGateway of the VPC")

        egressonlygateway = ec2.CfnEgressOnlyInternetGateway(
            self,
            "EgressOnlyInternetGateway",
            vpc_id=myvpc.vpc_id
        )
        i = 0

        for index, subnet in enumerate(myvpc.public_subnets):
            subnet.add_route("DefaultIpv6Route",
                router_id=internet_gateway.ref,
                router_type=ec2.RouterType.GATEWAY,
                destination_ipv6_cidr_block="::/0",
            )

            # This is of course not the best way to do this, but it seems CDK
            # currently allows no other way to set the IPv6 CIDR on subnets.
            assert isinstance(subnet.node.children[0], ec2.CfnSubnet)
            # As IPv6 are allocated on provisioning, we need to use "Fn::Cidr"
            # to get a subnet out of it.
            subnet.node.children[0].ipv6_cidr_block = core.Fn.select(
                index,
                core.Fn.cidr(
                    core.Fn.select(
                        0,
                        myvpc.vpc_ipv6_cidr_blocks
                    ),
                    len(myvpc.public_subnets),
                    "64"
                )
            )
            # Not work because CFN not allow assign both public IP and ipv6 together
            #subnet.node.children[0].assign_ipv6_address_on_creation=True
            # Make sure the dependencies are correct, otherwise we might be
            # creating a subnet before IPv6 is added.
            subnet.node.add_dependency(ipv6_block)
            i = i + 1
            
        for index, subnet in enumerate(myvpc.private_subnets):
            subnet.add_route("DefaultIpv6Route",
                router_id=egressonlygateway.ref,
                router_type=ec2.RouterType.EGRESS_ONLY_INTERNET_GATEWAY,
                destination_ipv6_cidr_block="::/0",
            )

            # This is of course not the best way to do this, but it seems CDK
            # currently allows no other way to set the IPv6 CIDR on subnets.
            assert isinstance(subnet.node.children[0], ec2.CfnSubnet)
            # As IPv6 are allocated on provisioning, we need to use "Fn::Cidr"
            # to get a subnet out of it.
            subnet.node.children[0].ipv6_cidr_block = core.Fn.select(
                i,
                core.Fn.cidr(
                    core.Fn.select(
                        0,
                        myvpc.vpc_ipv6_cidr_blocks
                    ),
                    len(myvpc.private_subnets) + len(myvpc.public_subnets),
                    "64"
                )
            )
            # Not work because CFN not allow assign both public IP and ipv6 together
            #subnet.node.children[0].assign_ipv6_address_on_creation=True
            # Make sure the dependencies are correct, otherwise we might be
            # creating a subnet before IPv6 is added.
            subnet.node.add_dependency(ipv6_block)
            i = i + 1



        with open('zonemap.cfg') as zonefile:
            zonemap = json.load(zonefile)
            srcprefix = zonemap['Mappings']['RegionMap'][region]['PREFIXLIST']

        bastionsg = ec2.SecurityGroup(
            self,
            'MyBastionSG',
            vpc=myvpc
        )
        bastionsg.add_egress_rule(
            ec2.Peer.ipv6("::/0"),
            ec2.Port.all_traffic()
        )
        bastionsg.add_ingress_rule(
            ec2.Peer.prefix_list(srcprefix),
            ec2.Port.all_traffic()
        )
        bastionsg.add_ingress_rule(
            bastionsg,
            ec2.Port.all_traffic()
        )
        
        bastion = ec2.BastionHostLinux(
            self,
            'MybastionLinux',
            vpc=myvpc,
            security_group=bastionsg,
            subnet_selection=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
            instance_type=ec2.InstanceType('t3.micro'),
            machine_image=ec2.AmazonLinuxImage(
                user_data=ec2.UserData.custom(usrdata),
                edition=ec2.AmazonLinuxEdition.STANDARD,
                generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2,
            )
        )
        #https://pypi.org/project/aws-cdk.aws-iam/
        bastion.instance.role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name("AdministratorAccess"))
        bastion.instance.instance.add_property_override("KeyName", mykey)
        bastion.instance.instance.add_property_override("Ipv6AddressCount", 1)

