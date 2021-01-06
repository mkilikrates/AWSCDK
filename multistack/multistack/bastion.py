import os
import json
from aws_cdk import (
    aws_ec2 as ec2,
    core,
)
account = os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"])
region = os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])
vpcconf = "vpcmap.cfg"
resconf = "resourcesmap.cfg"
cidrid = 0
natgw = 1
with open(resconf) as resfile:
    resmap = json.load(resfile)
with open('zonemap.cfg') as zonefile:
    zonemap = json.load(zonefile)
class bastionv4(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, vpc = ec2.Vpc, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.vpc = vpc
        # get prefix list from file to allow traffic from the office
        srcprefix = zonemap['Mappings']['RegionMap'][region]['PREFIXLIST']        
        # create security group for bastion
        self.bastionsg = ec2.SecurityGroup(
            self,
            'MyBastionSG',
            allow_all_outbound=True,
            vpc=self.vpc
        )
         # add ingress rules
        self.bastionsg.add_ingress_rule(
            ec2.Peer.prefix_list(srcprefix),
            ec2.Port.all_traffic()
        )
        self.bastionsg.add_ingress_rule(
            self.bastionsg,
            ec2.Port.all_traffic()
        )
        # get data for bastion resource
        res = 'bastion'
        resname = resmap['Mappings']['Resources'][res]['NAME']
        ressize = resmap['Mappings']['Resources'][res]['SIZE']
        mykey = resmap['Mappings']['Resources'][res]['KEY'] + region
        usrdatafile = resmap['Mappings']['Resources'][res]['USRFILE']
        usrdata = open(usrdatafile, "r").read()
        # create bastion host instance
        self.bastion = ec2.BastionHostLinux(
            self,
            'MyBastion',
            vpc=self.vpc,
            security_group=self.bastionsg,
            subnet_selection=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
            instance_type=ec2.InstanceType(ressize),
            machine_image=ec2.AmazonLinuxImage(
                user_data=ec2.UserData.custom(usrdata),
                edition=ec2.AmazonLinuxEdition.STANDARD,
                generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2,
            ),
            instance_name=resname + region,
        )
        # add tags
        for tagsmap in resmap['Mappings']['Resources'][res]['TAGS']:
            for k,v in tagsmap.items():
                core.Tags.of(self.bastion).add(k,v,include_resource_types=["AWS::EC2::Instance"])
        # add my key
        self.bastion.instance.instance.add_property_override("KeyName", mykey)
        # output
        core.CfnOutput(
            self,
            "bastion-sg",
            value=self.bastionsg.security_group_id,
            export_name="bastion-sg"
        )
        core.CfnOutput(
            self,
            "bastion-ipv4",
            value=self.bastion.__getattribute__("instance_public_ip"),
            export_name="bastion-ipv4"
        )

class bastionv6(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, vpc = ec2.Vpc, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.vpc = vpc
        # get prefix list from file to allow traffic from the office
        srcprefix = zonemap['Mappings']['RegionMap'][region]['PREFIXLIST']        
        # create security group for bastion
        self.bastionsg = ec2.SecurityGroup(
            self,
            'MyBastionSG',
            allow_all_outbound=True,
            vpc=self.vpc
        )
        # add egress rule
        ec2.CfnSecurityGroupEgress(
            self,
            "BastionEgressAllIpv6",
            ip_protocol="-1",
            cidr_ipv6="::/0",
            group_id=self.bastionsg.security_group_id
        )
         # add ingress rules
        self.bastionsg.add_ingress_rule(
            ec2.Peer.prefix_list(srcprefix),
            ec2.Port.all_traffic()
        )
        self.bastionsg.add_ingress_rule(
            self.bastionsg,
            ec2.Port.all_traffic()
        )
        # get data for bastion resource
        res = 'bastion'
        resname = resmap['Mappings']['Resources'][res]['NAME']
        ressize = resmap['Mappings']['Resources'][res]['SIZE']
        mykey = resmap['Mappings']['Resources'][res]['KEY'] + region
        usrdatafile = resmap['Mappings']['Resources'][res]['USRFILE']
        usrdata = open(usrdatafile, "r").read()
        # create bastion host instance
        self.bastion = ec2.BastionHostLinux(
            self,
            'MyBastion',
            vpc=self.vpc,
            security_group=self.bastionsg,
            subnet_selection=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
            instance_type=ec2.InstanceType(ressize),
            machine_image=ec2.AmazonLinuxImage(
                user_data=ec2.UserData.custom(usrdata),
                edition=ec2.AmazonLinuxEdition.STANDARD,
                generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2,
            ),
            instance_name=resname + region,
        )
        # add tags
        for tagsmap in resmap['Mappings']['Resources'][res]['TAGS']:
            for k,v in tagsmap.items():
                core.Tags.of(self.bastion).add(k,v,include_resource_types=["AWS::EC2::Instance"])
        # add my key
        self.bastion.instance.instance.add_property_override("KeyName", mykey)
        self.bastion.instance.instance.add_property_override("Ipv6AddressCount", 1)
        core.CfnOutput(
            self,
            "bastion",
            value=self.bastion.instance_id,
            export_name="bastion"
        )
        core.CfnOutput(
            self,
            "bastion-sg",
            value=self.bastionsg.security_group_id,
            export_name="bastion-sg"
        )
        core.CfnOutput(
            self,
            "bastion-ipv4",
            value=self.bastion.__getattribute__("instance_public_ip"),
            export_name="bastion-ipv4"
        )
