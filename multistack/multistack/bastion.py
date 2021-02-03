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
class bastion(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, res, preflst, allowall, vpc = ec2.Vpc, allowsg = ec2.SecurityGroup, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.vpc = vpc
        res = res
        # get prefix list from file to allow traffic from the office
        srcprefix = zonemap['Mappings']['RegionMap'][region]['PREFIXLIST']        
        # create security group for bastion
        self.bastionsg = ec2.SecurityGroup(
            self,
            f"{construct_id}SG",
            allow_all_outbound=True,
            vpc=self.vpc
        )
        # add egress rule
        ec2.CfnSecurityGroupEgress(
            self,
            f"{construct_id}EgressAllIpv4",
            ip_protocol="-1",
            cidr_ip="0.0.0.0/0",
            group_id=self.bastionsg.security_group_id
        )
         # add ingress rules
        if allowsg != '':
            self.bastionsg.add_ingress_rule(
                self.allowsg,
                ec2.Port.all_traffic()
            )
        if preflst == True:
            # get prefix list from file to allow traffic from the office
            srcprefix = zonemap['Mappings']['RegionMap'][region]['PREFIXLIST']        
            self.bastionsg.add_ingress_rule(
                ec2.Peer.prefix_list(srcprefix),
                ec2.Port.all_traffic()
            )
        if allowall == True:
            self.bastionsg.add_ingress_rule(
                ec2.Peer.any_ipv4,
                ec2.Port.all_traffic()
            )
        if type(allowall) == int or type(allowall) == float:
            self.bastionsg.add_ingress_rule(
                ec2.Peer.any_ipv4(),
                ec2.Port.tcp(allowall)
            )
        self.bastionsg.add_ingress_rule(
            self.bastionsg,
            ec2.Port.all_traffic()
        )
        if self.vpc.stack == 'Ipv6':
            ec2.CfnSecurityGroupEgress(
                self,
                f"{construct_id}EgressAllIpv6",
                ip_protocol="-1",
                cidr_ipv6="::/0",
                group_id=self.bastionsg.security_group_id
            )
            if allowall == True:
                self.bastionsg.add_ingress_rule(
                    ec2.Peer.any_ipv6,
                    ec2.Port.all_traffic()
                )
            if type(allowall) == int or type(allowall) == float:
                self.bastionsg.add_ingress_rule(
                    ec2.Peer.any_ipv6(),
                    ec2.Port.all_traffic()
                )

        # get data for bastion resource
        resname = resmap['Mappings']['Resources'][res]['NAME']
        ressize = resmap['Mappings']['Resources'][res]['SIZE']
        resclass = resmap['Mappings']['Resources'][res]['CLASS']
        mykey = resmap['Mappings']['Resources'][res]['KEY'] + region
        usrdatafile = resmap['Mappings']['Resources'][res]['USRFILE']
        usrdata = open(usrdatafile, "r").read()
        # create bastion host instance
        self.bastion = ec2.BastionHostLinux(
            self,
            f"{construct_id}",
            vpc=self.vpc,
            security_group=self.bastionsg,
            subnet_selection=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
            instance_type=ec2.InstanceType.of(
                instance_class=ec2.InstanceClass(resclass),
                instance_size=ec2.InstanceSize(ressize)
            ),
            machine_image=ec2.AmazonLinuxImage(
                user_data=ec2.UserData.custom(usrdata),
                edition=ec2.AmazonLinuxEdition.STANDARD,
                generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2,
            ),
            instance_name=f"{resname}-{region}",
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
            f"{construct_id}:id",
            value=self.bastion.instance_id,
            export_name=f"{construct_id}:id"
        )
        core.CfnOutput(
            self,
            f"{construct_id}:sg",
            value=self.bastionsg.security_group_id,
            export_name=f"{construct_id}:sg"
        )
        core.CfnOutput(
            self,
            f"{construct_id}:ipv4",
            value=self.bastion.__getattribute__("instance_public_ip"),
            export_name=f"{construct_id}:ipv4"
        )
        if self.vpc.stack == 'Ipv6':
            self.bastion.instance.instance.add_property_override("Ipv6AddressCount", 1)
