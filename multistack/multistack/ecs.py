import os
import json
from aws_cdk import (
    aws_ec2 as ec2,
    aws_ecs as ecs,
    aws_ecs_patterns as ecs_patterns,
    aws_iam as iam,
    core,
)
account = core.Aws.ACCOUNT_ID
region = core.Aws.REGION
resconf = "resourcesmap.cfg"
with open(resconf) as resfile:
    resmap = json.load(resfile)
with open('zonemap.cfg') as zonefile:
    zonemap = json.load(zonefile)
class EcsStack(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, res, preflst, allowall, ipstack, vpc = ec2.Vpc, allowsg = ec2.SecurityGroup, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # from https://github.com/aws-samples/aws-cdk-examples/blob/master/python/ecs/ecs-service-with-advanced-alb-config/app.py
        # get imported objects
        self.vpc = vpc
        self.ipstack = ipstack
        if allowsg != '':
            self.allowsg = allowsg
        if preflst == True:
            # get prefix list from file to allow traffic from the office
            self.map = core.CfnMapping(
                self,
                f"{construct_id}Map",
                mapping=zonemap["Mappings"]["RegionMap"]
            )
            srcprefix = self.map.find_in_map(core.Aws.REGION, 'PREFIXLIST')
        # get config for resource
        res = res
        resname = resmap['Mappings']['Resources'][res]['NAME']
        mykey = resmap['Mappings']['Resources'][res]['KEY']
        restype = resmap['Mappings']['Resources'][res]['Type']
        ressubgrp = resmap['Mappings']['Resources'][res]['SUBNETGRP']
        rescap = resmap['Mappings']['Resources'][res]['desir']
        mincap = resmap['Mappings']['Resources'][res]['min']
        maxcap = resmap['Mappings']['Resources'][res]['max']
        ressize = resmap['Mappings']['Resources'][res]['SIZE']
        resclass = resmap['Mappings']['Resources'][res]['CLASS']
        self.ecs = ecs.Cluster(
            self,
            f"{construct_id}-ecscluster",
            cluster_name=resname,
            vpc=self.vpc
        )
        if ressubgrp == 'Public':
            respubip = True
        else:
            respubip = False
        self.ecs.add_capacity(
            f"{construct_id}-ecsnodes",
            instance_type=ec2.InstanceType.of(
                    instance_class=ec2.InstanceClass(resclass),
                    instance_size=ec2.InstanceSize(ressize)
                ),
            # machine_image=ec2.AmazonLinuxImage(
            #     #user_data=ec2.UserData.custom(usrdata),
            #     edition=ec2.AmazonLinuxEdition.STANDARD,
            #     generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2
            # ),
            associate_public_ip_address=respubip,
            desired_capacity=rescap,
            min_capacity=mincap,
            max_capacity=maxcap,
            key_name=f"{mykey}{region}",
            vpc_subnets=ec2.SubnetSelection(subnet_group_name=ressubgrp,one_per_az=True),
        )
        # add rules to node group security group
        if allowsg != '':
            self.ecs.connections.allow_from(allowsg, port_range=ec2.Port(protocol=ec2.Protocol.ALL,string_representation='allow from sg'))
        if preflst == True:
            self.ecs.connections.allow_from(ec2.Peer.prefix_list(srcprefix), port_range=ec2.Port(protocol=ec2.Protocol.ALL,string_representation='allow from prefixlist'))
        if allowall == True:
            self.ecs.connections.allow_from_any_ipv4()
            if self.ipstack == 'Ipv6':
                self.ecs.connections.allow_from(ec2.Peer.any_ipv6(), port_range=ec2.Port(protocol=ec2.Protocol.ALL,string_representation='allow all from ipv6'))
        if self.ipstack == 'Ipv6':
            self.ecs.connections.allow_to(ec2.Peer.any_ipv6(), port_range=ec2.Port(protocol=ec2.Protocol.ALL,string_representation='allow to anyv6'))

        self.task = ecs.Ec2TaskDefinition(
            self,
            f"{construct_id}-task"
        )
        self.container = self.task.add_container(
            f"{construct_id}-task-web",
            image=ecs.ContainerImage.from_registry(
                'amazon/amazon-ecs-sample'
            ),
            memory_limit_mib=256
        )
        self.portmap = ecs.PortMapping(
            container_port=80,
            host_port=8080,
            protocol=ecs.Protocol.TCP
        )
        self.container.add_port_mappings(self.portmap)

        self.srvc = ecs.Ec2Service(
            self,
            f"{construct_id}-service",
            cluster=self.ecs,
            task_definition=self.task
        )


