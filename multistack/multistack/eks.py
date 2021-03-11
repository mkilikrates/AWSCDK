import os
import json
from aws_cdk import (
    aws_ec2 as ec2,
    aws_eks as eks,
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
class EksStack(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, res, preflst, allowall, vpc = ec2.Vpc, allowsg = ec2.SecurityGroup, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.vpc = vpc
        if allowsg != '':
            self.allowsg = allowsg
        # get config for resource
        res = res
        resvers = resmap['Mappings']['Resources'][res]['Version']
        resname = resmap['Mappings']['Resources'][res]['NAME']
        restype = resmap['Mappings']['Resources'][res]['Type']
        resfargtdns = resmap['Mappings']['Resources'][res]['FargateDNS']
        resendp = resmap['Mappings']['Resources'][res]['INTERNET']
        ressubgrp = resmap['Mappings']['Resources'][res]['SUBNETGRP']
        if resendp == True:
            eksendpt = eks.EndpointAccess.PUBLIC
        if resendp == False:
            eksendpt = eks.EndpointAccess.PRIVATE
        if resendp == '':
            eksendpt = eks.EndpointAccess.PUBLIC_AND_PRIVATE
        if resfargtdns == True:
            eksdnstype = eks.CoreDnsComputeType.FARGATE
        else:
            eksdnstype = eks.CoreDnsComputeType.EC2
        if resvers == "V1_14":
            eksvers = eks.KubernetesVersion.V1_14
        if resvers == "V1_15":
            eksvers = eks.KubernetesVersion.V1_15
        if resvers == "V1_16":
            eksvers = eks.KubernetesVersion.V1_16
        if resvers == "V1_17":
            eksvers = eks.KubernetesVersion.V1_17
        if resvers == "V1_18":
            eksvers = eks.KubernetesVersion.V1_18
        if resvers == "V1_19":
            eksvers = eks.KubernetesVersion.V1_19
        # create security group for Auto Scale Group
        self.aseks = ec2.SecurityGroup(
            self,
            f"{construct_id}MyEKSsg",
            allow_all_outbound=True,
            vpc=self.vpc
        )
        # add egress rule
        if self.vpc.stack == 'Ipv6':
            ec2.CfnSecurityGroupEgress(
                self,
                f"{construct_id}ASGEgressAllIpv6",
                ip_protocol="-1",
                cidr_ipv6="::/0",
                group_id=self.aseks.security_group_id
            )
        else:
            ec2.CfnSecurityGroupEgress(
                self,
                f"{construct_id}ASGEgressAllIpv4",
                ip_protocol="-1",
                cidr_ip="0.0.0.0/0",
                group_id=self.aseks.security_group_id
            )
        # add ingress rule
        if allowsg != '':
            self.aseks.add_ingress_rule(
                self.allowsg,
                ec2.Port.all_traffic()
            )
        if preflst == True:
            # get prefix list from file to allow traffic from the office
            self.map = core.CfnMapping(
                self,
                f"{construct_id}Map",
                mapping=zonemap["Mappings"]["RegionMap"]
            )
            srcprefix = self.map.find_in_map(core.Aws.REGION, 'PREFIXLIST')
            self.aseks.add_ingress_rule(
                ec2.Peer.prefix_list(srcprefix),
                ec2.Port.all_traffic()
            )
        if allowall == True:
            self.aseks.add_ingress_rule(
                ec2.Peer.any_ipv4,
                ec2.Port.all_traffic()
            )
            self.aseks.add_ingress_rule(
                ec2.Peer.any_ipv6,
                ec2.Port.all_traffic()
            )
        if type(allowall) == int or type(allowall) == float:
            self.aseks.add_ingress_rule(
                ec2.Peer.any_ipv4(),
                ec2.Port.tcp(allowall)
            )
            self.aseks.add_ingress_rule(
                ec2.Peer.any_ipv6(),
                ec2.Port.tcp(allowall)
            )
        if 'desir' in resmap['Mappings']['Resources'][res]:
            rescap = resmap['Mappings']['Resources'][res]['desir']
            ressize = resmap['Mappings']['Resources'][res]['SIZE']
            resclass = resmap['Mappings']['Resources'][res]['CLASS']
            if restype == 'EC2':
                # create EKS Cluster
                self.eksclust = eks.Cluster(
                    self,
                    f"{construct_id}EKSCluster",
                    default_capacity=rescap,
                    default_capacity_instance=ec2.InstanceType.of(
                        instance_class=ec2.InstanceClass(resclass),
                        instance_size=ec2.InstanceSize(ressize),
                    ),
                    default_capacity_type=eks.DefaultCapacityType.NODEGROUP,
                    core_dns_compute_type=eksdnstype,
                    endpoint_access=eksendpt,
                    cluster_name=resname,
                    vpc=self.vpc,
                    vpc_subnets=self.vpc.select_subnets(subnet_group_name=ressubgrp,one_per_az=True).subnets,
                    version=eksvers,
                    security_group=self.aseks,
                )
            if allowsg != '':
                self.eksclust.connections.add_security_group(allowsg)
            if preflst == True:
                self.eksclust.connections.allow_default_port_from(ec2.Peer.prefix_list(srcprefix))
            if allowall == True:
                self.eksclust.connections.allow_default_port_from_any_ipv4()
        else:
            if restype == 'EC2':
                self.eksclust = eks.Cluster(
                    self,
                    f"{construct_id}EKSCluster",
                    default_capacity=0,
                    core_dns_compute_type=eksdnstype,
                    endpoint_access=eksendpt,
                    cluster_name=resname,
                    vpc=self.vpc,
                    vpc_subnets=self.vpc.select_subnets(subnet_group_name=ressubgrp,one_per_az=True).subnets,
                    version=eksvers,
                    security_group=self.aseks,
                )
                if 'NodeGrp' in resmap['Mappings']['Resources'][res]:
                    res = resmap['Mappings']['Resources'][res]['NodeGrp']
                    resname = resmap['Mappings']['Resources'][res]['NAME']
                    restype = resmap['Mappings']['Resources'][res]['Type']
                    mykey = resmap['Mappings']['Resources'][res]['KEY']
                    ressubgrp = resmap['Mappings']['Resources'][res]['SUBNETGRP']
                    rescap = resmap['Mappings']['Resources'][res]['desir']
                    resmin = resmap['Mappings']['Resources'][res]['min']
                    resmax = resmap['Mappings']['Resources'][res]['max']
                    ressize = resmap['Mappings']['Resources'][res]['SIZE']
                    resclass = resmap['Mappings']['Resources'][res]['CLASS']
                    respubip = resmap['Mappings']['Resources'][res]['PUBIP']
                    if restype == 'ON_DEMAND':
                        captype = eks.CapacityType.ON_DEMAND
                    if restype == 'SPOT':
                        captype = eks.CapacityType.SPOT
                    if allowsg != '':
                        self.allowsg = allowsg
                    else:
                        self.allowsg = self.aseks
                    self.eksnodeasg = self.eksclust.add_auto_scaling_group_capacity(
                        f"{construct_id}EKSNodeGrp",
                        instance_type=ec2.InstanceType.of(
                            instance_class=ec2.InstanceClass(resclass),
                            instance_size=ec2.InstanceSize(ressize),
                        ),
                        bootstrap_enabled=True,
                        bootstrap_options=None,
                        machine_image_type=eks.MachineImageType.AMAZON_LINUX_2,
                        allow_all_outbound=True,
                        associate_public_ip_address=respubip,
                        desired_capacity=rescap,
                        key_name=f"{mykey}{region}",
                        max_capacity=resmax,
                        min_capacity=resmin,
                        vpc_subnets=ec2.SubnetSelection(subnet_group_name=ressubgrp,one_per_az=True)
                    ).add_security_group(self.aseks)
                    # self.eksnodeasg = eks.Nodegroup(
                    #     self,
                    #     f"{construct_id}EKSNodeGrp",
                    #     cluster=self.eksclust,
                    #     capacity_type=captype,
                    #     desired_size=rescap,
                    #     instance_types=[
                    #         ec2.InstanceType.of(
                    #             instance_class=ec2.InstanceClass(resclass),
                    #             instance_size=ec2.InstanceSize(ressize),
                    #         )
                    #     ],
                    #     min_size=resmin,
                    #     max_size=resmax,
                    #     nodegroup_name=resname,
                    #     subnets=ec2.SubnetSelection(subnet_group_name=ressubgrp,one_per_az=True),
                    #     remote_access=eks.NodegroupRemoteAccess(
                    #         ssh_key_name=f"{mykey}{region}",
                    #         source_security_groups=[self.allowsg]
                    #     )
                    # )
        # self.eksoidc = iam.OpenIdConnectProvider(
        #     self,
        #     f"{construct_id}OIDC",
        #     url=self.eksclust.cluster_open_id_connect_issuer_url,
        #     client_ids=['sts.amazonaws.com']
        # )