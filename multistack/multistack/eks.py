import os
import json
from aws_cdk import (
    aws_ec2 as ec2,
    aws_eks as eks,
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
        resfargt = resmap['Mappings']['Resources'][res]['Fargate']
        ressize = resmap['Mappings']['Resources'][res]['SIZE']
        resclass = resmap['Mappings']['Resources'][res]['CLASS']
        rescap = resmap['Mappings']['Resources'][res]['desir']
        resendp = resmap['Mappings']['Resources'][res]['INTERNET']
        ressubgrp = resmap['Mappings']['Resources'][res]['SUBNETGRP']
        if resendp == True:
            eksendpt = eks.EndpointAccess.PUBLIC
        if resendp == False:
            eksendpt = eks.EndpointAccess.PRIVATE
        if resendp == '':
            eksendpt = eks.EndpointAccess.PUBLIC_AND_PRIVATE
        if resfargt == True:
            ekstype = eks.CoreDnsComputeType.FARGATE
        else:
            ekstype = eks.CoreDnsComputeType.EC2
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
            mymap = core.CfnMapping(
                self,
                f"{construct_id}Map",
                mapping=zonemap["Mappings"]["RegionMap"]
            )
            srcprefix = mymap.find_in_map(core.Aws.REGION, 'PREFIXLIST')
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
            core_dns_compute_type=ekstype,
            endpoint_access=eksendpt,
            cluster_name=resname,
            vpc=self.vpc,
            vpc_subnets=self.vpc.select_subnets(subnet_group_name=ressubgrp,one_per_az=True).subnets,
            version=eksvers
        )