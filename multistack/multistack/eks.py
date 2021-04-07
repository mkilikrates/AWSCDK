import os
import json
import requests
import yaml
from aws_cdk import (
    aws_ec2 as ec2,
    aws_eks as eks,
    aws_iam as iam,
    core,
)
import multistack.ekselb as MyChart
import cdk8s as cdk8s
account = core.Aws.ACCOUNT_ID
region = core.Aws.REGION
resconf = "resourcesmap.cfg"
with open(resconf) as resfile:
    resmap = json.load(resfile)
with open('zonemap.cfg') as zonefile:
    zonemap = json.load(zonefile)
class EksStack(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, res, preflst, allowall, ipstack, vpc = ec2.Vpc, allowsg = ec2.SecurityGroup, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
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
        resvers = resmap['Mappings']['Resources'][res]['Version']
        resname = resmap['Mappings']['Resources'][res]['NAME']
        restype = resmap['Mappings']['Resources'][res]['Type']
        resfargtdns = resmap['Mappings']['Resources'][res]['FargateDNS']
        resendp = resmap['Mappings']['Resources'][res]['INTERNET']
        ressubgrp = resmap['Mappings']['Resources'][res]['SUBNETGRP']
        if 'ROLEADM' in resmap['Mappings']['Resources'][res]:
            resrole = resmap['Mappings']['Resources'][res]['ROLEADM']
        else:
            resrole = ''
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
        # Iam Role
        self.eksrole = iam.Role(
            self,
            f"{construct_id}-role",
            assumed_by=iam.ServicePrincipal('eks.amazonaws.com'),
            description="Role for EKS Cluster",
        )
        self.eksrole.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name('AmazonEKSServicePolicy'))
        self.eksrole.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name('AmazonEKSClusterPolicy'))
        # create security group for LB
        self.lbsg = ec2.SecurityGroup(
            self,
            f"{construct_id}MyLBsg",
            allow_all_outbound=True,
            vpc=self.vpc
        )
        # add egress rule
        ec2.CfnSecurityGroupEgress(
            self,
            f"{construct_id}EgressAllIpv4",
            ip_protocol="-1",
            cidr_ip="0.0.0.0/0",
            group_id=self.lbsg.security_group_id
        )
        if self.ipstack == 'Ipv6':
            ec2.CfnSecurityGroupEgress(
                self,
                f"{construct_id}EgressAllIpv6",
                ip_protocol="-1",
                cidr_ipv6="::/0",
                group_id=self.lbsg.security_group_id
            )
        # add ingress rule
        if self.allowsg != '':
            self.lbsg.add_ingress_rule(
                self.allowsg,
                ec2.Port.all_traffic()
            )
        if preflst == True:
            srcprefix = self.map.find_in_map(core.Aws.REGION, 'PREFIXLIST')
            self.lbsg.add_ingress_rule(
                ec2.Peer.prefix_list(srcprefix),
                ec2.Port.all_traffic()
            )
        if allowall == True:
            self.lbsg.add_ingress_rule(
                ec2.Peer.any_ipv4,
                ec2.Port.all_traffic()
            )
            if self.ipstack == 'Ipv6':
                self.lbsg.add_ingress_rule(
                    ec2.Peer.any_ipv6,
                    ec2.Port.all_traffic()
                )
        if type(allowall) == int or type(allowall) == float:
            self.lbsg.add_ingress_rule(
                ec2.Peer.any_ipv4(),
                ec2.Port.tcp(allowall)
            )
            if self.ipstack == 'Ipv6':
                self.lbsg.add_ingress_rule(
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
                    f"{construct_id}-ekscluster",
                    default_capacity=rescap,
                    default_capacity_instance=ec2.InstanceType.of(
                        instance_class=ec2.InstanceClass(resclass),
                        instance_size=ec2.InstanceSize(ressize),
                    ),
                    default_capacity_type=eks.DefaultCapacityType.NODEGROUP,
                    core_dns_compute_type=eksdnstype,
                    endpoint_access=eksendpt,
                    vpc=self.vpc,
                    version=eksvers,
                    role=self.eksrole,
                    output_masters_role_arn=True
                )
        else:
            if restype == 'EC2':
                self.eksclust = eks.Cluster(
                    self,
                    f"{construct_id}-ekscluster",
                    default_capacity=0,
                    core_dns_compute_type=eksdnstype,
                    endpoint_access=eksendpt,
                    vpc=self.vpc,
                    version=eksvers,
                    role=self.eksrole,
                    output_masters_role_arn=True
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
                        vpc_subnets=ec2.SubnetSelection(
                            subnet_group_name=ressubgrp,one_per_az=False
                        )
                    )
                    # add rules to node group security group
                    self.eksnodeasg.connections.allow_from(self.lbsg, port_range=ec2.Port(protocol=ec2.Protocol.ALL,string_representation='allow from sg'))
                    if allowsg != '':
                        self.eksnodeasg.connections.allow_from(allowsg, port_range=ec2.Port(protocol=ec2.Protocol.ALL,string_representation='allow from sg'))
                    if preflst == True:
                        self.eksnodeasg.connections.allow_from(ec2.Peer.prefix_list(srcprefix), port_range=ec2.Port(protocol=ec2.Protocol.ALL,string_representation='allow from prefixlist'))
                    if allowall == True:
                        self.eksnodeasg.connections.allow_from_any_ipv4()
                        if self.ipstack == 'Ipv6':
                            self.eksnodeasg.connections.allow_from(ec2.Peer.any_ipv6(), port_range=ec2.Port(protocol=ec2.Protocol.ALL,string_representation='allow all from ipv6'))
                    if self.ipstack == 'Ipv6':
                        self.eksnodeasg.connections.allow_to(ec2.Peer.any_ipv6(), port_range=ec2.Port(protocol=ec2.Protocol.ALL,string_representation='allow to anyv6'))
        # add rules to cluster control pane security group
        if allowsg != '':
            #self.eksclust.connections.add_security_group(allowsg)
            self.eksclust.connections.allow_default_port_from(allowsg)
        if preflst == True:
            self.eksclust.connections.allow_default_port_from(ec2.Peer.prefix_list(srcprefix))
        if allowall == True:
            self.eksclust.connections.allow_default_port_from_any_ipv4()
            if self.ipstack == 'Ipv6':
                ec2.CfnSecurityGroupIngress(self,f"{construct_id}EKSClusterSGAllowv6",group_id=self.eksclust.cluster_security_group_id, ip_protocol='-1', cidr_ipv6='::/0')
        # create openid provider to be used in rules
        iam.OpenIdConnectPrincipal(self.eksclust.open_id_connect_provider)
        # add custom role to master role of cluster
        if resrole != '':
            myrole = iam.Role.from_role_arn(
                self,
                f"{construct_id}AddRole",
                f"arn:{core.Aws.PARTITION}:iam:{core.Aws.ACCOUNT_ID}:role/{resrole}"
            )
            self.eksclust.aws_auth.add_masters_role(myrole)
        # service account for load balancer
        self.albsvcacc = self.eksclust.add_service_account(
            "aws-load-balancer-controller",
            name="aws-load-balancer-controller",
            namespace=('default')
        )
        url = 'https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/v2.1.3/docs/install/iam_policy.json'
        mypol = requests.get(url)
        mypolstat = json.dumps(mypol.json())
        mynewpol = json.loads(mypolstat)
        for statement in mynewpol['Statement']:
            self.albsvcacc.add_to_principal_policy(iam.PolicyStatement.from_json(statement))
        # load balancer controller
        self.eksclust.add_cdk8s_chart(
            "aws-load-balancer-controller",
            chart=MyChart.Albctrl(cdk8s.App(),"aws-load-balancer-controller", clustername = self.eksclust.cluster_name, namespace='default')
        ).node.add_dependency(self.albsvcacc)
        # service account for external dns controller
        self.dnsvcacc = self.eksclust.add_service_account(
            "external-dns",
            name="external-dns",
            namespace=('default')
        )
        # external dns controller
        self.manifest = MyChart.extdns(
                cdk8s.App(),
                "Manifest-external-dns",
                svcaccount = self.dnsvcacc,
        )
        # apply chart
        self.chart = self.eksclust.add_cdk8s_chart(
            "external-dns",
            chart=self.manifest
        ).node.add_dependency(self.dnsvcacc)

        # outputs
        core.CfnOutput(
            self,
            f"{construct_id}-eksclusterSG",
            value=self.eksclust.cluster_security_group_id
        )
        core.CfnOutput(
            self,
            f"{construct_id}-kubectlSG",
            value=self.eksclust.kubectl_security_group.security_group_id
        )
        core.CfnOutput(
            self,
            f"{construct_id}-kubectlRole",
            value=self.eksclust.kubectl_role.role_name
        )
        

