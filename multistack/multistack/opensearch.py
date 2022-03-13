import os
import json
from aws_cdk import (
    aws_ec2 as ec2,
    aws_kms as kms,
    aws_opensearchservice as opensearch,
    aws_route53 as r53,
    aws_route53_targets as r53tgs,
    aws_iam as iam,
    core,
)

account = core.Aws.ACCOUNT_ID
region = core.Aws.REGION
class main(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, res, preflst, allowall, ipstack, maxaz = int, vpc = ec2.Vpc, allowsg = ec2.SecurityGroup, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        res = res
        self.ipstack = ipstack
        if allowsg != '':
            self.allowsg = allowsg
        resconf = "resourcesmap.cfg"
        with open(resconf) as resfile:
            resmap = json.load(resfile)
        with open('zonemap.cfg') as zonefile:
            zonemap = json.load(zonefile)
        # get prefix list from file to allow traffic from the office
        self.map = core.CfnMapping(
            self,
            f"{construct_id}Map",
            mapping=zonemap["Mappings"]["RegionMap"]
        )
        # create security group for ec2
        if vpc != '':
            self.vpc = vpc
            self.opensearchsg = ec2.SecurityGroup(
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
                group_id=self.opensearchsg.security_group_id
            )
            if self.ipstack == 'Ipv6':
                ec2.CfnSecurityGroupEgress(
                    self,
                    f"{construct_id}EgressAllIpv6",
                    ip_protocol="-1",
                    cidr_ipv6="::/0",
                    group_id=self.opensearchsg.security_group_id
                )
            # add ingress rule
            if allowsg != '':
                self.opensearchsg.add_ingress_rule(
                    allowsg,
                    ec2.Port.all_traffic()
                )
            if preflst == True:
                srcprefix = self.map.find_in_map(core.Aws.REGION, 'PREFIXLIST')
                self.opensearchsg.add_ingress_rule(
                    ec2.Peer.prefix_list(srcprefix),
                    ec2.Port.all_traffic()
                )
            if allowall == True:
                self.opensearchsg.add_ingress_rule(
                    ec2.Peer.any_ipv4(),
                    ec2.Port.all_traffic()
                )
                if self.ipstack == 'Ipv6':
                    self.opensearchsg.add_ingress_rule(
                        ec2.Peer.any_ipv6(),
                        ec2.Port.all_traffic()
                    )
            if type(allowall) == int or type(allowall) == float:
                self.opensearchsg.add_ingress_rule(
                    ec2.Peer.any_ipv4(),
                    ec2.Port.tcp(allowall)
                )
                if self.ipstack == 'Ipv6':
                    self.opensearchsg.add_ingress_rule(
                        ec2.Peer.any_ipv6(),
                        ec2.Port.tcp(allowall)
                    )
            if 'SUBNETGRP' in resmap['Mappings']['Resources'][res]:
                ressubgrp = [ec2.SubnetSelection(subnet_group_name=resmap['Mappings']['Resources'][res]['SUBNETGRP'],one_per_az=True)]
            else:
                ressubgrp = [ec2.SubnetSelection(subnet_group_name='Endpoints',one_per_az=True)]
        else:
            self.vpc = None
            self.opensearchsg = None
            ressubgrp = None
        # Service Link Role
        self.domain_servicelinkrole = iam.CfnServiceLinkedRole(
            self,
            f"{construct_id}ServiceLinkRole",
            aws_service_name='opensearchservice.amazonaws.com',
        )
        if 'NAME' in resmap['Mappings']['Resources'][res]:
            resname = resmap['Mappings']['Resources'][res]['NAME']
        else:
            resname = res
        if 'DOMAIN' in resmap['Mappings']['Resources'][res]:
            appdomain = resmap['Mappings']['Resources'][res]['DOMAIN']
            # get hosted zone id
            self.hz = r53.HostedZone.from_lookup(
                self,
                f"{construct_id}:Domain",
                domain_name=appdomain,
                private_zone=True
            )
        else:
            appdomain = None

        if 'Version' in resmap['Mappings']['Resources'][res]:
            resvers = resmap['Mappings']['Resources'][res]['Version']
            if resmap['Mappings']['Resources'][res]['Version'] == 'OPENSEARCH_1_0':
                resvers = opensearch.EngineVersion.OPENSEARCH_1_0
            if resmap['Mappings']['Resources'][res]['Version'] == 'OPENSEARCH_1_1':
                resvers = opensearch.EngineVersion.OPENSEARCH_1_1
        else:
            resvers = opensearch.EngineVersion.OPENSEARCH_1_1
        if 'MSIZE' in resmap['Mappings']['Resources'][res]:
            resmsize = resmap['Mappings']['Resources'][res]['MSIZE']
        else:
            resmsize = 't3.small.search'
        if 'SIZE' in resmap['Mappings']['Resources'][res]:
            ressize = resmap['Mappings']['Resources'][res]['SIZE']
        else:
            ressize = 't3.small.search'
        if 'WSIZE' in resmap['Mappings']['Resources'][res]:
            reswsize = resmap['Mappings']['Resources'][res]['WSIZE']
        else:
            reswsize = None
        if 'desirm' in resmap['Mappings']['Resources'][res]:
            desirmcap = resmap['Mappings']['Resources'][res]['desirm']
        else:
            desirmcap = 1
        if 'desirw' in resmap['Mappings']['Resources'][res]:
            desirwcap = resmap['Mappings']['Resources'][res]['desirw']
        else:
            desirwcap = None
        if 'desir' in resmap['Mappings']['Resources'][res]:
            desircap = resmap['Mappings']['Resources'][res]['desir']
        else:
            desircap = 1
        if 'AZAWARE' in resmap['Mappings']['Resources'][res]:
            azawsare = resmap['Mappings']['Resources'][res]['AZAWARE']
            azcount = maxaz
        else:
            azawsare = False
            azcount = None
        if 'VOLUMES' in resmap['Mappings']['Resources'][res]:
            for vol in resmap['Mappings']['Resources'][res]['VOLUMES']:
                if 'SIZE' in vol:
                    resvolsize = vol['SIZE']
                else:
                    resvolsize = 10
                if 'IOPS' in vol:
                    resvoliops = vol['IOPS']
                else:
                    resvoliops = None
                if 'TYPE' in vol:
                    if vol['TYPE'] == 'GP2':
                        resvoltype = ec2.EbsDeviceVolumeType.GP2
                    if vol['TYPE'] == 'GP3':
                        resvoltype = ec2.EbsDeviceVolumeType.GP3
                else:
                    resvoltype = ec2.EbsDeviceVolumeType.GP2
            resebs = opensearch.EbsOptions(
                enabled=True,
                iops=resvoliops,
                volume_size=resvolsize,
                volume_type=resvoltype
            )
        else:
            resebs = None
        if 'RCRYPT' in resmap['Mappings']['Resources'][res]:
            resencrest = resmap['Mappings']['Resources'][res]['RCRYPT']
            if 'Crypkey' in resencrest:
                cripkey = kms.KeySpec(value=resencrest['Crypkey'])
            else:
                cripkey = kms.KeySpec.SYMMETRIC_DEFAULT
            if 'keyrot' in resencrest:
                keyrot = resencrest['keyrot']
            else:
                keyrot = False

            if 'penwin' in resencrest:
                penwin = core.Duration.days(resencrest['penwin'])
            else:
                penwin = core.Duration.days(7)
            if 'rempol' in resencrest:
                rempol = core.RemovalPolicy(resencrest['rempol'])
            else:
                rempol = core.RemovalPolicy.DESTROY
            encrestkey = kms.Key(
                self,
                f"{construct_id}Key",
                alias=resencrest['Keyid'],
                description="Key for Opensearch Encrypt at Rest",
                key_usage=kms.KeyUsage.ENCRYPT_DECRYPT,
                enabled=True,
                key_spec=cripkey,
                policy=None,
                enable_key_rotation=keyrot,
                removal_policy=rempol,
                pending_window=penwin
            )
            encrestcfg = opensearch.EncryptionAtRestOptions(
                enabled=True,
                kms_key=encrestkey
            )
        else:
            encrestcfg = None
        self.domain = opensearch.Domain(
            self,
            f"{construct_id}Domain",
            version=resvers,
            capacity=opensearch.CapacityConfig(
                master_node_instance_type=resmsize,
                master_nodes=desirmcap,
                data_node_instance_type=ressize,
                data_nodes=desircap,
                warm_instance_type=reswsize,
                warm_nodes=desirwcap
            ),
            zone_awareness=opensearch.ZoneAwarenessConfig(
                enabled=azawsare,
                availability_zone_count=azcount
            ),
            vpc=self.vpc,
            security_groups=[self.opensearchsg],
            vpc_subnets=ressubgrp,
            ebs=resebs,
            encryption_at_rest=encrestcfg,
            enforce_https=True,
            node_to_node_encryption=True
        )
        self.domain.node.add_dependency(self.domain_servicelinkrole)
        self.domain.node.add_dependency(self.opensearchsg)
        core.CfnOutput(
            self,
            f"{construct_id}DomainName",
            value=self.domain.domain_name
        )
        core.CfnOutput(
            self,
            f"{construct_id}DomainEndpoint",
            value=self.domain.domain_endpoint
        )
        if appdomain != None and resname != None:
            self.domainfqdn = r53.CnameRecord(
                self,
                f"{construct_id}FQDN",
                zone=self.hz,
                record_name=f"{resname}.{appdomain}",
                domain_name=self.domain.domain_endpoint,
                ttl=core.Duration.minutes(60),
            )
            core.CfnOutput(
                self,
                f"{construct_id}ClusterFQDN",
                value=f"{resname}.{appdomain}"
            )

