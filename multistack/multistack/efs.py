from ctypes.wintypes import SIZE
import os
import json
from aws_cdk import (
    aws_ec2 as ec2,
    aws_kms as kms,
    aws_efs as efs,
    aws_route53 as r53,
    aws_route53_targets as r53tgs,
    aws_iam as iam,
    core,
)

account = core.Aws.ACCOUNT_ID
region = core.Aws.REGION
class main(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, res, preflst, allowall, ipstack, vpc = ec2.Vpc, allowsg = ec2.SecurityGroup, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.vpc = vpc
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
        self.efssg = ec2.SecurityGroup(
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
            group_id=self.efssg.security_group_id
        )
        if self.ipstack == 'Ipv6':
            ec2.CfnSecurityGroupEgress(
                self,
                f"{construct_id}EgressAllIpv6",
                ip_protocol="-1",
                cidr_ipv6="::/0",
                group_id=self.efssg.security_group_id
            )
        # add ingress rule
        if allowsg != '':
            self.efssg.add_ingress_rule(
                allowsg,
                ec2.Port.all_traffic()
            )
        if preflst == True:
            srcprefix = self.map.find_in_map(core.Aws.REGION, 'PREFIXLIST')
            self.efssg.add_ingress_rule(
                ec2.Peer.prefix_list(srcprefix),
                ec2.Port.all_traffic()
            )
        if allowall == True:
            self.efssg.add_ingress_rule(
                ec2.Peer.any_ipv4(),
                ec2.Port.all_traffic()
            )
            if self.ipstack == 'Ipv6':
                self.efssg.add_ingress_rule(
                    ec2.Peer.any_ipv6(),
                    ec2.Port.all_traffic()
                )
        if type(allowall) == int or type(allowall) == float:
            self.efssg.add_ingress_rule(
                ec2.Peer.any_ipv4(),
                ec2.Port.tcp(allowall)
            )
            if self.ipstack == 'Ipv6':
                self.efssg.add_ingress_rule(
                    ec2.Peer.any_ipv6(),
                    ec2.Port.tcp(allowall)
                )
        if 'NAME' in resmap['Mappings']['Resources'][res]:
            resname = resmap['Mappings']['Resources'][res]['NAME']
        else:
            resname = None
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
        if 'SUBNETGRP' in resmap['Mappings']['Resources'][res]:
            ressubgrp = ec2.SubnetSelection(subnet_group_name=resmap['Mappings']['Resources'][res]['SUBNETGRP'],one_per_az=True)
        else:
            ressubgrp = ec2.SubnetSelection(subnet_group_name='Endpoints',one_per_az=True)
        if 'CRYPT' in resmap['Mappings']['Resources'][res]:
            resencrypt = True
            resencrest = resmap['Mappings']['Resources'][res]['CRYPT']
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
            encryptkey = kms.Key(
                self,
                f"{construct_id}Key",
                alias=resencrest['Keyid'],
                description="Key for EFS Encrypt at Rest",
                key_usage=kms.KeyUsage.ENCRYPT_DECRYPT,
                enabled=True,
                key_spec=cripkey,
                policy=None,
                enable_key_rotation=keyrot,
                removal_policy=rempol,
                pending_window=penwin
            )
        else:
            resencrypt = False
            encryptkey = None
        if 'BKP' in resmap['Mappings']['Resources'][res]:
            resbkp = resmap['Mappings']['Resources'][res]['BKP']
        else:
            resbkp = False
        if 'LIFECYCLE' in resmap['Mappings']['Resources'][res]:
            if resmap['Mappings']['Resources'][res]['LIFECYCLE'] == 7:
                reslbkpfcc = efs.LifecyclePolicy.AFTER_7_DAYS
            if resmap['Mappings']['Resources'][res]['LIFECYCLE'] == 14:
                reslbkpfcc = efs.LifecyclePolicy.AFTER_14_DAYS
            if resmap['Mappings']['Resources'][res]['LIFECYCLE'] == 30:
                reslbkpfcc = efs.LifecyclePolicy.AFTER_30_DAYS
            if resmap['Mappings']['Resources'][res]['LIFECYCLE'] == 60:
                reslbkpfcc = efs.LifecyclePolicy.AFTER_60_DAYS
            if resmap['Mappings']['Resources'][res]['LIFECYCLE'] == 90:
                reslbkpfcc = efs.LifecyclePolicy.AFTER_90_DAYS
        else:
            reslbkpfcc = None
        if 'PERFMODE' in resmap['Mappings']['Resources'][res]:
            if resmap['Mappings']['Resources'][res]['PERFMODE'] == 'GENERAL_PURPOSE':
                resperfmode = efs.PerformanceMode.GENERAL_PURPOSE
            if resmap['Mappings']['Resources'][res]['PERFMODE'] == 'MAX_IO':
                resperfmode = efs.PerformanceMode.MAX_IO
        else:
            resperfmode = efs.PerformanceMode.GENERAL_PURPOSE
        if 'THROUGHPUT' in resmap['Mappings']['Resources'][res]:
            resthroughputmode = efs.ThroughputMode.PROVISIONED
            resthroughputsize = core.Size.mebibytes(resmap['Mappings']['Resources'][res]['THROUGHPUT'])
        else:
            resthroughputmode = efs.ThroughputMode.BURSTING
            resthroughputsize = None
        self.filesystem = efs.FileSystem(
            self,
            f"{construct_id}",
            vpc=self.vpc,
            security_group=self.efssg,
            vpc_subnets=ressubgrp,
            encrypted=resencrypt,
            kms_key=encryptkey,
            file_system_name=resname,
            enable_automatic_backups=resbkp,
            lifecycle_policy=reslbkpfcc,
            out_of_infrequent_access_policy=efs.OutOfInfrequentAccessPolicy.AFTER_1_ACCESS,
            performance_mode=resperfmode,
            throughput_mode=resthroughputmode,
            provisioned_throughput_per_second=resthroughputsize
        )
        self.filesystemaccesspoint = self.filesystem.add_access_point(
            f"{construct_id}AcessPoint"
        )
        core.CfnOutput(
            self,
            f"{construct_id}FSid",
            value=self.filesystem.file_system_id
        )

        if appdomain != None and resname != None:
            self.efsfqdn = r53.CnameRecord(
                self,
                f"{construct_id}FQDN",
                zone=self.hz,
                record_name=f"{resname}.{appdomain}",
                domain_name=f"{self.filesystem.file_system_id}.efs.{region}.amazonaws.com",
                ttl=core.Duration.minutes(60),
            )
            core.CfnOutput(
                self,
                f"{construct_id}EFSFQDN",
                value=f"{resname}.{appdomain}"
            )
