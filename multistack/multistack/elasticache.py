import os
import json
from aws_cdk import (
    aws_ec2 as ec2,
    aws_logs as log,
    aws_kinesis as kinesis,
    aws_kms as kms,
    aws_elasticache as elasticache,
    aws_certificatemanager as acm,
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
        self.elasticachesg = ec2.SecurityGroup(
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
            group_id=self.elasticachesg.security_group_id
        )
        if self.ipstack == 'Ipv6':
            ec2.CfnSecurityGroupEgress(
                self,
                f"{construct_id}EgressAllIpv6",
                ip_protocol="-1",
                cidr_ipv6="::/0",
                group_id=self.elasticachesg.security_group_id
            )
        # add ingress rule
        if allowsg != '':
            self.elasticachesg.add_ingress_rule(
                allowsg,
                ec2.Port.all_traffic()
            )
        if preflst == True:
            srcprefix = self.map.find_in_map(core.Aws.REGION, 'PREFIXLIST')
            self.elasticachesg.add_ingress_rule(
                ec2.Peer.prefix_list(srcprefix),
                ec2.Port.all_traffic()
            )
        if allowall == True:
            self.elasticachesg.add_ingress_rule(
                ec2.Peer.any_ipv4(),
                ec2.Port.all_traffic()
            )
            if self.ipstack == 'Ipv6':
                self.elasticachesg.add_ingress_rule(
                    ec2.Peer.any_ipv6(),
                    ec2.Port.all_traffic()
                )
        if type(allowall) == int or type(allowall) == float:
            self.elasticachesg.add_ingress_rule(
                ec2.Peer.any_ipv4(),
                ec2.Port.tcp(allowall)
            )
            if self.ipstack == 'Ipv6':
                self.elasticachesg.add_ingress_rule(
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
            ressubgrp = resmap['Mappings']['Resources'][res]['SUBNETGRP']
        else:
            ressubgrp = 'Endpoints'
        if 'SIZE' in resmap['Mappings']['Resources'][res]:
            ressize = resmap['Mappings']['Resources'][res]['SIZE']
        else:
            ressize = 'cache.t3.micro'

        if 'LOGS' in resmap['Mappings']['Resources'][res]:
            reslogs = resmap['Mappings']['Resources'][res]['LOGS']
        else:
            reslogs = ''
        # enable logs
        if reslogs != '':
            elasticachelogconfig = []
            for logcfg in reslogs:
                if 'logGroup' in logcfg['LogDestination']:
                    elasticacheloggroup = log.LogGroup(
                        self,
                        f"{construct_id}LogGroup",
                        logcfg['LogDestination']['logGroup'],
                        retention=log.RetentionDays.ONE_WEEK
                    )
                    mylogdstcfg = elasticache.CfnCacheCluster.DestinationDetailsProperty(
                        cloud_watch_logs_details=elasticache.CfnCacheCluster.CloudWatchLogsDestinationDetailsProperty(
                            log_group=elasticacheloggroup.log_group_name
                        )
                    )
                    elasticacheloggtype = 'cloudwatch-logs'
                    elasticachelogconfig.append(elasticache.CfnCacheCluster.LogDeliveryConfigurationRequestProperty(
                        destination_details=elasticache.CfnCacheCluster.DestinationDetailsProperty(mylogdstcfg),
                        destination_type=elasticacheloggtype
                    ))
                if 'logStream' in logcfg['LogDestination']:
                    if 'logStreamkeyid' in logcfg['LogDestination']:
                        if 'Crypkey' in logcfg['LogDestination']:
                            cripkey = kms.KeySpec(value=logcfg['LogDestination']['Crypkey'])
                        else:
                            cripkey = kms.KeySpec.SYMMETRIC_DEFAULT
                        if 'keyrot' in logcfg['LogDestination']:
                            keyrot = logcfg['LogDestination']['keyrot']
                        else:
                            keyrot = False

                        if 'penwin' in logcfg['LogDestination']:
                            penwin = core.Duration.days(logcfg['LogDestination']['penwin'])
                        else:
                            penwin = core.Duration.days(7)
                        if 'rempol' in logcfg['LogDestination']:
                            rempol = core.RemovalPolicy(logcfg['LogDestination']['rempol'])
                        else:
                            rempol = core.RemovalPolicy.DESTROY
                        logstreamkey = kms.Key(
                            self,
                            f"{construct_id}LogStreamKey",
                            alias=logcfg['LogDestination']['logStreamkeyid'],
                            description="Key for Kinesis Stream",
                            key_usage=kms.KeyUsage.ENCRYPT_DECRYPT,
                            enabled=True,
                            key_spec=cripkey,
                            policy=None,
                            enable_key_rotation=keyrot,
                            removal_policy=rempol,
                            pending_window=penwin
                        )
                        if 'Crypkey' in logcfg['LogDestination']:
                            streamencrypt = kinesis.CfnStream.StreamEncryptionProperty(
                                encryption_type='KMS',
                                key_id=logstreamkey.key_id
                            )
                        else:
                            streamencrypt = None
                        elasticachelogstream = kinesis.CfnStream(
                            self,
                            f"{construct_id}LogStream",
                            stream_encryption=streamencrypt
                        )
                        mylogdstcfg = elasticache.CfnCacheCluster.DestinationDetailsProperty(
                            kinesis_firehose_details=elasticache.CfnCacheCluster.KinesisFirehoseDestinationDetailsProperty(
                                delivery_stream=elasticachelogstream
                            )
                        )
                    elasticacheloggtype = 'kinesis-firehose'
                    elasticachelogconfig.append(elasticache.CfnCacheCluster.LogDeliveryConfigurationRequestProperty(
                        destination_details=elasticache.CfnCacheCluster.DestinationDetailsProperty(mylogdstcfg),
                        destination_type=elasticacheloggtype
                    ))
        else:
            elasticachelogconfig = None
        if 'AZMODE' in resmap['Mappings']['Resources'][res]:
            azmode = resmap['Mappings']['Resources'][res]['AZMODE']
        else:
            azmode = None
        if 'desir' in resmap['Mappings']['Resources'][res]:
            desircap = resmap['Mappings']['Resources'][res]['desir']
        else:
            desircap = 1
        if 'ENGINE' in resmap['Mappings']['Resources'][res]:
            engine = resmap['Mappings']['Resources'][res]['ENGINE']
        else:
            engine = 'memcached'

        cachesubnetgroup = elasticache.CfnSubnetGroup(
            self,
            f"{construct_id}SubnetGrp",
            description=f"{construct_id}SubnetGrp",
            subnet_ids=self.vpc.select_subnets(subnet_group_name=ressubgrp,one_per_az=True).subnet_ids,
        )
        self.cache_cluster = elasticache.CfnCacheCluster(
            self,
            f"{construct_id}",
            cache_node_type=ressize,
            engine=engine,
            az_mode=azmode,
            num_cache_nodes=desircap,
            cache_subnet_group_name=cachesubnetgroup.cache_subnet_group_name,
            vpc_security_group_ids=[self.elasticachesg.security_group_id],
            cluster_name=resname,
            log_delivery_configurations=elasticachelogconfig,
            auto_minor_version_upgrade=True
        )
        core.CfnOutput(
            self,
            f"{construct_id}ClusterName",
            value=self.cache_cluster.cluster_name
        )
        if appdomain != None and resname != None:
            self.clusterfqdn = r53.CnameRecord(
                self,
                f"{construct_id}FQDN",
                zone=self.hz,
                record_name=f"{resname}.{appdomain}",
                domain_name=self.cache_cluster.attr_configuration_endpoint_address,
                ttl=core.Duration.minutes(60),
            )
            core.CfnOutput(
                self,
                f"{construct_id}ClusterFQDN",
                value=f"{resname}.{appdomain}"
            )
