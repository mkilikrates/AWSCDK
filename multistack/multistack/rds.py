import os
import json
from aws_cdk import (
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_rds as rds,
    aws_ssm as ssm,
    aws_logs as log,
    aws_route53 as r53,
    core,
)
account = core.Aws.ACCOUNT_ID
region = core.Aws.REGION
resconf = "resourcesmap.cfg"
with open(resconf) as resfile:
    resmap = json.load(resfile)
with open('zonemap.cfg') as zonefile:
    zonemap = json.load(zonefile)
class myrds(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, res, preflst, domain, allowall, ipstack, vpc = ec2.Vpc, allowsg = ec2.SecurityGroup, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.vpc = vpc
        self.ipstack = ipstack
        # get prefix list from file to allow traffic from the office
        mymap = core.CfnMapping(
            self,
            f"{construct_id}Map",
            mapping=zonemap["Mappings"]["RegionMap"]
        )
        # create security group for rds
        self.rdssg = ec2.SecurityGroup(
            self,
            f"{construct_id}:MyRdsSG",
            allow_all_outbound=True,
            vpc=self.vpc
        )
        if preflst == True:
            srcprefix = mymap.find_in_map(core.Aws.REGION, 'PREFIXLIST')
            # add ingress rules
            self.rdssg.add_ingress_rule(
                ec2.Peer.prefix_list(srcprefix),
                ec2.Port.all_traffic()
            )
        if type(allowsg) == list:
            for each in allowsg:
                self.rdssg.add_ingress_rule(
                    each,
                    ec2.Port.all_traffic()
                )
        elif allowsg != '':
            self.rdssg.add_ingress_rule(
                allowsg,
                ec2.Port.all_traffic()
            )
        self.rdssg.add_ingress_rule(
            self.rdssg,
            ec2.Port.all_traffic()
        )
        if allowall == True:
            self.rdssg.add_ingress_rule(
                ec2.Peer.any_ipv4(),
                ec2.Port.all_traffic()
            )
            if self.ipstack == 'Ipv6':
                self.rdssg.add_ingress_rule(
                    ec2.Peer.any_ipv6(),
                    ec2.Port.all_traffic()
                )
        if type(allowall) == int or type(allowall) == float:
            self.rdssg.add_ingress_rule(
                ec2.Peer.any_ipv4(),
                ec2.Port.tcp(allowall)
            )
            if self.ipstack == 'Ipv6':
                self.rdssg.add_ingress_rule(
                    ec2.Peer.any_ipv6(),
                    ec2.Port.tcp(allowall)
                )
        if type(allowall) == list:
            for each in allowall:
                self.rdssg.add_ingress_rule(
                    ec2.Peer.any_ipv4(),
                    ec2.Port.tcp(each)
                )
                if self.ipstack == 'Ipv6':
                    self.rdssg.add_ingress_rule(
                        ec2.Peer.any_ipv6(),
                        ec2.Port.tcp(each)
                    )

        # get data for rds resource
        res = res
        resname = resmap['Mappings']['Resources'][res]['NAME']
        ressize = resmap['Mappings']['Resources'][res]['SIZE']
        resclass = resmap['Mappings']['Resources'][res]['CLASS']
        resusr = resmap['Mappings']['Resources'][res]['DBUSR']
        respol = resmap['Mappings']['Resources'][res]['RemovalPolicy']
        ressubgrp = resmap['Mappings']['Resources'][res]['SUBNETGRP']
        resintn = resmap['Mappings']['Resources'][res]['Internet']
        if domain != '':
            self.hz = domain
            appdomain = domain.zone_name
        elif 'DOMAIN' in resmap['Mappings']['Resources'][res]:
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
        if resmap['Mappings']['Resources'][res]['ENGINE'] == "MYSQL":
            reseng = rds.DatabaseInstanceEngine.MYSQL
            reslog = [
                    "error",
                    "general",
                    "slowquery",
                    "audit"
                ]
        if resmap['Mappings']['Resources'][res]['ENGINE'] == "ORACLE":
            reseng = rds.DatabaseInstanceEngine.ORACLE_EE
            reslog = [
                'trace',
                'audit',
                'alert',
                'listener'
            ]
        if resmap['Mappings']['Resources'][res]['ENGINE'] == "POSTGRESQL":
            reseng = rds.DatabaseInstanceEngine.POSTGRES
            reslog = ["postgresql"]
        if resmap['Mappings']['Resources'][res]['ENGINE'] == "MARIADB":
            reseng = rds.DatabaseInstanceEngine.MARIADB
            reslog = [
                    "error",
                    "general",
                    "slowquery",
                    "audit"
                ]
        if 'Cluster' in resmap['Mappings']['Resources'][res]:
            if resmap['Mappings']['Resources'][res]['Cluster'] == "AURORA_POSTGRESQL":
                rescl = rds.DatabaseClusterEngine.AURORA_POSTGRESQL
            if resmap['Mappings']['Resources'][res]['Cluster'] == "AURORA_MYSQL":
                rescl = rds.DatabaseClusterEngine.AURORA_MYSQL
            if 'Type' in resmap['Mappings']['Resources'][res]:
                clustertype = resmap['Mappings']['Resources'][res]['Type']
                clustertype = 'Cluster'
            if  clustertype == "Serverless":
                # create RDS Cluster
                if 'pause' in resmap['Mappings']['Resources'][res]:
                    autopause = core.Duration.minutes(resmap['Mappings']['Resources'][res]['pause'])
                else:
                    autopause = core.Duration.minutes(5)
                if 'min' in resmap['Mappings']['Resources'][res]:
                    if resmap['Mappings']['Resources'][res] == 1:
                        mincap = rds.AuroraCapacityUnit.ACU_1
                    elif resmap['Mappings']['Resources'][res] == 2:
                        mincap = rds.AuroraCapacityUnit.ACU_2
                    elif resmap['Mappings']['Resources'][res] == 4:
                        mincap = rds.AuroraCapacityUnit.ACU_4
                    elif resmap['Mappings']['Resources'][res] == 8:
                        mincap = rds.AuroraCapacityUnit.ACU_8
                    elif resmap['Mappings']['Resources'][res] == 16:
                        mincap = rds.AuroraCapacityUnit.ACU_16
                    elif resmap['Mappings']['Resources'][res] == 32:
                        mincap = rds.AuroraCapacityUnit.ACU_32
                    elif resmap['Mappings']['Resources'][res] == 64:
                        mincap = rds.AuroraCapacityUnit.ACU_64
                    elif resmap['Mappings']['Resources'][res] == 128:
                        mincap = rds.AuroraCapacityUnit.ACU_128
                    elif resmap['Mappings']['Resources'][res] == 192:
                        mincap = rds.AuroraCapacityUnit.ACU_192
                    elif resmap['Mappings']['Resources'][res] == 256:
                        mincap = rds.AuroraCapacityUnit.ACU_256
                    elif resmap['Mappings']['Resources'][res] == 384:
                        mincap = rds.AuroraCapacityUnit.ACU_384
                    else:
                        mincap = rds.AuroraCapacityUnit.ACU_1
                else:
                    mincap = rds.AuroraCapacityUnit.ACU_1
                if 'max' in resmap['Mappings']['Resources'][res]:
                    if resmap['Mappings']['Resources'][res] == 1:
                        maxcap = rds.AuroraCapacityUnit.ACU_1
                    elif resmap['Mappings']['Resources'][res] == 2:
                        maxcap = rds.AuroraCapacityUnit.ACU_2
                    elif resmap['Mappings']['Resources'][res] == 4:
                        maxcap = rds.AuroraCapacityUnit.ACU_4
                    elif resmap['Mappings']['Resources'][res] == 8:
                        maxcap = rds.AuroraCapacityUnit.ACU_8
                    elif resmap['Mappings']['Resources'][res] == 16:
                        maxcap = rds.AuroraCapacityUnit.ACU_16
                    elif resmap['Mappings']['Resources'][res] == 32:
                        maxcap = rds.AuroraCapacityUnit.ACU_32
                    elif resmap['Mappings']['Resources'][res] == 64:
                        maxcap = rds.AuroraCapacityUnit.ACU_64
                    elif resmap['Mappings']['Resources'][res] == 128:
                        maxcap = rds.AuroraCapacityUnit.ACU_128
                    elif resmap['Mappings']['Resources'][res] == 192:
                        maxcap = rds.AuroraCapacityUnit.ACU_192
                    elif resmap['Mappings']['Resources'][res] == 256:
                        maxcap = rds.AuroraCapacityUnit.ACU_256
                    elif resmap['Mappings']['Resources'][res] == 384:
                        maxcap = rds.AuroraCapacityUnit.ACU_384
                    else:
                        maxcap = rds.AuroraCapacityUnit.ACU_16
                else:
                    maxcap = rds.AuroraCapacityUnit.ACU_16
                self.rds = rds.ServerlessCluster(
                    self,
                    f"{construct_id}:MyRdsServlessCluster",
                    cluster_identifier=f"{construct_id}MyRdsServlessCluster",
                    engine=rescl,
                    vpc=self.vpc,
                    vpc_subnets=ec2.SubnetSelection(subnet_group_name=ressubgrp,one_per_az=True),
                    security_groups=[self.rdssg],
                    credentials=rds.Credentials.from_generated_secret(
                        username=resusr,
                        secret_name=f"{construct_id}Secret"
                    ),
                    deletion_protection=False,
                    enable_data_api=False,
                    backup_retention=core.Duration.days(1),
                    scaling=rds.ServerlessScalingOptions(
                        min_capacity=mincap,
                        max_capacity=maxcap,
                        auto_pause=autopause
                    )
                )
                core.CfnOutput(
                    self,
                    f"{construct_id}ServlessCluster",
                    value=self.rds.cluster_identifier
                )
                core.CfnOutput(
                    self,
                    f"{construct_id}SecretName",
                    value=self.rds.secret.secret_name
                )
                if appdomain != None and resname != None:
                    self.rdsclusterfqdn = r53.CnameRecord(
                        self,
                        f"{construct_id}FQDN",
                        zone=self.hz,
                        record_name=f"{resname}.{appdomain}",
                        domain_name=self.rds.cluster_endpoint.hostname,
                        ttl=core.Duration.minutes(60),
                    )
                    core.CfnOutput(
                        self,
                        f"{construct_id}ClusterFQDN",
                        value=f"{resname}.{appdomain}"
                    )
            else:
                # create RDS Cluster
                self.rds = rds.DatabaseCluster(
                    self,
                    f"{construct_id}:MyRdsCluster",
                    engine=rescl,
                    instance_props=rds.InstanceProps(
                        vpc=self.vpc,
                        allow_major_version_upgrade=True,
                        auto_minor_version_upgrade=True,
                        delete_automated_backups=True,
                        instance_type=ec2.InstanceType.of(
                            instance_class=ec2.InstanceClass(resclass),
                            instance_size=ec2.InstanceSize(ressize)
                        ),
                        vpc_subnets=ec2.SubnetSelection(subnet_group_name=ressubgrp,one_per_az=True),
                        security_groups=[self.rdssg],
                        publicly_accessible=resintn
                    ),
                    credentials=rds.Credentials.from_generated_secret(
                        username=resusr,
                        secret_name=f"{construct_id}Secret"
                    ),
                    deletion_protection=False,
                    instance_identifier_base=resname,
                    removal_policy=core.RemovalPolicy(respol),
                    cloudwatch_logs_exports=reslog,
                    cloudwatch_logs_retention=log.RetentionDays.ONE_WEEK,
                )
                core.CfnOutput(
                    self,
                    f"{construct_id}Cluster",
                    value=self.rds.cluster_identifier
                )
                core.CfnOutput(
                    self,
                    f"{construct_id}SecretName",
                    value=self.rds.secret.secret_name
                )
                if appdomain != None and resname != None:
                    self.rdsclusterfqdn = r53.CnameRecord(
                        self,
                        f"{construct_id}FQDN",
                        zone=self.hz,
                        record_name=f"{resname}.{appdomain}",
                        domain_name=self.rds.cluster_endpoint.hostname,
                        ttl=core.Duration.minutes(60),
                    )
            core.CfnOutput(
                self,
                f"{construct_id}:rds-endpoint",
                value=f"{self.rds.cluster_endpoint.hostname}:{self.rds.cluster_endpoint.port}",
                export_name=f"{construct_id}:rds-endpoint"
            )
            core.CfnOutput(
                self,
                f"{construct_id}:rds-ro-endpoint",
                value=f"{self.rds.cluster_read_endpoint.hostname}:{self.rds.cluster_read_endpoint.port}",
                export_name=f"{construct_id}:rds-ro-endpoint"
            )
        else:
            # create RDS Instance
            self.rds = rds.DatabaseInstance(
                self,
                f"{construct_id}MyRdsInstance",
                engine=reseng,
                instance_type=ec2.InstanceType.of(
                    instance_class=ec2.InstanceClass(resclass),
                    instance_size=ec2.InstanceSize(ressize)
                ),
                database_name=f"{construct_id}MydataBase",
                vpc=self.vpc,
                allow_major_version_upgrade=True,
                auto_minor_version_upgrade=True,
                delete_automated_backups=True,
                vpc_subnets=ec2.SubnetSelection(subnet_group_name=ressubgrp,one_per_az=True),
                security_groups=[self.rdssg],
                publicly_accessible=True,
                credentials=rds.Credentials.from_generated_secret(
                    username=resusr,
                    secret_name=f"{construct_id}Secret"
                ),
                deletion_protection=False,
                removal_policy=core.RemovalPolicy(respol),
                cloudwatch_logs_exports=reslog,
                cloudwatch_logs_retention=log.RetentionDays.ONE_WEEK,
            )
            core.CfnOutput(
                self,
                f"{construct_id}Server",
                value=self.rds.instance_identifier
            )
            core.CfnOutput(
                self,
                f"{construct_id}SecretName",
                value=self.rds.secret.secret_name
            )
            core.CfnOutput(
                self,
                f"{construct_id}:rds-endpoint",
                value=f"{self.rds.db_instance_endpoint_address}:{self.rds.db_instance_endpoint_port}",
                export_name=f"{construct_id}:rds-endpoint"
            )
            if appdomain != None and resname != None:
                self.rdsclusterfqdn = r53.ARecord(
                    self,
                    id=f"{construct_id}FQDN",
                    target=self.rds.db_instance_endpoint_address,
                    zone=self.hz,
                    record_name=f"{resname}.{appdomain}",
                    ttl=core.Duration.minutes(60)
                )
                core.CfnOutput(
                    self,
                    f"{construct_id}ClusterFQDN",
                    value=f"{resname}.{appdomain}"
                )
