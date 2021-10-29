import os
import json
from aws_cdk import (
    aws_ec2 as ec2,
    aws_ecs as ecs,
    aws_ecs_patterns as ecs_patterns,
    aws_iam as iam,
    aws_kms as kms,
    aws_logs as log,
    aws_servicediscovery as sd,
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
    def __init__(self, scope: core.Construct, construct_id: str, res, preflst, allowall, ipstack, srvdisc, vpc = ec2.Vpc, allowsg = ec2.SecurityGroup, **kwargs) -> None:
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
        # check for logs
        if 'EXECCMDKMS' in resmap['Mappings']['Resources'][res]:
            if resmap['Mappings']['Resources'][res]['EXECCMDKMS'] == True:
                ecsexeclogkms = kms.Key(
                    self,
                    f"{construct_id}:KmsKey",
                    alias=resname
                ).key_id
        else:
            ecsexeclogkms = None
        if 'EXECCMDLOGGRP' in resmap['Mappings']['Resources'][res] or 'EXECCMDS3LOG' in resmap['Mappings']['Resources'][res]:
            execcmdcfglog = {}
            if 'EXECCMDLOGGRP' in resmap['Mappings']['Resources'][res]:
                execcmdloggrp = resmap['Mappings']['Resources'][res]['EXECCMDLOGGRP']
                if 'EXECCMDLOGSTM' in resmap['Mappings']['Resources'][res]:
                    execcmdlogstm = resmap['Mappings']['Resources'][res]['EXECCMDLOGSTM']
                else:
                    execcmdlogstm = 'container-stdout'
                self.execcmdloggrp = log.LogGroup(
                    self,
                    f"{construct_id}:ExecLogsGroup",
                    log_group_name=execcmdloggrp,
                    retention=log.RetentionDays.ONE_WEEK,
                    encryption_key=ecsexeclogkms
                ).add_stream(f"{construct_id}:ExecLogsStream", log_stream_name=execcmdlogstm)
                execcmdcfgloggrp = self.execcmdloggrp.log_stream_name
                if ecsexeclogkms != None:
                    execcmdcfglogkms = True
                else:
                    execcmdcfglogkms = False
            else:
                execcmdcfgloggrp = None
                execcmdcfglogkms = False
            if 'EXECCMDS3LOG' in resmap['Mappings']['Resources'][res]:
                execcmds3log = resmap['Mappings']['Resources'][res]['EXECCMDS3LOG']
                if 'EXECCMDS3LOGPRF' in resmap['Mappings']['Resources'][res]:
                    execcmds3logprf = resmap['Mappings']['Resources'][res]['EXECCMDS3LOGPRF']
                else:
                    execcmds3logprf = 'container-stdout'
                if ecsexeclogkms != None:
                    execcmdcfgs3kms = True
                else:
                    execcmdcfgs3kms = False
            else:
                execcmds3log = None
                execcmds3logprf = None
                execcmdcfgs3kms = False
            execcmdcfg = ecs.CfnCluster.ExecuteCommandConfigurationProperty(
                kms_key_id=ecsexeclogkms,
                logging='OVERRIDE',
                log_configuration=ecs.CfnCluster.ExecuteCommandLogConfigurationProperty(
                    cloud_watch_log_group_name=execcmdcfgloggrp,
                    cloud_watch_encryption_enabled=execcmdcfglogkms,
                    s3_bucket_name=execcmds3log,
                    s3_key_prefix=execcmds3logprf,
                    s3_encryption_enabled=execcmdcfgs3kms
                )
            )
        else:
            execcmdcfg = None
        # check subnet
        if 'SUBNETGRP' in resmap['Mappings']['Resources'][res]:
            ressubgrp = resmap['Mappings']['Resources'][res]['SUBNETGRP']
            if ressubgrp == 'Public':
                respubip = True
            else:
                respubip = False
            vpc = self.vpc
        else:
            vpc = None
        if 'PUBIP' in resmap['Mappings']['Resources'][res]:
            respubip = resmap['Mappings']['Resources'][res]['PUBIP']
        # check roles
        if 'TASKEXECROLEARN' in resmap['Mappings']['Resources'][res]:
            taskexecrolearn = resmap['Mappings']['Resources'][res]['TASKEXECROLEARN']
            taskexecrole = iam.Role.from_role_arn(
                self,
                f"{construct_id}taskexecrole",
                role_arn=taskexecrolearn
            )
        else:
            taskexecrole = None
        if 'TASKROLEARN' in resmap['Mappings']['Resources'][res]:
            taskrolearn = resmap['Mappings']['Resources'][res]['TASKROLEARN']
            taskrole = iam.Role.from_role_arn(
                self,
                f"{construct_id}taskrole",
                role_arn=taskrolearn
            )
        else:
            taskrole = None
        # check cluster type and instance size
        if 'Type' in resmap['Mappings']['Resources'][res]:
            restype = resmap['Mappings']['Resources'][res]['Type']
        else:
            restype = 'FARGATE'
        if restype == 'EC2':
            # create cluster
            self.ecs = ecs.Cluster(
                self,
                f"{construct_id}-ecscluster",
                cluster_name=resname,
                vpc=self.vpc
            )
            restype = resmap['Mappings']['Resources'][res]['Type']
            if 'desir' in resmap['Mappings']['Resources'][res]:
                rescap = resmap['Mappings']['Resources'][res]['desir']
            else:
                rescap = 1
            if 'min' in resmap['Mappings']['Resources'][res]:
                mincap = resmap['Mappings']['Resources'][res]['min']
            else:
                mincap = 0
            if 'max' in resmap['Mappings']['Resources'][res]:
               maxcap = resmap['Mappings']['Resources'][res]['max']
            else:
                maxcap = 1
            if 'SIZE' in resmap['Mappings']['Resources'][res]:
                ressize = resmap['Mappings']['Resources'][res]['SIZE']
            else:
                ressize = 'MICRO'
            if 'CLASS' in resmap['Mappings']['Resources'][res]:
                resclass = resmap['Mappings']['Resources'][res]['CLASS']
            else:
                resclass = 'BURSTABLE3'
            mykey = resmap['Mappings']['Resources'][res]['KEY']
            self.ecs.add_capacity(
                f"{construct_id}-ecsnodes",
                instance_type=ec2.InstanceType.of(
                        instance_class=ec2.InstanceClass(resclass),
                        instance_size=ec2.InstanceSize(ressize)
                    ),
                associate_public_ip_address=respubip,
                desired_capacity=rescap,
                min_capacity=mincap,
                max_capacity=maxcap,
                key_name=f"{mykey}{region}",
                vpc_subnets=ec2.SubnetSelection(subnet_group_name=ressubgrp,one_per_az=True),
            )
            self.task = ecs.Ec2TaskDefinition(
                self,
                f"{construct_id}-task",
                network_mode=ecs.NetworkMode.AWS_VPC
            )
            # add rules to node group security group to node
            if allowsg != '':
                self.ecs.connections.allow_from(allowsg, port_range=ec2.Port(protocol=ec2.Protocol.ALL,string_representation='allow from sg'))
            if preflst == True:
                self.ecs.connections.allow_from(ec2.Peer.prefix_list(srcprefix), port_range=ec2.Port(protocol=ec2.Protocol.ALL,string_representation='allow from prefixlist'))
            if allowall == True:
                self.ecs.connections.allow_from_any_ipv4(port_range=ec2.Port(protocol=ec2.Protocol.ALL,string_representation='allow all from ipv4'))
                if self.ipstack == 'Ipv6':
                    self.ecs.connections.allow_from(ec2.Peer.any_ipv6(), port_range=ec2.Port(protocol=ec2.Protocol.ALL,string_representation='allow all from ipv6'))
            if self.ipstack == 'Ipv6':
                self.ecs.connections.allow_to(ec2.Peer.any_ipv6(), port_range=ec2.Port(protocol=ec2.Protocol.ALL,string_representation='allow to anyv6'))

        elif restype == 'FARGATE':
            # create cluster
            self.ecs = ecs.Cluster(
                self,
                f"{construct_id}-ecscluster",
                cluster_name=resname,
                execute_command_configuration=execcmdcfg,
                vpc=vpc
            )

            restype = resmap['Mappings']['Resources'][res]['Type']
            # check https://docs.aws.amazon.com/cdk/api/latest/python/aws_cdk.aws_ecs/FargateTaskDefinitionProps.html
            if 'MEM' in resmap['Mappings']['Resources'][res]:
                taskmem = resmap['Mappings']['Resources'][res]['MEM']
            else:
                taskmem = 512
            if 'CPU'in resmap['Mappings']['Resources'][res]:
                taskcpu = resmap['Mappings']['Resources'][res]['CPU']
            else:
                taskcpu = 256
            if 'STORAGE'in resmap['Mappings']['Resources'][res]:
                taskstor = resmap['Mappings']['Resources'][res]['STORAGE']
            else:
                taskstor = 20
            self.task = ecs.FargateTaskDefinition(
                self,
                f"{construct_id}-task",
                cpu=taskcpu,
                #ephemeral_storage_gib=taskstor,
                memory_limit_mib=taskmem,
                execution_role=taskexecrole,
                task_role=taskrole
            )
        # check for container to be used
        if 'DOCKERIMAGE' in resmap['Mappings']['Resources'][res]:
            dockerimage = resmap['Mappings']['Resources'][res]['DOCKERIMAGE']
            self.container = self.task.add_container(
                f"{construct_id}-task-web",
                image=ecs.ContainerImage.from_registry(
                    dockerimage
                ),
                memory_limit_mib=256,
                container_name=f"{construct_id}-task-web"
            )
            if 'CONTPORT' in resmap['Mappings']['Resources'][res]:
                contport = resmap['Mappings']['Resources'][res]['CONTPORT']
                if 'HOSTPORT' in resmap['Mappings']['Resources'][res]:
                    hostport = resmap['Mappings']['Resources'][res]['HOSTPORT']
                else:
                    hostport = contport
                portmap = ecs.PortMapping(
                    container_port=contport,
                    host_port=hostport,
                    protocol=ecs.Protocol.TCP
                )
                self.container.add_port_mappings(portmap)
        if 'SERVICE' in resmap['Mappings']['Resources'][res]:
            if resmap['Mappings']['Resources'][res]['SERVICE'] == True:
                if restype == 'EC2':
                    if 'SRVDNSTTL' in resmap['Mappings']['Resources'][res]:
                        servicednsttl = core.Duration.seconds(resmap['Mappings']['Resources'][res]['SRVDNSTTL'])
                    else:
                        servicednsttl = core.Duration.seconds(15)
                    #check if use cloudmap
                    # if 'NAMESPACE' in resmap['Mappings']['Resources'][res]:
                    #     namespace = resmap['Mappings']['Resources'][res]['NAMESPACE']
                    # else:
                    #     namespace = ''
                        # if 'NSTYPE' in resmap['Mappings']['Resources'][res]:
                        #     resnstype = resmap['Mappings']['Resources'][res]['NSTYPE']
                        # else:
                        #     resnstype = 'VPC'
                        # if resnstype == 'VPC':
                        #     self.namespacetype = sd.NamespaceType.DNS_PRIVATE
                        #     vpc = self.vpc
                        # elif resnstype == 'HTTP':
                        #     self.namespacetype = sd.NamespaceType.HTTP
                        #     vpc = None
                        # elif resnstype == 'PUB':
                        #     self.namespacetype = sd.NamespaceType.DNS_PUBLIC
                        #     vpc = None
                        # self.namespace = self.ecs.add_default_cloud_map_namespace(
                        #     name=namespace,
                        #     type=self.namespacetype,
                        #     vpc=vpc
                        # )
                        # if self.ipstack == 'Ipv6':
                        #     dnsrectype = sd.DnsRecordType.A_AAAA
                        # else:
                        #     dnsrectype = sd.DnsRecordType.A
                        # # if elb != '':
                        # #     loadbalancer = True
                        # # else:
                        # #     loadbalancer = False
                        # self.servicename = self.namespace.create_service(
                        #     f"{construct_id}ServiceName",
                        #     name=f"{construct_id}-service",
                        #     dns_record_type=sd.DnsRecordType.SRV,
                        #     dns_ttl=servicednsttl,
                        #     load_balancer=False
                        # )
                    self.srvc = ecs.Ec2Service(
                        self,
                        f"{construct_id}-service",
                        cluster=self.ecs,
                        task_definition=self.task,
                    )
                if restype == 'FARGATE':
                    self.srvc = ecs.FargateService(
                        self,
                        f"{construct_id}-service",
                        task_definition=self.task,
                        vpc_subnets=ec2.SubnetSelection(subnet_group_name=ressubgrp,one_per_az=True),
                        cluster=self.ecs
                    )
                    # add rules to node group security group to node
                    if allowsg != '':
                        self.srvc.connections.allow_from(allowsg, port_range=ec2.Port(protocol=ec2.Protocol.ALL,string_representation='allow from sg'))
                    if preflst == True:
                        self.srvc.connections.allow_from(ec2.Peer.prefix_list(srcprefix), port_range=ec2.Port(protocol=ec2.Protocol.ALL,string_representation='allow from prefixlist'))
                    if allowall == True:
                        self.srvc.connections.allow_from_any_ipv4(port_range=ec2.Port(protocol=ec2.Protocol.ALL,string_representation='allow all from ipv4'))
                        if self.ipstack == 'Ipv6':
                            self.srvc.connections.allow_from(ec2.Peer.any_ipv6(), port_range=ec2.Port(protocol=ec2.Protocol.ALL,string_representation='allow all from ipv6'))
                    if self.ipstack == 'Ipv6':
                        self.srvc.connections.allow_to(ec2.Peer.any_ipv6(), port_range=ec2.Port(protocol=ec2.Protocol.ALL,string_representation='allow to anyv6'))
                    self.srvc.node.add_dependency(self.task)
                    self.srvc.node.add_dependency(self.container)
                if srvdisc != '':
                    self.srvc.associate_cloud_map_service(
                        container=self.container,
                        container_port=contport,
                        service=srvdisc
                    )
