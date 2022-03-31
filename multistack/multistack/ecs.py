import os
import json
from pathlib import Path
from platform import platform
from sys import path
from aws_cdk import (
    aws_ec2 as ec2,
    aws_ecs as ecs,
    aws_ecs_patterns as ecs_patterns,
    aws_ecr_assets as ecr_assets,
    aws_iam as iam,
    aws_kms as kms,
    aws_logs as log,
    aws_efs as efs,
    aws_autoscaling as asg,
    aws_servicediscovery as sd,
    aws_secretsmanager as secretsmanager,
    core,
    aws_elasticloadbalancing as clb,
    aws_elasticloadbalancingv2 as elb,
    aws_elasticloadbalancingv2_targets as lbtargets,
    aws_applicationautoscaling as appsg
)
account = core.Aws.ACCOUNT_ID
region = core.Aws.REGION
resconf = "resourcesmap.cfg"
with open(resconf) as resfile:
    resmap = json.load(resfile)
with open('zonemap.cfg') as zonefile:
    zonemap = json.load(zonefile)
class EcsStack(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, res, preflst, allowall, ipstack, contenv, contsecr, volume, volaccesspoint, grantsg, lb, certif, srvdisc = sd, asg = asg, vpc = ec2.Vpc, allowsg = ec2.SecurityGroup, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # from https://github.com/aws-samples/aws-cdk-examples/blob/master/python/ecs/ecs-service-with-advanced-alb-config/app.py
        # get imported objects
        self.vpc = vpc
        self.ipstack = ipstack
        if contsecr != '':
            secman = []
            for sec in contsecr:
                secman.append(secretsmanager.Secret.from_secret_complete_arn(self,f"{construct_id}Sec",secret_complete_arn=sec.secret_full_arn))
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
        # create security group for ecs
        self.ecssg = ec2.SecurityGroup(
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
            group_id=self.ecssg.security_group_id
        )
        if self.ipstack == 'Ipv6':
            ec2.CfnSecurityGroupEgress(
                self,
                f"{construct_id}EgressAllIpv6",
                ip_protocol="-1",
                cidr_ipv6="::/0",
                group_id=self.ecssg.security_group_id
            )
        # add ingress rule
        if type(allowsg) == list:
            for each in allowsg:
                self.ecssg.add_ingress_rule(
                    each,
                    ec2.Port.all_traffic()
                )
        elif allowsg != '':
            self.ecssg.add_ingress_rule(
                allowsg,
                ec2.Port.all_traffic()
            )
        if preflst == True:
            srcprefix = self.map.find_in_map(core.Aws.REGION, 'PREFIXLIST')
            self.ecssg.add_ingress_rule(
                ec2.Peer.prefix_list(srcprefix),
                ec2.Port.all_traffic()
            )
        if allowall == True:
            self.ecssg.add_ingress_rule(
                ec2.Peer.any_ipv4(),
                ec2.Port.all_traffic()
            )
            if self.ipstack == 'Ipv6':
                self.ecssg.add_ingress_rule(
                    ec2.Peer.any_ipv6(),
                    ec2.Port.all_traffic()
                )
        if type(allowall) == int or type(allowall) == float:
            self.ecssg.add_ingress_rule(
                ec2.Peer.any_ipv4(),
                ec2.Port.tcp(allowall)
            )
            if self.ipstack == 'Ipv6':
                self.ecssg.add_ingress_rule(
                    ec2.Peer.any_ipv6(),
                    ec2.Port.tcp(allowall)
                )
        if type(allowall) == list:
            for each in allowall:
                self.ecssg.add_ingress_rule(
                    ec2.Peer.any_ipv4(),
                    ec2.Port.tcp(each)
                )
                if self.ipstack == 'Ipv6':
                    self.ecssg.add_ingress_rule(
                        ec2.Peer.any_ipv6(),
                        ec2.Port.tcp(each)
                    )
        if type(grantsg) == list:
            index = 0
            for each in grantsg:
                ec2.SecurityGroup.from_security_group_id(
                    self,
                    f"{construct_id}{index}",
                    security_group_id=each, mutable=True
                    ).add_ingress_rule(
                        self.ecssg,
                        ec2.Port.all_traffic()
                    )
                index = index + 1
        elif grantsg != '':
            ec2.SecurityGroup.from_security_group_id(
                self,
                f"{construct_id}0",
                security_group_id=grantsg, mutable=True
                ).add_ingress_rule(
                    self.ecssg,
                    ec2.Port.all_traffic()
                )
        if 'rempol' in res:
            rempol = core.RemovalPolicy(resmap['Mappings']['Resources'][res]['rempol'])
        else:
            rempol = core.RemovalPolicy.DESTROY
        # enable log insights
        if 'Insights' in resmap['Mappings']['Resources'][res]:
            resinsights = resmap['Mappings']['Resources'][res]['Insights']
        else:
            resinsights = False
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
            # IAM permissions required for ECS Exec
            self.ecsexecpolicy = iam.PolicyStatement(
                actions=[
                    "ssmmessages:CreateControlChannel",
                    "ssmmessages:CreateDataChannel",
                    "ssmmessages:OpenControlChannel",
                    "ssmmessages:OpenDataChannel"
                ],
                effect=iam.Effect.ALLOW,
            )
            # Add all resources to this policy document
            self.ecsexecpolicy.add_all_resources()
            if 'EXECCMDLOGGRP' in resmap['Mappings']['Resources'][res]:
                execcmdloggrp = resmap['Mappings']['Resources'][res]['EXECCMDLOGGRP']
                if 'EXECCMDLOGSTM' in resmap['Mappings']['Resources'][res]:
                    execcmdlogstm = resmap['Mappings']['Resources'][res]['EXECCMDLOGSTM']
                else:
                    execcmdlogstm = 'container-stdout'
                self.execcmdloggrp = log.LogGroup(
                    self,
                    f"{execcmdloggrp}:ExecLogsGroup",
                    retention=log.RetentionDays.ONE_WEEK,
                    encryption_key=ecsexeclogkms,
                    removal_policy=rempol
                )
                self.execcmdloggrp.add_stream(f"{construct_id}:ExecLogsStream", log_stream_name=execcmdlogstm)
                execcmdcfgloggrp = self.execcmdloggrp.log_group_name
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
            execcmdcfg = ecs.ExecuteCommandConfiguration(
                kms_key=ecsexeclogkms,
                logging=ecs.ExecuteCommandLogging.OVERRIDE,
                log_configuration=ecs.ExecuteCommandLogConfiguration(
                    cloud_watch_log_group=self.execcmdloggrp,
                    cloud_watch_encryption_enabled=execcmdcfglogkms,
                    s3_bucket=execcmds3log,
                    s3_key_prefix=execcmds3logprf,
                    s3_encryption_enabled=execcmdcfgs3kms
                )
            )
            execcmdcfgbol = True
        else:
            execcmdcfg = None
            execcmdcfgbol = False
        # check roles
        if 'TASKEXECROLEARN' in resmap['Mappings']['Resources'][res]:
            taskexecrolearn = resmap['Mappings']['Resources'][res]['TASKEXECROLEARN']
            self.taskexecrole = iam.Role.from_role_arn(
                self,
                f"{construct_id}taskexecrole",
                role_arn=taskexecrolearn
            )
        else:
            self.taskexecrole = iam.Role(
                self,
                f"{construct_id}taskexecrole",
                assumed_by=iam.ServicePrincipal('ecs-tasks.amazonaws.com'),
                description="Role for ECS Task Execution",
            )
            pol = iam.ManagedPolicy.from_aws_managed_policy_name('service-role/AmazonECSTaskExecutionRolePolicy')
            self.taskexecrole.add_managed_policy(pol)
        if 'MNGTASKEXECROLE' in resmap['Mappings']['Resources'][res]:
            for mngpol in resmap['Mappings']['Resources'][res]['MNGTASKEXECROLE']:
                pol = iam.ManagedPolicy.from_aws_managed_policy_name(mngpol)
                self.taskexecrole.add_managed_policy(pol)
        if 'EXECROLE' in resmap['Mappings']['Resources'][res]:
            roles = resmap['Mappings']['Resources'][res]['EXECROLE']
            for police in roles:
                newpol = {}
                if 'Actions' in police:
                    newpol["actions"] = police['Actions']
                if 'Conditions' in police:
                    newpol["conditions"] = police['Conditions']
                if 'Effect' in police:
                    if police['Effect'] == "allow":
                        newpol["effect"] = iam.Effect.ALLOW
                    if police['Effect'] == "deny":
                        newpol["effect"] = iam.Effect.DENY
                if 'NoActions' in police:
                    newpol["not_actions"] = police['NoActions']
                if 'NoResources' in police:
                    newpol["not_resources"] = police['NoResources']
                if 'Principals' in police:
                    if police['Principals'] == '*':
                        newpol["principals"] = [iam.StarPrincipal()]
                    else:
                        newpol["principals"] = [iam.ArnPrincipal(police['Principals'])]
                if 'NoPrincipals' in police:
                    newpol["not_principals"] = police['NoPrincipals']
                if 'Resources' in police:
                    newpol["resources"] = police['Resources']
                if 'SID' in police:
                    newpol["sid"] = police['SID']
                self.taskexecrole.add_to_policy(statement=iam.PolicyStatement(**newpol))
        # capacity strategy
        if 'CAPSTRATEGY' in resmap['Mappings']['Resources'][res]:
            capstrategy = []
            for cap in resmap['Mappings']['Resources'][res]['CAPSTRATEGY']:
                if 'Provider' in cap:
                    if 'weight' in cap:
                        weight = cap['weight']
                    else:
                        weight = None
                    if 'base' in cap:
                        base = cap['base']
                    else:
                        base = None
                    # capstrategy.append(ecs.CapacityProviderStrategy(
                    #     capacity_provider=cap['Provider'],
                    #     weight=weight,
                    #     base=base
                    # ))
                    capstrategy.append(ecs.CfnService.CapacityProviderStrategyItemProperty(
                        capacity_provider=cap['Provider'],
                        weight=weight,
                        base=base
                    ))
                    lauchtype = None
        else:
            capstrategy = None
            lauchtype = task['Type']

        # create cluster
        self.ecs = ecs.Cluster(
            self,
            f"{construct_id}-ecscluster",
            cluster_name=resname,
            vpc=vpc,
            container_insights=resinsights,
            execute_command_configuration=execcmdcfg
        )
        # add ec2 capacity from auto scale group
        if asg != '':
            self.ecs.add_auto_scaling_group(auto_scaling_group=asg)
        if 'ASG' in resmap['Mappings']['Resources'][res]:
            self.asg = asg.AutoScalingGroup.from_auto_scaling_group_name(
                self,
                f"{construct_id}-AutoScaleGroup",
                auto_scaling_group_name=resmap['Mappings']['Resources'][res]['ASG']
            )
            self.ecs.add_auto_scaling_group(auto_scaling_group=self.asg)
        # task definition
        if 'TASK' in resmap['Mappings']['Resources'][res]:
            for task in resmap['Mappings']['Resources'][res]['TASK']:
                taskname = task['Name']
                # check subnet
                if 'SUBNETGRP' in task:
                    ressubgrp = self.vpc.select_subnets(subnet_group_name=task['SUBNETGRP'], one_per_az=True).subnet_ids
                    if task['SUBNETGRP'] == 'Public':
                        respubip = 'ENABLED'
                    else:
                        respubip = 'DISABLED'
                    vpc = self.vpc
                else:
                    vpc = None
                    ressubgrp = None
                if 'PUBIP' in task:
                    if task['PUBIP'] == True:
                        respubip = 'ENABLED'
                    else:
                        respubip = 'DISABLED'
                if 'NetMode' in task:
                    if task['NetMode'] == 'AWS_VPC':
                        netmode = ecs.NetworkMode.AWS_VPC
                        srvcnetcfg = {
                            "awsvpcConfiguration": {
                                "subnets": ressubgrp,
                                "assignPublicIp": respubip,
                                "securityGroups": [self.ecssg.security_group_id]
                            }
                        }
                        # srvcnetcfg = ecs.CfnService.NetworkConfigurationProperty(
                        #     awsvpc_configuration=ecs.CfnService.AwsVpcConfigurationProperty(
                        #         subnets=ressubgrp,
                        #         assign_public_ip=respubip,
                        #         security_groups=[self.ecssg]
                        #     )
                        # )
                    elif task['NetMode'] == 'BRIDGE':
                        netmode = ecs.NetworkMode.BRIDGE
                        srvcnetcfg = None
                    elif task['NetMode'] == 'HOST':
                        netmode = ecs.NetworkMode.HOST
                        srvcnetcfg = None
                    elif task['NetMode'] == 'NAT':
                        netmode = ecs.NetworkMode.NAT
                        srvcnetcfg = None
                    elif task['NetMode'] == 'NONE':
                        srvcnetcfg = None
                        netmode = ecs.NetworkMode.NONE
                else:
                    srvcnetcfg = None
                    netmode = ecs.NetworkMode.NONE
                if 'TASKROLEARN' in task:
                    taskrolearn = task['TASKROLEARN']
                    self.taskrole = iam.Role.from_role_arn(
                        self,
                        f"{construct_id}taskrole",
                        role_arn=taskrolearn
                    )
                else:
                    self.taskrole = iam.Role(
                        self,
                        f"{construct_id}-taskrole",
                        assumed_by=iam.ServicePrincipal('ecs-tasks.amazonaws.com'),
                        description="Role for ECS Task {construct_id}",
                    )
                if 'MNGTASKROLE' in task:
                    for mngpol in task['MNGTASKROLE']:
                        pol = iam.ManagedPolicy.from_aws_managed_policy_name(mngpol)
                        self.taskrole.add_managed_policy(pol)
                if execcmdcfgbol == True:
                    self.taskrole.add_to_policy(self.ecsexecpolicy)
                if 'TASKROLE' in task:
                    roles = task['TASKROLE']
                    for police in roles:
                        newpol = {}
                        if 'Actions' in police:
                            newpol["actions"] = police['Actions']
                        if 'Conditions' in police:
                            newpol["conditions"] = police['Conditions']
                        if 'Effect' in police:
                            if police['Effect'] == "allow":
                                newpol["effect"] = iam.Effect.ALLOW
                            if police['Effect'] == "deny":
                                newpol["effect"] = iam.Effect.DENY
                        if 'NoActions' in police:
                            newpol["not_actions"] = police['NoActions']
                        if 'NoResources' in police:
                            newpol["not_resources"] = police['NoResources']
                        if 'Principals' in police:
                            if police['Principals'] == '*':
                                newpol["principals"] = [iam.StarPrincipal()]
                            else:
                                newpol["principals"] = [iam.ArnPrincipal(police['Principals'])]
                        if 'NoPrincipals' in police:
                            newpol["not_principals"] = police['NoPrincipals']
                        if 'Resources' in police:
                            newpol["resources"] = police['Resources']
                        if 'SID' in police:
                            newpol["sid"] = police['SID']
                        self.taskrole.add_to_policy(statement=iam.PolicyStatement(**newpol))
                if 'vol' in task:
                    taskvols = []
                    for vol in task['vol']:
                        if 'Name' in vol:
                            volname = vol['Name']
                        if 'efsfromstack' in vol:
                            systemid = volume[vol['efsfromstack']]
                        elif 'efssystemid' in vol:
                            systemid = vol['efssystemid']
                        else:
                            systemid = None
                        if 'accesspointfromstack' in vol:
                            accesspoint = volaccesspoint[vol['efsfromstack']]
                        elif 'efsaccesspoint' in vol:
                            accesspoint = [vol['efsaccesspoint']]
                        else:
                            accesspoint = None
                        if 'accesspointiam' in vol:
                            accesspointiam = vol['accesspointiam']
                        else:
                            accesspointiam = None
                        if 'Root' in vol:
                            rootdir = vol['Root']
                        else:
                            rootdir = None
                        if 'TransitEnc' in vol:
                            transitenc = vol['TransitEnc']
                        else:
                            transitenc = None
                        if 'TransitEncPort' in vol:
                            transitencport = vol['TransitEncPort']
                        else:
                            transitencport = None
                        if systemid != None:
                            taskvols.append(
                                ecs.Volume(
                                    name=volname,
                                    efs_volume_configuration=(
                                        ecs.EfsVolumeConfiguration(
                                            file_system_id=systemid,
                                            authorization_config=ecs.AuthorizationConfig(access_point_id=accesspoint, iam=accesspointiam),
                                            root_directory=rootdir,
                                            transit_encryption=transitenc,
                                            transit_encryption_port=transitencport
                                        )
                                    )
                                )
                            )
                        # add options for docker and host
                else:
                    taskvols = None
                if task['Type'] == 'EC2':
                    self.task = ecs.Ec2TaskDefinition(
                        self, 
                        f"{construct_id}{taskname}", 
                        network_mode=netmode,
                        execution_role=self.taskrole,
                        volumes=taskvols
                    )
                if task['Type'] == 'FARGATE':
                    if 'MEM' in task:
                        taskmem = task['MEM']
                    else:
                        taskmem = 512
                    if 'CPU'in task:
                        taskcpu = task['CPU']
                    else:
                        taskcpu = 256
                    if 'STORAGE'in task:
                        taskstor = task['STORAGE']
                    else:
                        taskstor = None
                    if 'PLATFORM'in task:
                        resplatform = ecs.FargatePlatformVersion(task['PLATFORM'])
                    else:
                        resplatform = ecs.FargatePlatformVersion.LATEST
                    self.task = ecs.FargateTaskDefinition(
                        self,
                        f"{construct_id}{taskname}", 
                        cpu=taskcpu,
                        ephemeral_storage_gib=taskstor,
                        memory_limit_mib=taskmem,
                        execution_role=self.taskexecrole,
                        task_role=self.taskrole,
                        volumes=taskvols
                    )
                    #.node.override_logical_id(f"{self}.{construct_id}{taskname}")
                if 'Container' in task:
                    containeres = []
                    cont = 0
                    for container in task['Container']:
                        if 'Name' in container:
                            containername = container['Name']
                        if 'File' in container:
                            imagefile = container['File']
                        else:
                            imagefile = None
                        if 'imagenetmode' in container:
                            if container['imagenetmode'] == 'DEFAULT':
                                imagenetmode = ecr_assets.NetworkMode.DEFAULT
                            elif container['imagenetmode'] == 'HOST':
                                imagenetmode = ecr_assets.NetworkMode.HOST
                            elif container['imagenetmode'] == 'NONE':
                                imagenetmode = ecr_assets.NetworkMode.NONE
                        else:
                            imagenetmode = ecr_assets.NetworkMode.DEFAULT
                        if 'imagebuildargs' in container:
                            imagebuildarg = container['imagebuildargs']
                        else:
                            imagebuildarg = None
                        if 'imageignoremode' in container:
                            imageignoremode = container['imageignoremode']
                        else:
                            imageignoremode = None
                        if 'Command' in container:
                            contcommand = container['Command']
                        else:
                            contcommand = None
                        if 'CPU'in container:
                            contcpu = task['CPU']
                        else:
                            contcpu = None
                        if 'Linuxpar'in task:
                            contlinuxpar = task['Linuxpar']
                        else:
                            contlinuxpar = None
                        # only check up to 2 levels
                        if 'environment'in container:
                            ctenv = container['environment']
                            for k,v in ctenv.items():
                                if isinstance(v,dict):
                                    for k1,v1 in v.items():
                                        if k1 == 'envfromstack':
                                            ctenv[k] = contenv[v1]
                                elif isinstance(v,list):
                                    for item in v:
                                        if isinstance(item,dict):
                                            for k2,v2 in item.items():
                                                if k2 == 'envfromstack':
                                                    ctenv[k][v][k1] = contenv[v2]
                            contenviron = ctenv
                        else:
                            contenviron = None
                        if 'secrets'in container:
                            ctsecr = container['secrets']
                            for k,v in ctsecr.items():
                                if isinstance(v,dict):
                                    for k1,v1 in v.items():
                                        if k1 == 'secfromstack':
                                            secman[v1].secret.grant_read(self.taskexecrole)
                                            ctsecr[k] = ecs.Secret.from_secrets_manager(secman[v1])
                                        if k1 == 'secjsonfromstack':
                                            ctsecr[k] = ecs.Secret.from_secrets_manager(secman[v1['stackid']],v1['field'])
                                            secman[v1['stackid']].grant_read(self.taskexecrole)
                                elif isinstance(v,list):
                                    for item in v:
                                        if isinstance(item,dict):
                                            for k2,v2 in item.items():
                                                if k2 == 'secjsonfromstack':
                                                    secman[v2['stackid']].grant_read(self.taskexecrole)
                                                    ctsecr[k][v][k1] = ecs.Secret.from_secrets_manager(secman[v2])
                                                if k2 == 'secjsonfromstack':
                                                    secman[v2['stackid']].grant_read(self.taskexecrole)
                                                    ctsecr[k][v][k1] = ecs.Secret.from_secrets_manager(secman[v2['stackid']],v2['field'])
                            contsecrets = ctsecr
                        else:
                            contsecrets = None
                        if 'logdriver'in container:
                            if container['logdriver'] == 'aws_logs':
                                if 'logretention' in container:
                                    if container['logretention'] == "ONE_WEEK":
                                        contlogreten = log.RetentionDays.ONE_WEEK
                                elif 'logretention' in container:
                                    if container['logretention'] == "ONE_MONTH":
                                        contlogreten = log.RetentionDays.ONE_MONTH
                                else:
                                    contlogreten = log.RetentionDays.ONE_WEEK
                                if 'logstream' in container:
                                    contlogstm = container['logstream']
                                else:
                                    contlogstm = f"{construct_id}{taskname}{containername}{task}LogStream"
                                if 'loggroup' in container:
                                    contloggrp = container['loggroup']
                                    if 'loggroupname' in container:
                                        contloggroupname = container['loggroup']
                                    else:
                                        contloggroupname = None
                                    contlog_group = log.LogGroup(
                                        self,
                                        f"{contloggrp}",
                                        log_group_name=contloggroupname,
                                        retention=contlogreten
                                    )
                                    contloggrpname = contlog_group.log_group_name

                                else:
                                    contloggrp = f"{construct_id}{taskname}{containername}LogGroup"
                                    if cont == 0:
                                        contlog_group = log.LogGroup(
                                            self,
                                            f"{contloggrp}",
                                            retention=contlogreten
                                        )
                                        contloggrpname = contlog_group.log_group_name
                                contlog = ecs.LogDrivers.aws_logs(
                                    stream_prefix=contlogstm,
                                    log_group=contlog_group,
                                )
                        else:
                            contlog = None
                        if 'Dir' in container:
                            imagedir = container['Dir']
                            image = ecs.ContainerImage.from_asset(
                                directory=imagedir,
                                file=imagefile,
                                build_args=imagebuildarg,
                                network_mode=imagenetmode,
                                ignore_mode=imageignoremode
                            )
                        elif 'imagefromregistry' in container:
                            regstrycred = None
                            imageregistry = container['imagefromregistry']
                            image=ecs.ContainerImage.from_registry(name=imageregistry, credentials=regstrycred)
                        # add option for credentials
                        # add options for fromDockerImageAsset, from_ecr_repository, from_registry and from_tarball
                        # add container to task
                        containeres.append(ecs.ContainerDefinition(
                            self,
                            f"{construct_id}{containername}",
                            task_definition=self.task,
                            image=image,
                            container_name=containername,
                            command=contcommand,
                            cpu=contcpu,
                            environment=contenviron,
                            secrets=contsecrets,
                            logging=contlog,
                            linux_parameters=contlinuxpar,
                        ))
                        # create mount points
                        # add other types
                        if 'mountpoints' in container:
                            for mountpoint in container['mountpoints']:
                                if 'path' in mountpoint:
                                    contpath = mountpoint['path']
                                if 'volname' in mountpoint:
                                    contvolname = mountpoint['volname']
                                if 'ro' in mountpoint:
                                    contro = mountpoint['ro']
                                else:
                                    contro = False
                                containeres[cont].add_mount_points(
                                            ecs.MountPoint(
                                                container_path=contpath,
                                                read_only=contro,
                                                source_volume=contvolname
                                            )
                                    )
                        # create service and expose using ALB
                        if 'Service' in container:
                            srvcont = 0
                            for srvc in container['Service']:
                                if 'Name' in srvc:
                                    srvcname = srvc['Name']
                                if 'Proto' in srvc:
                                    if srvc['Proto'] == 'TCP':
                                        contproto = ecs.Protocol.TCP
                                    if srvc['Proto'] == 'UDP':
                                        contproto = ecs.Protocol.UDP
                                else:
                                    contproto = None
                                if 'HostPort' in srvc:
                                    conthostport = srvc['HostPort']
                                else:
                                    conthostport = None
                                if 'ContPort' in srvc:
                                    contport = srvc['ContPort']
                                else:
                                    contport = None
                                if 'Depmin' in srvc:
                                    tgdepmin = srvc['Depmin']
                                else:
                                    tgdepmin = None
                                if 'Depmax' in srvc:
                                    tgdepmax = srvc['Depmax']
                                else:
                                    tgdepmax = None
                                if 'Depcircbrkena' in srvc:
                                    tgdepcircbrkena = srvc['Depcircbrkena']
                                else:
                                    tgdepcircbrkena = False
                                if 'Depcircbrkrlbk' in srvc:
                                    tgdepcircbrkroll = srvc['Depcircbrkrlbk']
                                else:
                                    tgdepcircbrkroll = False
                                if 'Maxcount' in srvc:
                                    tgmax = srvc['Maxcount']
                                else:
                                    tgmax = None
                                if 'Depcontype' in srvc:
                                    tgdepcontype = ecs.CfnService.DeploymentControllerProperty(
                                        type=srvc['Depcontype']
                                    )
                                else:
                                    tgdepcontype = ecs.CfnService.DeploymentControllerProperty(
                                        type='ECS'
                                    )
                                if 'SchdStrat' in srvc:
                                    tgrschstrategy = srvc['SchdStrat']
                                else:
                                    tgrschstrategy = False
                                if 'Descount' in srvc:
                                    tgdes = srvc['Descount']
                                else:
                                    tgdes = None
                                if contport != None:
                                    containeres[cont].add_port_mappings(ecs.PortMapping(container_port=contport, host_port=conthostport, protocol=contproto))
                                    if srvdisc != '':
                                        if 'NSRECTYPE' in container:
                                            contnsrectype = container['NSRECTYPE']
                                        else:
                                            contnsrectype = None
                                        if 'NSTTL' in container:
                                            contnsttl = container['NSTTL']
                                        else:
                                            contnsttl = None
                                        if 'NSFail' in container:
                                            contnsfail = container['NSFail']
                                        else:
                                            contnsfail = None
                                        contmapopt = ecs.CloudMapOptions(
                                            cloud_map_namespace=srvdisc,
                                            container=containeres[cont],
                                            container_port=contport,
                                            dns_record_type=contnsrectype,
                                            dns_ttl=contnsttl,
                                            failure_threshold=contnsfail,
                                            name=containername
                                        )
                                    else:
                                        contmapopt = None
                                    if 'Targets' in srvc:
                                        svctgrp = []
                                        for target in srvc['Targets']:
                                            if 'Name' in target:
                                                targetname = target['Name']
                                            else:
                                                targetname = None
                                            if 'TGType' in target:
                                                if target['TGType'] == 'IP':
                                                    tgtype = elb.TargetType.IP
                                                    tgport = contport
                                                elif target['TGType'] == 'HOST':
                                                    tgtype = elb.TargetType.INSTANCE
                                                    tgport = conthostport
                                                else:
                                                    tgtype = elb.TargetType.IP
                                                    tgport = contport
                                            else:
                                                tgtype = elb.TargetType.IP
                                                tgport = contport
                                            if 'LBAlgType' in target:
                                                if target['LBAlgType'] == 'RB':
                                                    lbalgtype = elb.TargetGroupLoadBalancingAlgorithmType.ROUND_ROBIN
                                                elif target['LBAlgType'] == 'LEAST':
                                                    lbalgtype = elb.TargetGroupLoadBalancingAlgorithmType.LEAST_OUTSTANDING_REQUESTS
                                                else:
                                                    lbalgtype = None
                                            else:
                                                lbalgtype = None
                                            if 'stickduration' in target:
                                                stickduration = core.Duration.seconds(target['stickduration'])
                                            else:
                                                stickduration = None
                                            if 'cookie' in target:
                                                cookiename = target['cookie']
                                            else:
                                                cookiename = None
                                            if 'slowstart' in target:
                                                slowstart = core.Duration.seconds(target['slowstart'])
                                            else:
                                                slowstart = None
                                            if 'deregdelay' in target:
                                                deregdelay = core.Duration.seconds(target['deregdelay'])
                                            else:
                                                deregdelay = None
                                            if 'HCPORT' in target:
                                                hcport = target['HCPORT']
                                            else:
                                                hcport = 'traffic-port'
                                            if 'HCPROTO' in target:
                                                hcproto = target['HCPROTO']
                                                if hcproto == 'TCP':
                                                    hcproto = elb.Protocol.TCP
                                                elif hcproto == 'UDP':
                                                    hcproto = elb.Protocol.UDP
                                                elif hcproto == 'TCP_UDP':
                                                    hcproto = elb.Protocol.TCP_UDP
                                                elif hcproto == 'HTTP':
                                                    hcproto = elb.Protocol.HTTP
                                                elif hcproto == 'HTTPS':
                                                    hcproto = elb.Protocol.HTTPS
                                                elif hcproto == 'TLS':
                                                    hcproto = elb.Protocol.TLS
                                                else:
                                                    hcproto = None
                                                if target['HCPROTO'] == 'HTTP' or target['HCPROTO'] == 'HTTPS':
                                                    if 'HCPath' in target:
                                                        hcpath = target['HCPath']
                                                    else:
                                                        hcpath = '/'
                                            else:
                                                hcpath = None
                                                hcproto = None
                                            if 'HCGRPC' in target:
                                                hcgrpc = target['HCGRPC']
                                            else:
                                                hcgrpc = None
                                            if 'HCHTTP' in target:
                                                hchttp = target['HCHTTP']
                                            else:
                                                hchttp = None
                                            if 'HCCount' in target:
                                                hccount = target['HCCount']
                                            else:
                                                hccount = 3
                                            if 'HCUnCount' in target:
                                                hcuncount = target['HCUnCount']
                                            else:
                                                hcuncount = 3
                                            if 'HCInt' in target:
                                                hcint = core.Duration.seconds(target['HCInt'])
                                            else:
                                                hcint = core.Duration.seconds(30)
                                            if 'HCtmt' in target:
                                                hctmt = core.Duration.seconds(target['HCtmt'])
                                            else:
                                                hctmt = core.Duration.seconds(10)
                                            if 'HC' in target:
                                                hc = target['HC']
                                                svchc = elb.HealthCheck(
                                                    enabled=hc,
                                                    port=str(hcport),
                                                    protocol=hcproto,
                                                    healthy_grpc_codes=hcgrpc,
                                                    healthy_http_codes=hchttp,
                                                    healthy_threshold_count=hccount,
                                                    unhealthy_threshold_count=hcuncount,
                                                    interval=hcint,
                                                    path=hcpath,
                                                    timeout=hctmt
                                                )
                                            else:
                                                svchc = None
                                            if 'elbfromstack' in target:
                                                loadbalancer = lb[target['elbfromstack']]
                                            else:
                                                loadbalancer = None
                                            if 'certfromstack' in target:
                                                certificates = []
                                                for cert in target['certfromstack']:
                                                    certificates.append(elb.ListenerCertificate.from_arn(certif[cert]))
                                            else:
                                                certificates = None
                                            if 'elblist' in target:
                                                elblist = target['elblist']
                                                if elblist == '443':
                                                    elbproto = elb.Protocol.HTTPS
                                                elif elblist == '80':
                                                    elbproto = elb.Protocol.HTTP
                                                else:
                                                    if 'elbproto' in target:
                                                        if target['elbproto'] == 'TCP':
                                                            elbproto = elb.Protocol.TCP
                                                        elif target['elbproto'] == 'UDP':
                                                            elbproto = elb.Protocol.UDP
                                                        elif target['elbproto'] == 'TLS':
                                                            elbproto = elb.Protocol.TLS
                                                        elif target['elbproto'] == 'TCP_UDP':
                                                            elbproto = elb.Protocol.TCP_UDP
                                                        else:
                                                            elbproto = elb.Protocol.HTTP
                                                    else:
                                                        elbproto = elb.Protocol.HTTP
                                            else:
                                                elblist = 80
                                                elbproto = elb.Protocol.HTTP
                                            if target['Type'] == 'alb':
                                                self.elbtgr = elb.ApplicationTargetGroup(
                                                    self,
                                                    f"{construct_id}-{srvcname}-{targetname}",
                                                    load_balancing_algorithm_type=lbalgtype,
                                                    target_group_name=f"{construct_id}-{srvcname}-{targetname}",
                                                    slow_start=slowstart,
                                                    deregistration_delay=deregdelay,
                                                    target_type=tgtype,
                                                    port=tgport,
                                                    stickiness_cookie_duration=stickduration,
                                                    stickiness_cookie_name=cookiename,
                                                    vpc=self.vpc,
                                                    health_check=svchc
                                                )
                                                svctgrp.append(ecs.CfnService.LoadBalancerProperty(
                                                    container_name=containername,
                                                    container_port=contport,
                                                    target_group_arn=self.elbtgr.target_group_arn
                                                ))
                                                if loadbalancer != None:
                                                    if 'Metrics' in target:
                                                        tgscale = appsg.ScalableTarget(
                                                            self,
                                                            f"{srvcname}ScaleTrg{targetname}",
                                                            max_capacity=tgmax,
                                                            min_capacity=tgdepmin,
                                                            service_namespace=appsg.ServiceNamespace.ECS,
                                                            scalable_dimension="ecs:service:DesiredCount",
                                                            resource_id=f"service/{self.ecs.cluster_name}/{srvcname}"
                                                        )
                                                        for metric in target['Metrics']:
                                                            if 'TargValue' in metric:
                                                                metrictargval = metric['TargValue']
                                                            else:
                                                                metrictargval = None
                                                            if 'ScaleinCool' in metric:
                                                                scalecoolin = metric['ScaleinCool']
                                                            else:
                                                                scalecoolin = None
                                                            if 'ScaleoutCool' in metric:
                                                                scaleoutcool = metric['ScaleoutCool']
                                                            else:
                                                                scaleoutcool = None
                                                            if metric['Name'] == 'RequestCountPerTarget':
                                                                tgscale.scale_to_track_metric(
                                                                    id=f"{srvcname}RequestCountPerTarget",
                                                                    predefined_metric=appsg.PredefinedMetric.ALB_REQUEST_COUNT_PER_TARGET,
                                                                    resource_label= f"{loadbalancer.load_balancer_full_name}/{self.elbtgr.target_group_full_name}",
                                                                    target_value= metrictargval,
                                                                    scale_in_cooldown= core.Duration.seconds(scalecoolin),
                                                                    scale_out_cooldown= core.Duration.seconds(scaleoutcool)
                                                                )
                                                            if metric['Name'] == 'TargetResponseTime':
                                                                tgscale.scale_to_track_metric(
                                                                    id=f"{srvcname}TargetResponseTime",
                                                                    custom_metric=loadbalancer.metric_target_response_time(),
                                                                    resource_label= f"{loadbalancer.load_balancer_full_name}/{self.elbtgr.target_group_full_name}",
                                                                    target_value= metrictargval,
                                                                    scale_in_cooldown= core.Duration.seconds(scalecoolin),
                                                                    scale_out_cooldown= core.Duration.seconds(scaleoutcool)
                                                                )
                                                    if  type(elblist) == list:
                                                        for each in elblist:
                                                            if each == 443:
                                                                self.elbtgr = elb.ApplicationListener(
                                                                    self,
                                                                    f"{construct_id}:Listener_https",
                                                                    load_balancer=loadbalancer,
                                                                    port=each,
                                                                    protocol=elb.ApplicationProtocol.HTTPS,
                                                                    certificates=certificates,
                                                                    default_target_groups=[self.elbtgr]
                                                                )
                                                                # self.elbtgr.add_target(
                                                                #     targets=ecs.EcsTarget(
                                                                #         container_name=containername,
                                                                #         container_port=contport,
                                                                #         protocol=contproto,
                                                                #         listener=self.elblistnrs
                                                                #     )
                                                                # )
                                                                #redir http traffic to https
                                                                loadbalancer.add_redirect(
                                                                    source_port=80,
                                                                    source_protocol=elb.ApplicationProtocol.HTTP,
                                                                    target_port=443,
                                                                    target_protocol=elb.ApplicationProtocol.HTTPS
                                                                )
                                                            else:
                                                                self.elblistnrs = elb.ApplicationListener(
                                                                    self,
                                                                    f"{construct_id}:Listener_http",
                                                                    load_balancer=loadbalancer,
                                                                    port=each,
                                                                    protocol=elb.ApplicationProtocol.HTTP,
                                                                    default_target_groups=[self.elbtgr]
                                                                )
                                                                                                                                
                                                                # self.elbtgr.add_target(
                                                                #     targets=ecs.EcsTarget(
                                                                #         container_name=containername,
                                                                #         container_port=contport,
                                                                #         protocol=contproto,
                                                                #         listener=self.elblistnrs
                                                                #     )
                                                                # )
                                                            self.elbtgr.node.default_child.override_logical_id(f"{construct_id}:Listener{each}")
                                                    elif elblist == 443:
                                                        self.elblistnrs = elb.ApplicationListener(
                                                            self,
                                                            f"{construct_id}:Listener_https",
                                                            load_balancer=loadbalancer,
                                                            port=elblist,
                                                            protocol=elb.ApplicationProtocol.HTTPS,
                                                            certificates=certificates,
                                                            default_target_groups=[self.elbtgr]
                                                        )
                                                        #redir http traffic to https
                                                        loadbalancer.add_redirect(
                                                            source_port=80,
                                                            source_protocol=elb.ApplicationProtocol.HTTP,
                                                            target_port=443,
                                                            target_protocol=elb.ApplicationProtocol.HTTPS
                                                        )
                                                        
                                                        # self.elbtgr.add_target(
                                                        #     targets=ecs.EcsTarget(
                                                        #         container_name=containername,
                                                        #         container_port=contport,
                                                        #         protocol=contproto,
                                                        #         listener=self.elblistnrs
                                                        #     )
                                                        # )
                                                        self.elbtgr.node.default_child.override_logical_id(f"{construct_id}:Listener{elblist}")
                                                    else:
                                                        self.elblistnrs = elb.ApplicationListener(
                                                            self,
                                                            f"{construct_id}:Listener_http",
                                                            load_balancer=loadbalancer,
                                                            port=contport,
                                                            protocol=elb.ApplicationProtocol.HTTP,
                                                            default_target_groups=[self.elbtgr]
                                                        )
                                                        
                                                        # self.elbtgr.add_target(
                                                        #     targets=ecs.EcsTarget(
                                                        #         container_name=containername,
                                                        #         container_port=contport,
                                                        #         protocol=contproto,
                                                        #         listener=self.elblistnrs
                                                        #     )
                                                        # )
                                                        self.elbtgr.node.default_child.override_logical_id(f"{construct_id}:Listener{elblist}")
                                            self.elbtgr.node.default_child.override_logical_id(f"{targetname}")
                                    self.srvc = ecs.CfnService(
                                        self,
                                        f"{construct_id}{taskname}{srvcname}",
                                        capacity_provider_strategy=capstrategy,
                                        cluster=self.ecs.cluster_name,
                                        deployment_configuration=ecs.CfnService.DeploymentConfigurationProperty(
                                            deployment_circuit_breaker=ecs.CfnService.DeploymentCircuitBreakerProperty(
                                            enable=tgdepcircbrkena,
                                            rollback=tgdepcircbrkroll
                                            ),
                                            maximum_percent=tgdepmax,
                                            minimum_healthy_percent=tgdepmin
                                        ),
                                        deployment_controller=tgdepcontype,
                                        desired_count=tgdes,
                                        enable_ecs_managed_tags=True,
                                        enable_execute_command=execcmdcfgbol,
                                        health_check_grace_period_seconds=None,
                                        launch_type=lauchtype,
                                        load_balancers=svctgrp,
                                        network_configuration=srvcnetcfg,
                                        service_name=srvcname,
                                        task_definition=self.task.task_definition_arn
                                    )
                                    tgscale.node.add_dependency(self.srvc)
                                    self.srvc.override_logical_id(f"{construct_id}{taskname}{srvcname}")
                                    # if task['Type'] == 'EC2':
                                    #     self.srvc = ecs.Ec2Service(
                                    #         self,
                                    #         f"{construct_id}{taskname}{srvcname}",
                                    #         service_name=srvcname,
                                    #         task_definition=self.task,
                                    #         assign_public_ip=respubip,
                                    #         security_groups=[self.ecssg],
                                    #         vpc_subnets=ressubgrp,
                                    #         cluster=self.ecs,
                                    #         capacity_provider_strategies=capstrategy,
                                    #         enable_execute_command=execcmdcfg,
                                    #         cloud_map_options=contmapopt
                                    #     )
                                    #     self.srvc.node.default_child.override_logical_id(f"{construct_id}{taskname}{srvcname}")
                                    # if task['Type'] == 'FARGATE':
                                    #     self.srvc = ecs.FargateService(
                                    #         self,
                                    #         f"{construct_id}{taskname}{srvcname}",
                                    #         service_name=srvcname,
                                    #         task_definition=self.task,
                                    #         assign_public_ip=respubip,
                                    #         security_groups=[self.ecssg],
                                    #         vpc_subnets=ressubgrp,
                                    #         cluster=self.ecs,
                                    #         capacity_provider_strategies=capstrategy,
                                    #         enable_execute_command=execcmdcfg,
                                    #         cloud_map_options=contmapopt,
                                    #         platform_version=resplatform
                                    #     )
                                    #     if contmapopt != None:
                                    #         self.srvc.enable_cloud_map(contmapopt)
                                        
                                    #     self.srvc.node.default_child.override_logical_id(f"{construct_id}{taskname}{srvcname}")
                                srvcont = srvcont + 1
                        else:
                            contport = None
                        cont = cont + 1
                        self.task.node.default_child.override_logical_id(f"{taskname}")
                    # if 'albfromstack' in task:
                    #     self.srvc.attach_to_application_target_group()
