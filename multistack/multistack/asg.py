#### How to call this file inside app.py file and options
# ASGStack = asg(app, "MY-ASG", env=myenv, res = 'nginxbe', preflst = True, allowall = '', ipstack = ipstack, allowsg = BationStack.bastionsg, vpc = VPCStack.vpc)
# where:
# ASGStack ==> Name of stack, used if you will import values from it in another stack
# asg ==> name of this script asg.py
# MY-ASG ==> Name of contruct, you can use on cdk (cdk list, cdk deploy or cdk destroy). . This is the name of Cloudformation Template in cdk.out dir (MY-BASTION.template.json)
# env ==> Environment to be used on this script (Account and region)
# res ==> resource name to be used in this script, see it bellow in resourcesmap.cfg
# preflst ==> boolean to use prefix-list on ingress security group (Allow ALL), see it bellow in zonemap.cfg
# allowsg ==> Security group to be allowed on ingress rules (Allow ALL)
# allowall ==> If true it will create this ingress rules (Allow ALL) or if port number, like 22 (ssh), it will create this ingress rule (Allow ALL for the given port)
# ipstack ==> if will be just ipv4 or dualstack (ipv6)
# vpc ==> vcp-id where will be created security group and launched this instance

#### How to create a resource information on resourcesmap.cfg for this template  ==>>> VIDE bastion.py

#### How to use a resource information on zonemap.cfg for this template  ==>>> VIDE bastion.py

import os
import json
from aws_cdk import (
    aws_ec2 as ec2,
    aws_ecs as ecs,
    aws_iam as iam,
    aws_autoscaling as asg,
    aws_cloudwatch as cw,
    aws_sns as sns,
    core,
)
from aws_cdk.aws_s3_assets import Asset
from zipfile import ZipFile
account = core.Aws.ACCOUNT_ID
region = core.Aws.REGION
resconf = "resourcesmap.cfg"
with open(resconf) as resfile:
    resmap = json.load(resfile)
with open('zonemap.cfg') as zonefile:
    zonemap = json.load(zonefile)

class main(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, res, preflst, allowall, ipstack, stackusrdata, snstopic = sns.Topic.topic_arn, vpc = ec2.Vpc, allowsg = ec2.SecurityGroup, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.vpc = vpc
        self.ipstack = ipstack
        if allowsg != '':
            self.allowsg = allowsg
        # get prefix list from file to allow traffic from the office
        self.map = core.CfnMapping(
            self,
            f"{construct_id}Map",
            mapping=zonemap["Mappings"]["RegionMap"]
        )
        # get config for resource
        res = res
        ressubgrp = resmap['Mappings']['Resources'][res]['SUBNETGRP']
        ressize = resmap['Mappings']['Resources'][res]['SIZE']
        resclass = resmap['Mappings']['Resources'][res]['CLASS']
        if 'KEY' in resmap['Mappings']['Resources'][res]:
            mykey = resmap['Mappings']['Resources'][res]['KEY'] + region
        else:
            mykey = None
        if snstopic == '':
            if 'SNSTOPIC' in resmap['Mappings']['Resources'][res]:
                topicname = resmap['Mappings']['Resources'][res]['SNSTOPIC']
                snstopic = sns.Topic.from_topic_arn(
                    self,
                    f"{construct_id}:SNSTopic",
                    topic_arn=f"arn:{core.Aws.PARTITION}:sns:{core.Aws.REGION}:{core.Aws.ACCOUNT_ID}:{topicname}"
                )
            else:
                snstopic = None
        if 'cooldown' in resmap['Mappings']['Resources'][res]:
            cooldown = core.Duration.seconds(resmap['Mappings']['Resources'][res]['cooldown'])
        else:
            cooldown = core.Duration.seconds(30)
        if 'min' in resmap['Mappings']['Resources'][res]:
            mincap = resmap['Mappings']['Resources'][res]['min']
        else:
            mincap = 1
        if 'max' in resmap['Mappings']['Resources'][res]:
            maxcap = resmap['Mappings']['Resources'][res]['max']
        else:
            maxcap = 1
        if 'desir' in resmap['Mappings']['Resources'][res]:
            desircap = resmap['Mappings']['Resources'][res]['desir']
        else:
            desircap = None
        if 'MONITOR' in resmap['Mappings']['Resources'][res]:
            resmon = resmap['Mappings']['Resources'][res]['MONITOR']
        else:
            resmon = False
        if 'MANAGPOL' in resmap['Mappings']['Resources'][res]:
            resmanpol = resmap['Mappings']['Resources'][res]['MANAGPOL']
        else:
            resmanpol = ''
        if 'VOLUMES' in resmap['Mappings']['Resources'][res]:
            myblkdev = []
            for vol in resmap['Mappings']['Resources'][res]['VOLUMES']:
                resvolname = vol['NAME']
                resvolsize = vol['SIZE']
                resvolcrypt = vol['CRYPT']
                if vol['TYPE'] == 'GP2':
                    resvoltype = asg.EbsDeviceVolumeType.GP2
                elif vol['TYPE'] == 'GP3':
                    resvoltype = asg.EbsDeviceVolumeType.GP3
                elif vol['TYPE'] == 'IO1':
                    resvoltype = asg.EbsDeviceVolumeType.IO1
                elif vol['TYPE'] == 'IO2':
                    resvoltype = asg.EbsDeviceVolumeType.IO2
                elif vol['TYPE'] == 'SC1':
                    resvoltype = asg.EbsDeviceVolumeType.SC1
                elif vol['TYPE'] == 'ST1':
                    resvoltype = asg.EbsDeviceVolumeType.ST1
                elif vol['TYPE'] == 'STANDARD':
                    resvoltype = asg.EbsDeviceVolumeType.STANDARD
                myblkdev.append(asg.BlockDevice(
                    device_name="/dev/xvda",
                    volume=asg.BlockDeviceVolume.ebs(
                        volume_type=resvoltype,
                        volume_size=resvolsize,
                        encrypted=resvolcrypt,
                        delete_on_termination=True
                    )
                ))
        else:
            myblkdev = None
        if 'INTERNET' in resmap['Mappings']['Resources'][res]:
            reseip = resmap['Mappings']['Resources'][res]['INTERNET']
        else:
            reseip = False
        # create security group for Auto Scale Group
        self.asgsg = ec2.SecurityGroup(
            self,
            f"{construct_id}:MyASGsg",
            allow_all_outbound=True,
            vpc=self.vpc
        )
        # add egress rule
        ec2.CfnSecurityGroupEgress(
            self,
            f"{construct_id}:EgressAllIpv4",
            ip_protocol="-1",
            cidr_ip="0.0.0.0/0",
            group_id=self.asgsg.security_group_id
        )
        if self.ipstack == 'Ipv6':
            ec2.CfnSecurityGroupEgress(
                self,
                f"{construct_id}:EgressAllIpv6",
                ip_protocol="-1",
                cidr_ipv6="::/0",
                group_id=self.asgsg.security_group_id
            )
        # add ingress rule
        if allowsg != '':
            self.asgsg.add_ingress_rule(
                self.allowsg,
                ec2.Port.all_traffic()
            )
        if preflst == True:
            srcprefix = self.map.find_in_map(core.Aws.REGION, 'PREFIXLIST')
            self.asgsg.add_ingress_rule(
                ec2.Peer.prefix_list(srcprefix),
                ec2.Port.all_traffic()
            )
        if allowall == True:
            self.asgsg.add_ingress_rule(
                ec2.Peer.any_ipv4(),
                ec2.Port.all_traffic()
            )
            if self.ipstack == 'Ipv6':
                self.asgsg.add_ingress_rule(
                    ec2.Peer.any_ipv6(),
                    ec2.Port.all_traffic()
                )
        if type(allowall) == int or type(allowall) == float:
            self.asgsg.add_ingress_rule(
                ec2.Peer.any_ipv4(),
                ec2.Port.tcp(allowall)
            )
            if self.ipstack == 'Ipv6':
                self.asgsg.add_ingress_rule(
                    ec2.Peer.any_ipv6()(),
                    ec2.Port.tcp(allowall)
                )
        # create instance profile for SSM patching
        pol = iam.ManagedPolicy.from_aws_managed_policy_name('AmazonSSMManagedInstanceCore')
        pol1 = iam.ManagedPolicy.from_aws_managed_policy_name('AmazonSSMPatchAssociation')
        resrole = iam.Role(
            self,
            f"{construct_id}Role",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            description=f"Role for Auto Scale Group",
            managed_policies=[pol, pol1]
        )
        if resmanpol !='':
            manpol = iam.ManagedPolicy.from_aws_managed_policy_name(resmanpol)
            resrole.add_managed_policy(manpol)
        if 'IMAGE' in resmap['Mappings']['Resources'][res]:
            imagekind = resmap['Mappings']['Resources'][res]['IMAGE']
            if type(imagekind) == str:
                if imagekind == 'AWSL2':
                    machineimage = ec2.AmazonLinuxImage(
                        edition=ec2.AmazonLinuxEdition.STANDARD,
                        generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2,
                    )
                    image = 'Linux'
                    usrdata = ec2.UserData.for_linux()
                    if stackusrdata !='':
                        usrdata.add_commands(stackusrdata)  
                    usrdata.add_commands(
                        "if [ $(curl --connect-timeout 3 -X HEAD -LI https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o /dev/null -w '%{http_code}\n' -s) == \"200\" ]; then curl 'https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip' -o 'awscliv2.zip'; rm /usr/bin/aws; unzip awscliv2.zip; rm awscliv2.zip; ./aws/install -i /usr/local/aws-cli -b /usr/bin; fi"
                        # "curl 'https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip' -o 'awscliv2.zip'",
                        # "rm /usr/bin/aws",
                        # "unzip awscliv2.zip",
                        # "rm awscliv2.zip",
                        # "./aws/install -i /usr/local/aws-cli -b /usr/bin"
                    )
                elif imagekind == 'WIN2019FULL':
                    machineimage = ec2.WindowsImage(
                        version=ec2.WindowsVersion.WINDOWS_SERVER_2019_ENGLISH_FULL_BASE
                    )
                    image = 'Windows'
                    usrdata = ec2.UserData.for_windows()
                    if stackusrdata !='':
                        usrdata.add_commands(stackusrdata)  
                    usrdata.add_commands(
                        "$Path = $env:TEMP;",
                        "$Installer = \"msiexec.exe\";",
                        "$Package = \"AWSCLIV2.msi\";",
                        "$arguments = \"/I $Path\$Package /qn\";",
                        "Invoke-WebRequest \"https://awscli.amazonaws.com/AWSCLIV2.msi\" -OutFile     $Path\$Package;",
                        "Start-Process $Installer -Wait -ArgumentList $arguments;"
                        "Remove-Item $Path\$Package"
                    )
                elif imagekind == 'Bottlerocket':
                    machineimage = ecs.BottleRocketImage(architecture=ecs.AmiHardwareType.STANDARD)
                    image = 'Bottlerocket'
                elif imagekind == 'BottlerocketARM':
                    machineimage = ecs.BottleRocketImage(architecture=ecs.AmiHardwareType.ARM)
                    image = 'Bottlerocket'
                elif imagekind == 'ECSAWSL2':
                    machineimage = ecs.EcsOptimizedImage.amazon_linux2()
                    image = 'Linux'
                else:
                    machineimage = ec2.AmazonLinuxImage(
                        edition=ec2.AmazonLinuxEdition.STANDARD,
                        generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2,
                    )
                    image = 'Linux'
                    usrdata = ec2.UserData.for_linux()
                    if stackusrdata !='':
                        usrdata.add_commands(stackusrdata)  
                    usrdata.add_commands(
                        "if [ $(curl --connect-timeout 3 -X HEAD -LI https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o /dev/null -w '%{http_code}\n' -s) == \"200\" ]; then curl 'https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip' -o 'awscliv2.zip'; rm /usr/bin/aws; unzip awscliv2.zip; rm awscliv2.zip; ./aws/install -i /usr/local/aws-cli -b /usr/bin; fi"
                        # "curl 'https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip' -o 'awscliv2.zip'",
                        # "rm /usr/bin/aws",
                        # "unzip awscliv2.zip",
                        # "rm awscliv2.zip",
                        # "./aws/install -i /usr/local/aws-cli -b /usr/bin"
                    )
            elif type(imagekind) == dict:
                if 'NAME' in imagekind:
                    imagename = imagekind['NAME']
                if 'FILTER' in imagekind:
                    imagefilter = imagekind['FILTER']
                machineimage = ec2.LookupMachineImage(
                    name = imagename,
                    owners=['aws-marketplace'], 
                    filters=imagefilter
                )
                image = 'Appliance'
            else:
                machineimage = ec2.AmazonLinuxImage(
                    edition=ec2.AmazonLinuxEdition.STANDARD,
                    generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2,
                )
                image = 'Linux'
                usrdata = ec2.UserData.for_linux()
                if stackusrdata !='':
                    usrdata.add_commands(stackusrdata)  
                usrdata.add_commands(
                    "if [ $(curl --connect-timeout 3 -X HEAD -LI https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o /dev/null -w '%{http_code}\n' -s) == \"200\" ]; then curl 'https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip' -o 'awscliv2.zip'; rm /usr/bin/aws; unzip awscliv2.zip; rm awscliv2.zip; ./aws/install -i /usr/local/aws-cli -b /usr/bin; fi"
                    # "curl 'https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip' -o 'awscliv2.zip'",
                    # "rm /usr/bin/aws",
                    # "unzip awscliv2.zip",
                    # "rm awscliv2.zip",
                    # "./aws/install -i /usr/local/aws-cli -b /usr/bin"
                )
        else:
            machineimage = ec2.AmazonLinuxImage(
                edition=ec2.AmazonLinuxEdition.STANDARD,
                generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2,
            )
            image = 'Linux'
            usrdata = ec2.UserData.for_linux()
            if stackusrdata !='':
                usrdata.add_commands(stackusrdata)  
            usrdata.add_commands(
                "if [ $(curl --connect-timeout 3 -X HEAD -LI https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o /dev/null -w '%{http_code}\n' -s) == \"200\" ]; then curl 'https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip' -o 'awscliv2.zip'; rm /usr/bin/aws; unzip awscliv2.zip; rm awscliv2.zip; ./aws/install -i /usr/local/aws-cli -b /usr/bin; fi"
                # "curl 'https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip' -o 'awscliv2.zip'",
                # "rm /usr/bin/aws",
                # "unzip awscliv2.zip",
                # "rm awscliv2.zip",
                # "./aws/install -i /usr/local/aws-cli -b /usr/bin"
            )
        # SNS Topic
        if snstopic != None:
            notification_configuration = [
                asg.NotificationConfiguration(
                    topic=snstopic,
                    scaling_events=asg.ScalingEvents.ALL
                )
            ]
        else:
            notification_configuration = None

        # create Auto Scalling Group
        self.asg = asg.AutoScalingGroup(
            self,
            f"{construct_id}",
            instance_type=ec2.InstanceType.of(
                instance_class=ec2.InstanceClass(resclass),
                instance_size=ec2.InstanceSize(ressize)
            ),
            machine_image=machineimage,
            block_devices=myblkdev,
            vpc=self.vpc,
            security_group=self.asgsg,
            key_name=mykey,
            desired_capacity=desircap,
            min_capacity=mincap,
            max_capacity=maxcap,
            cooldown=cooldown,
            group_metrics=[asg.GroupMetrics.all()],
            vpc_subnets=ec2.SubnetSelection(subnet_group_name=ressubgrp,one_per_az=True),
            role=resrole,
            user_data=usrdata,
            associate_public_ip_address=reseip,
            notifications=notification_configuration
        )
        if 'USRFILE' in resmap['Mappings']['Resources'][res]:
            userdata = resmap['Mappings']['Resources'][res]['USRFILE']
            if type(userdata) == str:
                usrdatafile = resmap['Mappings']['Resources'][res]['USRFILE']
                usrdata = open(usrdatafile, "r").read()
                self.asg.add_user_data(usrdata)
            elif type(userdata) == list:
                usrdatalst = []
                with ZipFile(f"cdk.out/{construct_id}customscript.zip",'w') as zip:
                    for usractions in resmap['Mappings']['Resources'][res]['USRFILE']:
                        filename = usractions['filename']
                        execution = usractions['execution']
                        usrdatalst.append(f"{execution} {filename}\n")
                        usrdatalst.append(f"rm {filename}\n")
                        zip.write(filename)
                if os.path.isfile(f"cdk.out/{construct_id}customscript.zip"):
                    customscript = Asset(
                        self,
                        f"{construct_id}customscript",
                        path=f"cdk.out/{construct_id}customscript.zip"
                    )
                    # core.CfnOutput(self, "S3BucketName", value=customscript.s3_bucket_name)
                    # core.CfnOutput(self, "S3ObjectKey", value=customscript.s3_object_key)
                    # core.CfnOutput(self, "S3HttpURL", value=customscript.http_url)
                    # core.CfnOutput(self, "S3ObjectURL", value=customscript.s3_object_url)
                    customscript.grant_read(self.asg.role)
                    self.asg.add_user_data(
                        "yum install -y unzip",
                        f"aws s3 cp s3://{customscript.s3_bucket_name}/{customscript.s3_object_key} customscript.zip",
                        f"unzip customscript.zip",
                        f"rm customscript.zip\n"
                    )
                    usrdata = ''.join(usrdatalst)
                    self.asg.add_user_data(usrdata)
        # add tags
        if 'TAGS' in resmap['Mappings']['Resources'][res]:
            for tagsmap in resmap['Mappings']['Resources'][res]['TAGS']:
                for k,v in tagsmap.items():
                    core.Tags.of(self.asg).add(k,v,apply_to_launched_instances=True)
        
        if resmon == True:
            cw.CfnAlarm(
                self,
                f"{construct_id}Alarm",
                comparison_operator=("LessThanOrEqualToThreshold"),
                evaluation_periods=3,
                actions_enabled=False,
                datapoints_to_alarm=2,
                threshold=0,
                dimensions=[
                    dict(
                        name="AutoScalingGroupName",
                        value=self.asg.auto_scaling_group_name
                    )
                ],
                namespace=("AWS/AutoScaling"),
                metric_name=("GroupInServiceInstances"),
                period=core.Duration.minutes(1).to_seconds(),
                statistic="Minimum",
            )
        self.asg.scale_on_schedule(
            "PrescaleInTheMorning",
            schedule=asg.Schedule.cron(hour="9", minute="0"),
            desired_capacity=2
        )
        self.asg.scale_on_schedule(
            "AllowDownscalingAtNight",
            schedule=asg.Schedule.cron(hour="20", minute="0"),
            desired_capacity=0
        )
