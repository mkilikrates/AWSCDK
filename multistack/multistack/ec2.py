import os
import json
from typing import Annotated
from aws_cdk import (
    aws_ec2 as ec2,
    aws_iam as iam,
    core,
)
from cdk_ec2_key_pair import KeyPair
from aws_cdk.aws_s3_assets import Asset
from zipfile import ZipFile
account = os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"])
region = os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])
class InstanceStack(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, res, preflst, allowall, ipstack, eipall = str, instpol = iam.PolicyStatement, vpc = ec2.Vpc, allowsg = ec2.SecurityGroup, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.vpc = vpc
        self.ipstack = ipstack
        res = res
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
        self.ec2sg = ec2.SecurityGroup(
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
            group_id=self.ec2sg.security_group_id
        )
        if self.ipstack == 'Ipv6':
            ec2.CfnSecurityGroupEgress(
                self,
                f"{construct_id}EgressAllIpv6",
                ip_protocol="-1",
                cidr_ipv6="::/0",
                group_id=self.ec2sg.security_group_id
            )
        # add ingress rule
        if allowsg != '':
            self.ec2sg.add_ingress_rule(
                self.allowsg,
                ec2.Port.all_traffic()
            )
        if preflst == True:
            srcprefix = self.map.find_in_map(core.Aws.REGION, 'PREFIXLIST')
            self.ec2sg.add_ingress_rule(
                ec2.Peer.prefix_list(srcprefix),
                ec2.Port.all_traffic()
            )
        if allowall == True:
            self.ec2sg.add_ingress_rule(
                ec2.Peer.any_ipv4,
                ec2.Port.all_traffic()
            )
            if self.ipstack == 'Ipv6':
                self.ec2sg.add_ingress_rule(
                    ec2.Peer.any_ipv6,
                    ec2.Port.all_traffic()
                )
        if type(allowall) == int or type(allowall) == float:
            self.ec2sg.add_ingress_rule(
                ec2.Peer.any_ipv4(),
                ec2.Port.tcp(allowall)
            )
            if self.ipstack == 'Ipv6':
                self.ec2sg.add_ingress_rule(
                    ec2.Peer.any_ipv6(),
                    ec2.Port.tcp(allowall)
                )
        # create a key to use from this ec2
        if 'CREATEKEY' in resmap['Mappings']['Resources'][res]:
            keyname = resmap['Mappings']['Resources'][res]['CREATEKEY']
            self.key = KeyPair(
                self,
                f"{keyname}",
                name=f"{construct_id}{keyname}-{region}",
                description='Key Pair from CDK automation',
                store_public_key=True
            )
        # get data for ec2 resource
        resname = resmap['Mappings']['Resources'][res]['NAME']
        ressubgrp = resmap['Mappings']['Resources'][res]['SUBNETGRP']
        ressize = resmap['Mappings']['Resources'][res]['SIZE']
        resclass = resmap['Mappings']['Resources'][res]['CLASS']
        if 'MANAGPOL' in resmap['Mappings']['Resources'][res]:
            resmanpol = resmap['Mappings']['Resources'][res]['MANAGPOL']
        else:
            resmanpol = ''
        if 'SRCDSTCHK' in resmap['Mappings']['Resources'][res]:
            ressrcdstchk = resmap['Mappings']['Resources'][res]['SRCDSTCHK']
        else:
            ressrcdstchk = True
        if 'USRDTREPL' in resmap['Mappings']['Resources'][res]:
            resusrdtrepl = resmap['Mappings']['Resources'][res]['USRDTREPL']
        else:
            resusrdtrepl = False
        if 'VOLUMES' in resmap['Mappings']['Resources'][res]:
            myblkdev = []
            for vol in resmap['Mappings']['Resources'][res]['VOLUMES']:
                if 'NAME' in vol:
                    resvolname = vol['NAME']
                else:
                    resvolname = "/dev/xvda"
                resvolsize = vol['SIZE']
                resvolcrypt = vol['CRYPT']
                if vol['TYPE'] == 'GP2':
                    resvoltype = ec2.EbsDeviceVolumeType.GP2
                elif vol['TYPE'] == 'GP3':
                    resvoltype = ec2.EbsDeviceVolumeType.GP3
                elif vol['TYPE'] == 'IO1':
                    resvoltype = ec2.EbsDeviceVolumeType.IO1
                elif vol['TYPE'] == 'IO2':
                    resvoltype = ec2.EbsDeviceVolumeType.IO2
                elif vol['TYPE'] == 'SC1':
                    resvoltype = ec2.EbsDeviceVolumeType.SC1
                elif vol['TYPE'] == 'ST1':
                    resvoltype = ec2.EbsDeviceVolumeType.ST1
                elif vol['TYPE'] == 'STANDARD':
                    resvoltype = ec2.EbsDeviceVolumeType.STANDARD
                myblkdev.append(ec2.BlockDevice(
                    device_name=resvolname,
                    volume=ec2.BlockDeviceVolume.ebs(
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
        if 'KEY' in resmap['Mappings']['Resources'][res]:
            mykey = resmap['Mappings']['Resources'][res]['KEY'] + region
        else:
            mykey = ''
        if 'IMAGE' in resmap['Mappings']['Resources'][res]:
            if resmap['Mappings']['Resources'][res]['IMAGE'] == 'AWSL2':
                machineimage = ec2.AmazonLinuxImage(
                    edition=ec2.AmazonLinuxEdition.STANDARD,
                    generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2,
                )
                image = 'Linux'
            elif resmap['Mappings']['Resources'][res]['IMAGE'] == 'WIN2019FULL':
                machineimage = ec2.WindowsImage(
                    version=ec2.WindowsVersion.WINDOWS_SERVER_2019_ENGLISH_FULL_BASE
                )
                image = 'Windows'
        else:
            machineimage = ec2.AmazonLinuxImage(
                edition=ec2.AmazonLinuxEdition.STANDARD,
                generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2,
            )
            image = 'Linux'

        # create instance
        self.instance = ec2.Instance(
            self,
            f"{construct_id}",
            instance_type=ec2.InstanceType.of(
                instance_class=ec2.InstanceClass(resclass),
                instance_size=ec2.InstanceSize(ressize)
            ),
            machine_image=machineimage,
            vpc=self.vpc,
            block_devices=myblkdev,
            instance_name=resname,
            security_group=self.ec2sg,
            source_dest_check=ressrcdstchk,
            user_data_causes_replacement=resusrdtrepl,
            vpc_subnets=ec2.SubnetSelection(
                subnet_group_name=ressubgrp,
                one_per_az=True
            )
        )
        # add tags
        if 'TAGS' in resmap['Mappings']['Resources'][res]:
            for tagsmap in resmap['Mappings']['Resources'][res]['TAGS']:
                for k,v in tagsmap.items():
                    core.Tags.of(self.instance).add(k,v,include_resource_types=["AWS::EC2::Instance"])
        # add my key
        if mykey != '':
            self.instance.instance.add_property_override("KeyName", mykey)
        # update awscli
        if image == 'Linux':
            self.instance.add_user_data(
                "curl 'https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip' -o 'awscliv2.zip'",
                "rm /usr/bin/aws",
                "unzip awscliv2.zip",
                "rm awscliv2.zip",
                "./aws/install -i /usr/local/aws-cli -b /usr/bin"
            )
        if image == 'Windows':
            self.instance.add_user_data(
                "$Path = $env:TEMP;",
                "$Installer = \"msiexec.exe\";",
                "$Package = \"AWSCLIV2.msi\";",
                "$arguments = \"/I $Path\$Package /qn\";",
                "Invoke-WebRequest \"https://awscli.amazonaws.com/AWSCLIV2.msi\" -OutFile     $Path\$Package;",
                "Start-Process $Installer -Wait -ArgumentList $arguments;",
                "Remove-Item $Path\$Package"
            )
        # add key on ~.ssh/ for ec2-user
        if 'CREATEKEY' in resmap['Mappings']['Resources'][res]:
            self.key.grant_read_on_private_key(self.instance.role)
            if image == 'Linux':
                self.instance.add_user_data(
                    f"aws --region {region} secretsmanager get-secret-value --secret-id ec2-ssh-key/{construct_id}{keyname}-{region}/private --query SecretString --output text > /home/ec2-user/.ssh/{construct_id}{keyname}-{region}.pem",
                    f"chmod 400 /home/ec2-user/.ssh/{construct_id}{keyname}-{region}.pem",
                    "chown -R ec2-user:ec2-user /home/ec2-user/.ssh",
                    "export AZ=$(curl http://169.254.169.254/latest/meta-data/placement/availability-zone)",
                    f"echo 'alias ec2=\"ssh -l ec2-user -i ~/.ssh/{construct_id}{keyname}-{region}.pem\"' >>/home/ec2-user/.bashrc\n"
                )
            if image == 'Windows':
                self.instance.add_user_data(
                    "mkdir $home\\.ssh\n",
                    "$cmd = \"& \'"f"C:\\Program Files\\Amazon\\AWSCLIV2\\aws.exe\' --region {region} secretsmanager get-secret-value --secret-id ec2-ssh-key/{construct_id}{keyname}-{region}/private --query SecretString --output text > $home\\.ssh\\{construct_id}{keyname}-{region}.pem\"""; $Process2Monitor = \"msiexec\"; Do { $ProcessesFound = Get-Process | ?{$Process2Monitor -contains $_.Name} | Select-Object -ExpandProperty Name; If ($ProcessesFound) { \"Still running: $($ProcessesFound -join ', ')\" | Write-Host; Start-Sleep -Seconds 5 } else { Invoke-Expression -Command $cmd -ErrorAction SilentlyContinue -Verbose } } Until (!$ProcessesFound)"
                )
        if 'USRFILE' in resmap['Mappings']['Resources'][res]:
            userdata = resmap['Mappings']['Resources'][res]['USRFILE']
            if type(userdata) == str:
                usrdatafile = resmap['Mappings']['Resources'][res]['USRFILE']
                usrdata = open(usrdatafile, "r").read()
                self.instance.add_user_data(usrdata)
            elif type(userdata) == list and image == 'Linux':
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
                    customscript.grant_read(self.instance.role)
                    self.instance.add_user_data(
                        "yum install -y unzip",
                        f"aws s3 cp s3://{customscript.s3_bucket_name}/{customscript.s3_object_key} customscript.zip",
                        f"unzip customscript.zip",
                        f"rm customscript.zip\n"
                    )
                    usrdata = ''.join(usrdatalst)
                    self.instance.add_user_data(usrdata)
        # create instance profile
        # add SSM permissions to update instance
        pol = iam.ManagedPolicy.from_aws_managed_policy_name('AmazonSSMManagedInstanceCore')
        self.instance.role.add_managed_policy(pol)
        # add managed policy based on resourcemap
        if resmanpol !='':
            manpol = iam.ManagedPolicy.from_aws_managed_policy_name(resmanpol)
            self.instance.role.add_managed_policy(manpol)
        # add policy created by other stack
        if instpol !='':
            self.instance.add_to_role_policy(instpol)
        # allocate elastic ip
        if reseip == True and eipall == '':
            self.eip = ec2.CfnEIP(
                self,
                f"{construct_id}EIP",
                domain='vpc',
                instance_id=self.instance.instance_id,
            )
            core.CfnOutput(
                self,
                f"{construct_id}:EIP",
                value=self.eip.ref,
                export_name=f"{construct_id}:EIP"
            )
        elif eipall !='':
            self.eip = ec2.CfnEIPAssociation(
                self,
                f"{construct_id}EIP",
                allocation_id=eipall,
                instance_id=self.instance.instance_id
            )
        if self.ipstack == 'Ipv6':
            self.instance.instance.add_property_override("Ipv6AddressCount", 1)
        # some outputs
        core.CfnOutput(
            self,
            f"{construct_id}:ID",
            value=self.instance.instance_id,
            export_name=f"{construct_id}:ID"
        )
        core.CfnOutput(
            self,
            f"{construct_id}:PrivIP",
            value=self.instance.instance_private_ip,
            export_name=f"{construct_id}:PrivIP"
        )
        if ressubgrp == 'Public' or eipall !='':
            core.CfnOutput(
                self,
                f"{construct_id}:PubIP",
                value=self.instance.instance_public_ip,
                export_name=f"{construct_id}:PubIP"
            )
        
