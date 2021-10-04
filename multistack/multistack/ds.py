#### How to call this file inside app.py file and options
#ADStack = myds(app, "MYDS", env=myenv, res = 'dirserv', vpc = VPCStack.vpc)
# where:
# ADStack ==> Name of stack, used if you will import values from it in another stack
# myds ==> reference to this script ds.py
# MYDS ==> Name of contruct, you can use on cdk (cdk list, cdk deploy or cdk destroy). . This is the name of Cloudformation Template in cdk.out dir (MYDS.template.json)
# env ==> Environment to be used on this script (Account and region)
# res ==> resource name to be used in this script, see it bellow in resourcesmap.cfg
# vpc ==> vcp-id where will be created security group and launched this instance

#### How to create a resource information on resourcesmap.cfg for this template
#         "NAME": "mybucket",
# {
#     "dirserv": {
#         "NAME": "myds",  ####==> It will be used to create Tag Name associated with this resource. (Mandatory)
#         "KEY": "passphrase",  ####==> The customer-managed encryption key to use for encrypting the secret value. (Mandatory)
#         "Type": "MSAD",  ####==> Type of Directory (SimpleAD|MSAD). (Mandatory)
#         "DOMAIN": "corp.example.com",  ####==> Domain Name. (Mandatory)
#         "SIZE": "Small",  ####==> Instance Size. (Large | Small) (Optional) - https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-directoryservice-simplead.html#cfn-directoryservice-simplead-size
#         "Edition": "Standard",  ####==> Microsoft AD Edition. (Enterprise | Standard) (Optional) - https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-directoryservice-microsoftad.html#cfn-directoryservice-microsoftad-edition
#         "SUBNETGRP": "Private",  ####==> Subnet Group used on VPC creation. (Mandatory)
#         "ALIAS": false,  ####==> boolean - If set to true, specifies an alias for a directory and assigns the alias to the directory. The alias is used to construct the access URL for the directory, such as http://<alias>.awsapps.com. (Optional)
#         "SSO": false,  ####==> boolean - Whether to enable single sign-on for a directory. (Optional)
#         "SHORTNAME": "CORP"  ####==> The NetBIOS name of the directory. (Optional)
#     }
# }

import os
import json
from aws_cdk import (
    aws_directoryservice as ds,
    aws_secretsmanager as sm,
    aws_ec2 as ec2,
    aws_ssm as ssm,
    core,
)
account = core.Aws.ACCOUNT_ID
region = core.Aws.REGION
resconf = "resourcesmap.cfg"
with open(resconf) as resfile:
    resmap = json.load(resfile)
class myds(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, res, vpc = ec2.Vpc, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.vpc = vpc
        # get data for rds resource
        res = res
        resname = resmap['Mappings']['Resources'][res]['NAME']
        reskey = resmap['Mappings']['Resources'][res]['KEY']
        restype = resmap['Mappings']['Resources'][res]['Type']
        resdomain = resmap['Mappings']['Resources'][res]['DOMAIN']
        ressubgrp = resmap['Mappings']['Resources'][res]['SUBNETGRP']
        if 'SIZE' in resmap['Mappings']['Resources'][res]:
            ressize = resmap['Mappings']['Resources'][res]['SIZE']
        else:
            ressize = 'Small'
        if 'ALIAS' in resmap['Mappings']['Resources'][res]:
            resalias = resmap['Mappings']['Resources'][res]['ALIAS']
        else:
            resalias = None
        if 'SSO' in resmap['Mappings']['Resources'][res]:
            ressso = resmap['Mappings']['Resources'][res]['SSO']
        else:
            ressso = None
        if 'SHORTNAME' in resmap['Mappings']['Resources'][res]:
            resshort = resmap['Mappings']['Resources'][res]['SHORTNAME']
        else:
            resshort = None
        if 'Edition' in resmap['Mappings']['Resources'][res]:
            resedt = resmap['Mappings']['Resources'][res]['Edition']
        else:
            resedt = 'Standard'
        # create credentials
        self.passwd = sm.Secret(
                    self,
                    f"{construct_id}{resname}Secret",
                    description=('Simple AD Admin password'),
                    generate_secret_string=sm.SecretStringGenerator(
                        secret_string_template=json.dumps(
                            {
                                "username" : "Administrator"
                            }
                        ),
                        generate_string_key=reskey
                    )
                )
        if restype == 'SimpleAD':
            # create SimpleAD
            self.ds = ds.CfnSimpleAD(
                self,
                f"{construct_id}{resname}",
                name=resdomain,
                password=self.passwd.secret_value_from_json(reskey).to_string(),
                size=ressize,
                vpc_settings=ds.CfnSimpleAD.VpcSettingsProperty(
                    subnet_ids=[self.vpc.select_subnets(subnet_group_name=ressubgrp,one_per_az=True).subnet_ids[0],self.vpc.select_subnets(subnet_group_name=ressubgrp,one_per_az=True).subnet_ids[1]],
                    vpc_id=self.vpc.vpc_id
                ),
                create_alias=resalias,
                description=('My Directory Service'),
                enable_sso=ressso,
                short_name=resshort
            )
        elif restype == 'MSAD':
            # create MicroSoft AD
            self.ds = ds.CfnMicrosoftAD(
                self,
                f"{construct_id}{resname}",
                name=resdomain,
                password=self.passwd.secret_value_from_json(reskey).to_string(),
                vpc_settings=ds.CfnMicrosoftAD.VpcSettingsProperty(
                    subnet_ids=[self.vpc.select_subnets(subnet_group_name=ressubgrp,one_per_az=True).subnet_ids[0],self.vpc.select_subnets(subnet_group_name=ressubgrp,one_per_az=True).subnet_ids[1]],
                    vpc_id=self.vpc.vpc_id
                ),
                create_alias=resalias,
                edition=resedt,
                enable_sso=ressso,
                short_name=resshort
            )
        self.dsid = core.CfnOutput(
            self,
            f"{self.stack_name}id",
            value=self.ds.ref,
            export_name=f"{self.stack_name}id"
        )
        self.dsname = core.CfnOutput(
            self,
            f"{self.stack_name}DomainName",
            value=self.ds.name,
            export_name=f"{self.stack_name}DomainName"
        )
        # splitdomain=resdomain.split('.')
        # directoryou = ''
        # for i in splitdomain:
        #     if i == splitdomain[0]:
        #         directoryou += str(f"OU={i},")
        #     elif i == splitdomain[len(splitdomain)-1]:
        #         directoryou += str(f"DC={i}")
        #     else:
        #         directoryou += str(f"DC={i},")
        # self.dsou = core.CfnOutput(
        #     self,
        #     f"{self.stack_name}DirectoryOU",
        #     value=directoryou,
        #     export_name=f"{self.stack_name}DirectoryOU"
        # )
        if resalias == True:
            core.CfnOutput(
                self,
                f"{self.stack_name}Alias",
                value=self.ds.get_att('Alias'),
                export_name=f"{self.stack_name}Alias"
            )
        index = 0
        while index <= 1:
            core.CfnOutput(
                self,
                f"{self.stack_name}Dns{index}",
                value=core.Fn.select(index, core.Token.as_list(self.ds.get_att('DnsIpAddresses'))),
                export_name=f"{self.stack_name}Dns{index}",
            ).override_logical_id(f"{self.stack_name}Dns{index}")
            index = index + 1
        # if 'SSMJOIN' in resmap['Mappings']['Resources'][res]:
        #     if resmap['Mappings']['Resources'][res]['SSMJOIN'] == True:
        #         ssmdoc = {}
        #         ssmdoc['schemaVersion'] = '1.2'
        #         ssmdoc['description'] = f"SSM document for join to domain {self.ds.ref}"
        #         ssmdoc['runtimeConfig'] = {}
        #         ssmdoc['runtimeConfig']['aws:domainJoin'] = {}
        #         ssmdoc['runtimeConfig']['aws:domainJoin']['properties'] = {}
        #         ssmdoc['runtimeConfig']['aws:domainJoin']['properties']['directoryId'] = self.ds.ref
        #         ssmdoc['runtimeConfig']['aws:domainJoin']['properties']['directoryName'] = resdomain
        #         splitdomain=resdomain.split('.')
        #         directoryou = ''
        #         for i in splitdomain:
        #             if i == splitdomain[0]:
        #                 directoryou += str(f"OU={i},")
        #             elif i == splitdomain[len(splitdomain)-1]:
        #                 directoryou += str(f"DC={i}")
        #             else:
        #                 directoryou += str(f"DC={i},")
        #         ssmdoc['runtimeConfig']['aws:domainJoin']['properties']['directoryOU'] = directoryou
        #         ssmdoc['runtimeConfig']['aws:domainJoin']['properties']['dnsIpAddresses'] = [self.ds.attr_dns_ip_addresses]
        #         self.dsjoin = ssm.CfnDocument(
        #             self,
        #             f"{construct_id}{resname}Joindoc",
        #             content=ssmdoc,
        #             document_format='JSON'
        #         )
        #         self.dsjoindoc = core.CfnOutput(
        #             self,
        #             f"{self.stack_name}SSMJoindoc",
        #             value=self.dsjoin.ref,
        #             export_name=f"{self.stack_name}SSMJoindoc"
        #         )

        


