import os
import json
from aws_cdk import (
    aws_directoryservice as ds,
    aws_secretsmanager as sm,
    aws_ec2 as ec2,
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
        restype = resmap['Mappings']['Resources'][res]['Type']
        resdomain = resmap['Mappings']['Resources'][res]['DOMAIN']
        ressize = resmap['Mappings']['Resources'][res]['SIZE']
        ressubgrp = resmap['Mappings']['Resources'][res]['SUBNETGRP']
        resalias = resmap['Mappings']['Resources'][res]['ALIAS']
        ressso = resmap['Mappings']['Resources'][res]['SSO']
        resshort = resmap['Mappings']['Resources'][res]['SHORTNAME']
        reskey = resmap['Mappings']['Resources'][res]['KEY']
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
            self.dsid = core.CfnOutput(
                self,
                f"{construct_id}id",
                value=self.ds.ref,
                export_name=f"{construct_id}id"
            )
            if resalias == True:
                core.CfnOutput(
                    self,
                    f"{construct_id}mydsAlias",
                    value=self.ds.get_att('Alias'),
                    export_name=f"{construct_id}mydsAlias"
                )
            index = 0
            while index <= 1:
                core.CfnOutput(
                    self,
                    f"{construct_id}{resname}Dns{index}",
                    value=core.Fn.select(index, core.Token.as_list(self.ds.get_att('DnsIpAddresses'))),
                    export_name=f"{construct_id}{resname}Dns{index}",
                )
                index = index + 1

