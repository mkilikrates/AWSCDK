import os
import json
from aws_cdk import (
    aws_sns as sns,
    aws_kms as kms,
    aws_iam as iam,
    core,
)
account = core.Aws.ACCOUNT_ID
region = core.Aws.REGION
resconf = "resourcesmap.cfg"
with open(resconf) as resfile:
    resmap = json.load(resfile)

class main(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, res, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        if res != '':
            topicname = resmap['Mappings']['Resources'][res]['NAME']
            if 'SNSKEY' in resmap['Mappings']['Resources'][res]:
                if 'Crypkey' in resmap['Mappings']['Resources'][res]['SNSKEY']:
                    cripkey = kms.KeySpec(value=resmap['Mappings']['Resources'][res]['SNSKEY']['Crypkey'])
                else:
                    cripkey = kms.KeySpec.SYMMETRIC_DEFAULT
                if 'keyrot' in resmap['Mappings']['Resources'][res]['SNSKEY']:
                    keyrot = resmap['Mappings']['Resources'][res]['SNSKEY']['keyrot']
                else:
                    keyrot = False

                if 'penwin' in resmap['Mappings']['Resources'][res]['SNSKEY']:
                    penwin = core.Duration.days(resmap['Mappings']['Resources'][res]['SNSKEY']['penwin'])
                else:
                    penwin = core.Duration.days(7)
                if 'rempol' in resmap['Mappings']['Resources'][res]['SNSKEY']:
                    rempol = core.RemovalPolicy(resmap['Mappings']['Resources'][res]['SNSKEY']['rempol'])
                else:
                    rempol = core.RemovalPolicy.DESTROY
                mypol = None
                if 'POLICE' in resmap['Mappings']['Resources'][res]['SNSKEY']:
                    mypol = []
                    for police in resmap['Mappings']['Resources'][res]['SNSKEY']['POLICE']:
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
                        mypol.append(iam.PolicyStatement(**newpol))
                snskey = kms.Key(
                    self,
                    f"{construct_id}SNSKey",
                    alias=resmap['Mappings']['Resources'][res]['NAME'],
                    description="Key for SNS Topic",
                    key_usage=kms.KeyUsage.ENCRYPT_DECRYPT,
                    enabled=True,
                    key_spec=cripkey,
                    policy=mypol,
                    enable_key_rotation=keyrot,
                    removal_policy=rempol,
                    pending_window=penwin
                )
            else:
                snskey = None
            if 'SNSFIFO' in resmap['Mappings']['Resources'][res]:
                snsfifo = resmap['Mappings']['Resources'][res]['SNSFIFO']
            else:
                snsfifo = False
                snscontdedup = None
            if snsfifo == True:
                if 'SNSDEDUP' in resmap['Mappings']['Resources'][res]:
                    snscontdedup = resmap['Mappings']['Resources'][res]['SNSDEDUP']
                else:
                    snscontdedup = False
            self.snstopic = sns.Topic(
                self,
                f"{construct_id}Topic",
                display_name=topicname,
                topic_name=topicname,
                content_based_deduplication=snscontdedup,
                fifo=snsfifo,
                master_key=snskey
            )
        
