import os
import json
from aws_cdk import (
    aws_certificatemanager as acm,
    aws_route53 as r53,
    aws_route53_targets as r53tgs,
    core,
)
account = os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"])
region = os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])
resconf = "resourcesmap.cfg"
with open(resconf) as resfile:
    resmap = json.load(resfile)
class cert(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, domain, san, validation, hz, res, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        if domain == '':
            if 'DOMAIN' in resmap['Mappings']['Resources'][res]:
                domain = resmap['Mappings']['Resources'][res]['DOMAIN']
        if san == []:
            if 'SAN' in resmap['Mappings']['Resources'][res]:
                san = resmap['Mappings']['Resources'][res]['SAN']
        if type(hz) == list:
            domainlst = []
            for domain in hz:
                domainlst.append(r53.HostedZone.from_hosted_zone_id(
                    self,
                    f"{construct_id}:Domain",
                    hosted_zone_id=domain
                ))
        elif hz == '':
            if 'HZ' in resmap['Mappings']['Resources'][res]:
                hz = resmap['Mappings']['Resources'][res]['HZ']
                if type(hz) == list:
                    domainlst = []
                    for domain in hz:
                        domainlst.append(r53.HostedZone.from_hosted_zone_id(
                            self,
                            f"{construct_id}:Domain",
                            hosted_zone_id=domain
                        ))
                else:
                    self.hz = r53.HostedZone.from_hosted_zone_id(
                        self,
                        f"{construct_id}:Domain",
                        hosted_zone_id=hz
                    )
            if 'HDomain' in resmap['Mappings']['Resources'][res]:
                if type(resmap['Mappings']['Resources'][res]['HDomain']) == list:
                    domainlst = []
                    for domain in hz:
                        domainlst.append(r53.HostedZone.from_lookup(
                            self,
                            f"{construct_id}:Domain",
                            domain_name=domain,
                            private_zone=False
                        ))
                    hz = domainlst
                else:
                    self.hz = r53.HostedZone.from_lookup(
                        self,
                        f"{construct_id}:Domain",
                        domain_name=resmap['Mappings']['Resources'][res]['HDomain'],
                        private_zone=False
                    )
                    hz = self.hz.hosted_zone_id
            if 'EMAILDomain' in resmap['Mappings']['Resources'][res]:
                emaildomain = resmap['Mappings']['Resources'][res]['EMAILDomain']
        if validation == '':
            if 'VALIDATION' in resmap['Mappings']['Resources'][res]:
                if resmap['Mappings']['Resources'][res]['VALIDATION'] == 'DNS':
                    if type(hz) == list:
                        validation = acm.CertificateValidation.from_dns_multi_zone(hosted_zones=hz)
                    elif hz != '':
                        validation = acm.CertificateValidation.from_dns(hosted_zone=self.hz)
                    else:
                        validation = acm.CertificateValidation.from_dns()
                elif resmap['Mappings']['Resources'][res]['VALIDATION'] == 'EMAIL':
                    validation = acm.CertificateValidation.from_email(validation_domains=emaildomain)
                else:
                    if hz != '':
                        validation = acm.CertificateValidation.from_dns(hosted_zone=self.hz)
                    else:
                        validation = acm.CertificateValidation.from_dns()
            else:
                if hz != '':
                    validation = acm.CertificateValidation.from_dns(hosted_zone=self.hz)
                else:
                    validation = acm.CertificateValidation.from_dns()
        else:
            if hz != '':
                validation = acm.CertificateValidation.from_dns(hosted_zone=self.hz)
            else:
                validation = acm.CertificateValidation.from_dns()
        self.cert = acm.Certificate(
            self,
            f"{construct_id}Cert",
            domain_name=domain,
            subject_alternative_names=san,
            validation=validation,
        )
