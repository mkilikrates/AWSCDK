import os
import json
from aws_cdk import (
    aws_ec2 as ec2,
    aws_servicediscovery as sd,
    core,
)
account = core.Aws.ACCOUNT_ID
region = core.Aws.REGION

class ServiceDiscovery(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, res, ipstack, elb, vpc = ec2.Vpc, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.vpc = vpc
        res = res
        resconf = "resourcesmap.cfg"
        with open(resconf) as resfile:
            resmap = json.load(resfile)
        # get data for resource
        resname = resmap['Mappings']['Resources'][res]['NAME']
        if 'SDTYPE' in resmap['Mappings']['Resources'][res]:
            restype = resmap['Mappings']['Resources'][res]['SDTYPE']
        else:
            restype = 'HTTP'
        if restype == 'HTTP':
            self.namespace = sd.HttpNamespace(
                self,
                f"{construct_id}Namespace",
                name=resname
            )
        elif restype == 'VPC':
            self.namespace = sd.PrivateDnsNamespace(
                self,
                f"{construct_id}PrivateVPCNamespace",
                name=resname,
                vpc=self.vpc
            )
        elif restype == 'PUB':
            self.namespace = sd.PublicDnsNamespace(
                self,
                f"{construct_id}PrivateVPCNamespace",
                name=resname
            )
        if 'DNSTYPE' in resmap['Mappings']['Resources'][res]:
            dnstype = resmap['Mappings']['Resources'][res]['DNSTYPE']
        else:
            dnstype = 'A'
        if dnstype == 'DUAL':
            dnsrectype = sd.DnsRecordType.A_AAAA
        elif dnstype == 'SRV':
            dnsrectype = sd.DnsRecordType.SRV
        elif dnstype == 'CNAME':
            dnsrectype = sd.DnsRecordType.CNAME
        elif dnstype == 'A':
            dnsrectype = sd.DnsRecordType.A
        elif dnstype == 'AAAA':
            dnsrectype = sd.DnsRecordType.AAAA
        if elb != '':
            loadbalancer = True
        else:
            loadbalancer = False
        if 'SRVDNSTTL' in resmap['Mappings']['Resources'][res]:
            servicednsttl = core.Duration.seconds(resmap['Mappings']['Resources'][res]['SRVDNSTTL'])
        else:
            servicednsttl = core.Duration.seconds(60)
        if 'SDHC' in resmap['Mappings']['Resources'][res]:
            if 'FAILTHR' in resmap['Mappings']['Resources'][res]['SDHC']:
                hcfailthr = resmap['Mappings']['Resources'][res]['SDHC']['FAILTHR']
            else:
                hcfailthr = 1
            if restype != 'VPC':
                if 'PATH' in resmap['Mappings']['Resources'][res]['SDHC']:
                    hcpath = resmap['Mappings']['Resources'][res]['SDHC']['PATH']
                else:
                    hcpath = 1
                if 'TYPE' in resmap['Mappings']['Resources'][res]['SDHC']:
                    if resmap['Mappings']['Resources'][res]['SDHC']['TYPE'] == 'HTTP':
                        hctype = sd.HealthCheckType.HTTP
                    if resmap['Mappings']['Resources'][res]['SDHC']['TYPE'] == 'HTTPS':
                        hctype = sd.HealthCheckType.HTTPS
                    if resmap['Mappings']['Resources'][res]['SDHC']['TYPE'] == 'TCP':
                        hctype = sd.HealthCheckType.TCP
                else:
                    hctype = sd.HealthCheckType.HTTP
                hc = sd.HealthCheckConfig(
                    failure_threshold=hcfailthr,
                    resource_path=hcpath,
                    type=hctype
                )
            if restype == 'VPC':
                hc = None
                chc = sd.HealthCheckCustomConfig(
                    failure_threshold=hcfailthr
                )
        else:
            hc = None
        if 'NAMESPACE' in resmap['Mappings']['Resources'][res]:
            servicename = resmap['Mappings']['Resources'][res]['NAMESPACE']
            self.servicename = self.namespace.create_service(
                f"{construct_id}ServiceName",
                name=servicename,
                dns_record_type=dnsrectype,
                dns_ttl=servicednsttl,
                health_check=hc,
                load_balancer=loadbalancer,
                custom_health_check=chc
            )
            core.CfnOutput(
                self,
                f"{construct_id}ServiceName",
                value=self.servicename.namespace.namespace_name
            )
        if elb != '':
            self.servicename.register_load_balancer(
                f"{construct_id}ServiceNameLB",
                load_balancer=elb
            )
        
