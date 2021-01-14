import os
import json
from aws_cdk import (
    aws_ec2 as ec2,
    aws_cloudwatch as cw,
    aws_certificatemanager as acm,
    aws_route53 as r53,
    aws_route53_targets as r53tgs,
    aws_logs as log,
    aws_iam as iam,
    core,
)
account = os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"])
region = os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])
resconf = "resourcesmap.cfg"
with open(resconf) as resfile:
    resmap = json.load(resfile)

class cvpncert(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, vpc = ec2.Vpc, bastionsg = ec2.SecurityGroup, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.vpc = vpc
        self.bastionsg = bastionsg
        # get config for resource
        res = 'cvpn'
        appname = resmap['Mappings']['Resources'][res]['NAME']
        appdomain = resmap['Mappings']['Resources'][res]['DOMAIN']
        clicerarn = resmap['Mappings']['Resources'][res]['CLICERT']
        cvpncidr = resmap['Mappings']['Resources'][res]['CIDR']
        # get hosted zone id
        self.hz = r53.HostedZone.from_lookup(
            self,
            f"{construct_id}:Domain",
            domain_name=appdomain,
            private_zone=False
        )
        # generate public certificate
        self.cert = acm.Certificate(
            self,
            f"{construct_id}:Certificate",
            domain_name=f"{appname}-{region}.{appdomain}",
            validation=acm.CertificateValidation.from_dns(self.hz)
        )
        clicert = acm.Certificate.from_certificate_arn(
            self,
            f"{construct_id}:client-certificate",
            clicerarn
        )
        # Log Group for CVPN Logs
        self.cvpnloggroup = log.LogGroup(
            self,
            f"{construct_id}:cvpnlogsGroup",
            retention=log.RetentionDays.ONE_WEEK
        )
        # Log Stream for CVPN Logs
        self.cvpnlogstream = log.LogStream(
            self,
            f"{construct_id}:cvpnlogsStream",
            log_group=self.cvpnloggroup
        )
        self.cvpn = ec2.CfnClientVpnEndpoint(
            self,
            f"{construct_id}:cvpn",
            description='Client VPN Endpoint Mutual Authentication',
            authentication_options=[
                {
                    "type": "certificate-authentication",
                    "mutual_authentication": {
                        "client_root_certificate_chain_arn": clicert
                    }
                }
            ],
            client_cidr_block=cvpncidr,
            connection_log_options=ec2.CfnClientVpnEndpoint.ConnectionLogOptionsProperty(
                enabled=True,
                cloudwatch_log_group=self.cvpnloggroup.log_group_name,
                cloudwatch_log_stream=self.cvpnlogstream.log_stream_name
            ),
            server_certificate_arn=self.cert.certificate_arn,
            split_tunnel=True,
            vpc_id=self.vpc.vpc_id,
            dns_servers=[
                '8.8.8.8'
            ],
            security_group_ids=[self.vpc.vpc_default_security_group],
        )
        # Network Target 
        for i, subnet in enumerate(self.vpc.isolated_subnets):
            ec2.CfnClientVpnTargetNetworkAssociation(
                self,
                f"{construct_id}:cvpn-association-{i}",
                client_vpn_endpoint_id=self.cvpn.ref,
                subnet_id=subnet.subnet_id
            )
            # add Routes
            ec2.CfnClientVpnRoute(
                self,
                f"{construct_id}:cvpn-route-{i}",
                client_vpn_endpoint_id=self.cvpn.ref,
                destination_cidr_block="0.0.0.0/0",
                target_vpc_subnet_id=subnet.subnet_id
            )
        # Authotization Rule
        ec2.CfnClientVpnAuthorizationRule(
            self,
            f"{construct_id}:cvpn-auth-rule-Allow-All",
            client_vpn_endpoint_id=self.cvpn.ref,
            target_network_cidr="0.0.0.0/0",
            authorize_all_groups=True,
            description="Allow All"
        )

class cvpnfed(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, vpc = ec2.Vpc, bastionsg = ec2.SecurityGroup, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.vpc = vpc
        self.bastionsg = bastionsg
        # get config for resource
        res = 'cvpn'
        appname = resmap['Mappings']['Resources'][res]['NAME']
        appdomain = resmap['Mappings']['Resources'][res]['DOMAIN']
        idparn = resmap['Mappings']['Resources'][res]['IDPARN']
        cvpncidr = resmap['Mappings']['Resources'][res]['CIDR']
        # get hosted zone id
        self.hz = r53.HostedZone.from_lookup(
            self,
            f"{construct_id}:Domain",
            domain_name=appdomain,
            private_zone=False
        )
        # generate public certificate
        self.cert = acm.Certificate(
            self,
            f"{construct_id}:Certificate",
            domain_name=f"{appname}-{region}.{appdomain}",
            validation=acm.CertificateValidation.from_dns(self.hz)
        )
        # Log Group for CVPN Logs
        self.cvpnloggroup = log.LogGroup(
            self,
            f"{construct_id}:cvpnlogsGroup",
            retention=log.RetentionDays.ONE_WEEK
        )
        # Log Stream for CVPN Logs
        self.cvpnlogstream = log.LogStream(
            self,
            f"{construct_id}:cvpnlogsStream",
            log_group=self.cvpnloggroup
        )
        self.cvpn = ec2.CfnClientVpnEndpoint(
            self,
            f"{construct_id}:cvpn",
            description='Client VPN Endpoint Federate Authentication',
            authentication_options=[
                {
                    "type": "federated-authentication",
                    "federatedAuthentication": {
                        "samlProviderArn": idparn
                    }
                }
            ],
            client_cidr_block=cvpncidr,
            connection_log_options=ec2.CfnClientVpnEndpoint.ConnectionLogOptionsProperty(
                enabled=True,
                cloudwatch_log_group=self.cvpnloggroup.log_group_name,
                cloudwatch_log_stream=self.cvpnlogstream.log_stream_name
            ),
            server_certificate_arn=self.cert.certificate_arn,
            split_tunnel=True,
            vpc_id=self.vpc.vpc_id,
            dns_servers=[
                '8.8.8.8'
            ],
            security_group_ids=[self.vpc.vpc_default_security_group],
        )
        # Network Target 
        for i, subnet in enumerate(self.vpc.isolated_subnets):
            net_assoc = ec2.CfnClientVpnTargetNetworkAssociation(
                self,
                f"{construct_id}:cvpn-association-{i}",
                client_vpn_endpoint_id=self.cvpn.ref,
                subnet_id=subnet.subnet_id
            )
            # add Routes
            ec2.CfnClientVpnRoute(
                self,
                f"{construct_id}:cvpn-route-{i}",
                client_vpn_endpoint_id=self.cvpn.ref,
                destination_cidr_block="0.0.0.0/0",
                target_vpc_subnet_id=subnet.subnet_id
            ).add_depends_on(net_assoc)
        # Authotization Rule
        ec2.CfnClientVpnAuthorizationRule(
            self,
            f"{construct_id}:cvpn-auth-rule-Allow-All",
            client_vpn_endpoint_id=self.cvpn.ref,
            target_network_cidr="0.0.0.0/0",
            authorize_all_groups=True,
            description="Allow All"
        )

