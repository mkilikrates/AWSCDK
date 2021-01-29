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

class cvpn(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, auth, vpc = ec2.Vpc, bastionsg = ec2.SecurityGroup, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.vpc = vpc
        self.bastionsg = bastionsg
        self.auth = auth
        # get config for resource
        res = 'cvpn'
        appname = resmap['Mappings']['Resources'][res]['NAME']
        appdomain = resmap['Mappings']['Resources'][res]['DOMAIN']
        if self.auth == 'mutual':
            clicerarn = resmap['Mappings']['Resources'][res]['CLICERT']
        cvpncidr = resmap['Mappings']['Resources'][res]['CIDR']
        if self.auth == 'federated':
            idparn = resmap['Mappings']['Resources'][res]['IDPARN']
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
        self.authopt = []
        for authopt in self.authopt:
            if authopt == 'mutual':
                self.authopt.append(
                    ec2.CfnClientVpnEndpointProps.authentication_options(
                        {
                            "type": "certificate-authentication",
                            "mutual_authentication": {
                                "client_root_certificate_chain_arn": clicert
                            }
                        }
                    )
                )
                clicert = acm.Certificate.from_certificate_arn(
                    self,
                    f"{construct_id}:client-certificate",
                    clicerarn
                )
            if authopt == 'federated':
                self.authopt.append(
                    ec2.CfnClientVpnEndpointProps.authentication_options(
                        {
                            "type": "federated-authentication",
                            "federatedAuthentication": {
                                "samlProviderArn": idparn
                            }
                        }
                    )
                )
        self.cvpn = ec2.CfnClientVpnEndpoint(
            self,
            f"{construct_id}:cvpn",
            description='Client VPN Endpoint Mutual Authentication',
                authentication_options=self.authopt,
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
class s2svpn(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, gwtype, route, gwid, cgwaddr, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.cgwaddr = cgwaddr.get_att_string("PublicIp")
        self.gwid = gwid
        if route == 'bgp':
            self.route = False
        if route == 'bgp':
            self.route = True
        self.cgw = ec2.CfnCustomerGateway(
            self,
            f"{construct_id}:mycgw",
            bgp_asn=65000,
            ip_address=self.cgwaddr,
            type=('ipsec.1')
        )
        core.CfnOutput(
            self,
            f"{construct_id}:Outmycgw",
            value=self.cgw.ref,
            export_name=f"{construct_id}:mycgw",
        )
        if gwtype == 'vgw':
            self.vpn = ec2.CfnVPNConnection(
                self,
                f"{construct_id}:vpn",
                customer_gateway_id=self.cgw.ref,
                type=('ipsec.1'),
                static_routes_only=self.route,
                vpn_gateway_id=self.gwid.gateway_id
            )
        if gwtype == 'tgw':
            self.vpn = ec2.CfnVPNConnection(
                self,
                f"{construct_id}:vpn",
                customer_gateway_id=self.cgw.ref,
                type=('ipsec.1'),
                static_routes_only=self.route,
                transit_gateway_id=self.gwid.ref
            )
        core.CfnOutput(
            self,
            f"{construct_id}:myvpn",
            value=self.vpn.ref,
            export_name=f"{construct_id}:myvpn",
        )

