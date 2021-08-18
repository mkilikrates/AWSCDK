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
    aws_lambda as lambda_,
    aws_lambda_python as lpython,
    aws_ssm as ssm,
    core,
)
account = os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"])
region = os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])
resconf = "resourcesmap.cfg"
with open(resconf) as resfile:
    resmap = json.load(resfile)


class cvpn(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, auth, res, dirid = str, vpc = ec2.Vpc, bastionsg = ec2.SecurityGroup, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.vpc = vpc
        self.bastionsg = bastionsg
        self.auth = auth
        # get config for resource
        appname = resmap['Mappings']['Resources'][res]['NAME']
        appdomain = resmap['Mappings']['Resources'][res]['DOMAIN']
        cvpncidr = resmap['Mappings']['Resources'][res]['CIDR']
        ressubgrp = resmap['Mappings']['Resources'][res]['SUBNETGRP']
        if 'DNS' in resmap['Mappings']['Resources'][res]:
            resdns = resmap['Mappings']['Resources'][res]['DNS']
        else:
            resdns = None
        if 'SPLIT' in resmap['Mappings']['Resources'][res]:
            ressplit = resmap['Mappings']['Resources'][res]['SPLIT']
        else:
            ressplit = False
        if 'Portal' in resmap['Mappings']['Resources'][res]:
            resportal = resmap['Mappings']['Resources'][res]['Portal']
        else:
            resportal = 'disabled'
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
        for authopt in self.auth:
            if authopt == 'mutual':
                clicerarn = resmap['Mappings']['Resources'][res]['CLICERT']
                self.authopt.append(
                    {
                        "mutualAuthentication": {
                            "clientRootCertificateChainArn": clicerarn
                        },
                        "type": "certificate-authentication",
                    }
                )
            if authopt == 'federated':
                idparn = resmap['Mappings']['Resources'][res]['IDPARN']
                self.authopt.append(
                    {
                        "type": "federated-authentication",
                        "federatedAuthentication": {
                            "samlProviderArn": idparn
                        }
                    }
                )
            if authopt == 'active_directory' and dirid !='':
                self.authopt.append(
                    {
                        "type": "directory-service-authentication",
                        "activeDirectory": {
                            "directoryId": dirid
                        }
                    }
                )

        self.cvpn = ec2.CfnClientVpnEndpoint(
            self,
            f"{construct_id}:cvpn",
            description='Client VPN Endpoint',
            authentication_options=self.authopt,
            client_cidr_block=cvpncidr,
            connection_log_options=ec2.CfnClientVpnEndpoint.ConnectionLogOptionsProperty(
                enabled=True,
                cloudwatch_log_group=self.cvpnloggroup.log_group_name,
                cloudwatch_log_stream=self.cvpnlogstream.log_stream_name
            ),
            server_certificate_arn=self.cert.certificate_arn,
            client_connect_options=None,
            dns_servers=resdns,
            security_group_ids=[self.vpc.vpc_default_security_group],
            self_service_portal=resportal,
            split_tunnel=ressplit,
            vpc_id=self.vpc.vpc_id,
        )
        # Network Target 
        for i, subnet in enumerate(self.vpc.select_subnets(subnet_group_name=ressubgrp, one_per_az=True).subnet_ids):
            myassociation = ec2.CfnClientVpnTargetNetworkAssociation(
                self,
                f"{construct_id}:cvpn-association-{i}",
                client_vpn_endpoint_id=self.cvpn.ref,
                subnet_id=subnet
            )
            # add Routes
            if 'Routes' in resmap['Mappings']['Resources'][res]:
                index = 0 
                for route in resmap['Mappings']['Resources'][res]['Routes']:
                    ec2.CfnClientVpnRoute(
                        self,
                        f"{construct_id}:cvpn-route-{index}{i}",
                        client_vpn_endpoint_id=self.cvpn.ref,
                        destination_cidr_block=route,
                        target_vpc_subnet_id=subnet
                    ).add_depends_on(myassociation)
                    myassociation.override_logical_id(f"association{index}{i}")
                    index = index + 1
        # Authotization Rule
        if 'Authorization' in resmap['Mappings']['Resources'][res]:
            index = 0 
            for auth in resmap['Mappings']['Resources'][res]['Authorization']:
                if 'Group' in auth:
                    allgroup = False
                    cvpngroup = auth['Group']
                else:
                    allgroup = True
                    cvpngroup = None
                for prefix in auth['Prefix']:
                    ec2.CfnClientVpnAuthorizationRule(
                        self,
                        f"{construct_id}:cvpn-auth-rule-Allow-{index}",
                        client_vpn_endpoint_id=self.cvpn.ref,
                        target_network_cidr=prefix,
                        authorize_all_groups=allgroup,
                        description=f"Allow {prefix}{cvpngroup}"
                    ).override_logical_id(f"cvpnauthrule{index}")
                    index = index + 1
class s2svpn(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, res, funct, gwtype, gwid, tgwrt, tgwprop, tgwrtfunct, cgwaddr, route, ipfamily, staticrt = list, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.cgwaddr = cgwaddr.get_att_string("PublicIp")
        ipfamily = ipfamily
        self.gwid = gwid
        tgwvpnattach = ''
        res = res
        if route == 'bgp':
            self.route = False
        if route == 'static':
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
        if res == '':
            if gwtype == 'vgw':
                self.vpn = ec2.CfnVPNConnection(
                    self,
                    f"{construct_id}:vpn",
                    customer_gateway_id=self.cgw.ref,
                    type=('ipsec.1'),
                    static_routes_only=self.route,
                    vpn_gateway_id=self.gwid.gateway_id
                )
                if route == 'static':
                    for rt in staticrt:
                        ec2.CfnVPNConnectionRoute(
                            self,
                            f"{construct_id}:staticrt",
                            destination_cidr_block=rt,
                            vpn_connection_id=self.vpn.ref
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
                if tgwrtfunct =='':
                    # create Police for lambda function
                    self.tgwvpnattachlambdapolicy = iam.PolicyStatement(
                        actions=[
                            "ec2:DescribeTransitGatewayAttachments",
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:DescribeLogGroups",
                            "logs:DescribeLogStreams",
                            "logs:PutLogEvents"
                        ],
                        resources=["*"],
                        effect=iam.Effect.ALLOW
                    )
                    self.tgwvpnattachlambdarole = iam.Role(
                        self,
                        "tgwvpnattachLambdaRole",
                        assumed_by=iam.ServicePrincipal(
                            'lambda.amazonaws.com'
                        ),
                        description=(
                            'Role for Lambda to describe tgw attachment for vpn as Custom Resources in CloudFormation'
                        )
                    )
                    self.tgwvpnattachlambdarole.add_to_policy(self.tgwvpnattachlambdapolicy)
                    # Create Lambda Function
                    self.tgwvpnattachlambda = lpython.PythonFunction(
                        self,
                        f"{construct_id}:tgwvpnattachlambda",
                        handler="lambda_handler",
                        timeout=core.Duration.seconds(90),
                        runtime=lambda_.Runtime.PYTHON_3_8,
                        description="Lambda to describe tgw attachment for vpn as Custom Resources in CloudFormation",
                        entry="lambda/GetVpnTgwAttach/",
                        role=(self.tgwvpnattachlambdarole),
                        log_retention=log.RetentionDays.ONE_WEEK
                    )
                    core.CfnOutput(
                    self,
                    f"{construct_id}:tgwvpnattachlambdaArn",
                    value=self.tgwvpnattachlambda.function_arn,
                    export_name=f"{construct_id}:tgwvpnattachlambdaArn"
                    )
                    tgwrtfunct = self.tgwvpnattachlambda.function_arn
                self.tgwvpnattach = core.CfnCustomResource(
                    self,
                    f"{construct_id}:tgwvpnattach",
                    service_token=tgwrtfunct
                )
                self.tgwvpnattach.add_depends_on(self.vpn)
                self.tgwvpnattach.add_property_override("VPN", self.vpn.ref)
                if tgwrt !='':
                    ec2.CfnTransitGatewayRouteTableAssociation(
                        self,
                        id=f"tgwrt-assvpn-{self.vpn.ref}",
                        transit_gateway_attachment_id=self.tgwvpnattach.get_att("TransitGatewayAttachmentId").to_string(),
                        transit_gateway_route_table_id=tgwrt
                    )
                elif self.tgwvpnattach.get_att("TransitGatewayRouteTableId").to_string() != "Not Found":
                    tgwrt = self.tgwvpnattach.get_att("TransitGatewayRouteTableId").to_string()
                if tgwprop !='':
                    ec2.CfnTransitGatewayRouteTablePropagation(
                        self,
                        id=f"tgwrt-propvpn-{self.vpn.ref}",
                        transit_gateway_attachment_id=self.tgwvpnattach.get_att("TransitGatewayAttachmentId").to_string(),
                        transit_gateway_route_table_id=tgwprop
                    )
                if route == 'static':
                    for rt in staticrt:
                        ec2.CfnTransitGatewayRoute(
                            self,
                            f"tgw-{region}-tgwrt-vpn-{self.vpn.ref}",
                            destination_cidr_block=rt,
                            transit_gateway_attachment_id=self.tgwvpnattach.get_att("TransitGatewayAttachmentId").to_string(),
                            transit_gateway_route_table_id=tgwrt
                        )
            self.vpnid = core.CfnOutput(
                self,
                f"{construct_id}:VPNid",
                value=self.vpn.ref,
                export_name=f"{construct_id}:VPNid",
            )
            ssm.StringParameter(
                self,
                "SSMVPNid",
                type=ssm.ParameterType("STRING"),
                parameter_name=f"/{region}/vpn/{self.stack_name}",
                description="VPNid",
                string_value=self.vpn.ref
            )
            ssm.StringParameter(
                self,
                "SSMCGWIP",
                type=ssm.ParameterType("STRING"),
                parameter_name=f"/{region}/vpn/{self.stack_name}/CGWIP",
                description="CGWIP",
                string_value=cgwaddr.get_att_string("PublicIp")
            )
            ssm.StringParameter(
                self,
                "SSMEIPAllocid",
                type=ssm.ParameterType("STRING"),
                parameter_name=f"/{region}/vpn/{self.stack_name}/EIPAllocid",
                description="EIPAllocid",
                string_value=cgwaddr.get_att_string("AllocationId")
            )
        else:
            # Get configuration
            myvpnopts = {}
            vpnaccel = resmap['Mappings']['Resources'][res]['EnableAcceleration']
            myvpnopts['TunnelOptions'] = []
            myvpnopts['EnableAcceleration'] = {}
            myvpnopts['EnableAcceleration'] = vpnaccel
            myvpnopts['StaticRoutesOnly'] = {}
            if route == "bgp":
                myvpnopts['StaticRoutesOnly'] = False
            else:
                myvpnopts['StaticRoutesOnly'] = True
            if ipfamily == 'ipv6':
                vpnipfamily = 'ipv6'
                myvpnopts['LocalIpv6NetworkCidr'] = {}
                myvpnopts['RemoteIpv6NetworkCidr'] = {}
                if resmap['Mappings']['Resources'][res]['LocalIpv6NetworkCidr']:
                    myvpnopts['LocalIpv6NetworkCidr'] = resmap['Mappings']['Resources'][res]['LocalIpv6NetworkCidr']
                else:
                    myvpnopts['LocalIpv6NetworkCidr'] = '::/0'
                if resmap['Mappings']['Resources'][res]['RemoteIpv6NetworkCidr']:
                    myvpnopts['RemoteIpv6NetworkCidr'] = resmap['Mappings']['Resources'][res]['RemoteIpv6NetworkCidr']
                else:
                    myvpnopts['RemoteIpv6NetworkCidr'] = '::/0'
            else:
                vpnipfamily = 'ipv4'
                if gwtype == 'tgw':
                    myvpnopts['LocalIpv4NetworkCidr'] = {}
                    myvpnopts['RemoteIpv4NetworkCidr'] = {}
                    if 'LocalIpv4NetworkCidr' in resmap['Mappings']['Resources'][res]:
                        myvpnopts['LocalIpv4NetworkCidr'] = resmap['Mappings']['Resources'][res]['LocalIpv4NetworkCidr']
                    else:
                        myvpnopts['LocalIpv4NetworkCidr'] = '0.0.0.0/0'
                    if 'RemoteIpv4NetworkCidr' in resmap['Mappings']['Resources'][res]:
                        myvpnopts['RemoteIpv4NetworkCidr'] = resmap['Mappings']['Resources'][res]['RemoteIpv4NetworkCidr']
                    else:
                        myvpnopts['RemoteIpv4NetworkCidr'] = '0.0.0.0/0'
            if gwtype == 'tgw':
                myvpnopts['TunnelInsideIpVersion'] = {}
                myvpnopts['TunnelInsideIpVersion'] = vpnipfamily
            myvpnopts['TunnelOptions'] = []
            for i in range (2):
                myvpnopts['TunnelOptions'].append({})
                if 'TunnelInsideCidr' in resmap['Mappings']['Resources'][res]['Tunnels'][i] and vpnipfamily == 'ipv4':
                    myvpnopts['TunnelOptions'][i]['TunnelInsideCidr'] = {}
                    myvpnopts['TunnelOptions'][i]['TunnelInsideCidr'] = resmap['Mappings']['Resources'][res]['Tunnels'][i]['TunnelInsideCidr']
                if 'TunnelInsideIpv6Cidr' in resmap['Mappings']['Resources'][res]['Tunnels'][i] and vpnipfamily == 'ipv6':
                    myvpnopts['TunnelOptions'][i]['TunnelInsideIpv6Cidr'] = {}
                    myvpnopts['TunnelOptions'][i]['TunnelInsideIpv6Cidr'] = resmap['Mappings']['Resources'][res]['Tunnels'][i]['TunnelInsideIpv6Cidr']
                if 'PreSharedKey' in resmap['Mappings']['Resources'][res]['Tunnels'][i]:
                    myvpnopts['TunnelOptions'][i]['PreSharedKey'] = {}
                    myvpnopts['TunnelOptions'][i]['PreSharedKey'] = resmap['Mappings']['Resources'][res]['Tunnels'][i]['PreSharedKey']
                if 'Phase1LifetimeSeconds' in resmap['Mappings']['Resources'][res]['Tunnels'][i]:
                    myvpnopts['TunnelOptions'][i]['Phase1LifetimeSeconds'] = {}
                    myvpnopts['TunnelOptions'][i]['Phase1LifetimeSeconds'] = resmap['Mappings']['Resources'][res]['Tunnels'][i]['Phase1LifetimeSeconds']
                if 'Phase2LifetimeSeconds' in resmap['Mappings']['Resources'][res]['Tunnels'][i]:
                    myvpnopts['TunnelOptions'][i]['Phase2LifetimeSeconds'] = {}
                    myvpnopts['TunnelOptions'][i]['Phase2LifetimeSeconds'] = resmap['Mappings']['Resources'][res]['Tunnels'][i]['Phase2LifetimeSeconds']
                if 'RekeyMarginTimeSeconds' in resmap['Mappings']['Resources'][res]['Tunnels'][i]:
                    myvpnopts['TunnelOptions'][i]['RekeyMarginTimeSeconds'] = {}
                    myvpnopts['TunnelOptions'][i]['RekeyMarginTimeSeconds'] = resmap['Mappings']['Resources'][res]['Tunnels'][i]['RekeyMarginTimeSeconds']
                if 'RekeyFuzzPercentage' in resmap['Mappings']['Resources'][res]['Tunnels'][i]:
                    myvpnopts['TunnelOptions'][i]['RekeyFuzzPercentage'] = {}
                    myvpnopts['TunnelOptions'][i]['RekeyFuzzPercentage'] = resmap['Mappings']['Resources'][res]['Tunnels'][i]['RekeyFuzzPercentage']
                if 'ReplayWindowSize' in resmap['Mappings']['Resources'][res]['Tunnels'][i]:
                    myvpnopts['TunnelOptions'][i]['ReplayWindowSize'] = {}
                    myvpnopts['TunnelOptions'][i]['ReplayWindowSize'] = resmap['Mappings']['Resources'][res]['Tunnels'][i]['ReplayWindowSize']
                if 'DPDTimeoutSeconds' in resmap['Mappings']['Resources'][res]['Tunnels'][i]:
                    myvpnopts['TunnelOptions'][i]['DPDTimeoutSeconds'] = {}
                    myvpnopts['TunnelOptions'][i]['DPDTimeoutSeconds'] = resmap['Mappings']['Resources'][res]['Tunnels'][i]['DPDTimeoutSeconds']
                if 'DPDTimeoutAction' in resmap['Mappings']['Resources'][res]['Tunnels'][i]:
                    myvpnopts['TunnelOptions'][i]['DPDTimeoutAction'] = {}
                    myvpnopts['TunnelOptions'][i]['DPDTimeoutAction'] = resmap['Mappings']['Resources'][res]['Tunnels'][i]['DPDTimeoutAction']
                if 'Phase1EncryptionAlgorithms' in resmap['Mappings']['Resources'][res]['Tunnels'][i]:
                    myvpnopts['TunnelOptions'][i]['Phase1EncryptionAlgorithms'] = []
                    myvpnopts['TunnelOptions'][i]['Phase1EncryptionAlgorithms'] = resmap['Mappings']['Resources'][res]['Tunnels'][i]['Phase1EncryptionAlgorithms']
                if 'Phase1IntegrityAlgorithms' in resmap['Mappings']['Resources'][res]['Tunnels'][i]:
                    myvpnopts['TunnelOptions'][i]['Phase1IntegrityAlgorithms'] = []
                    myvpnopts['TunnelOptions'][i]['Phase1IntegrityAlgorithms'] = resmap['Mappings']['Resources'][res]['Tunnels'][i]['Phase1IntegrityAlgorithms']
                if 'Phase1DHGroupNumbers' in resmap['Mappings']['Resources'][res]['Tunnels'][i]:
                    myvpnopts['TunnelOptions'][i]['Phase1DHGroupNumbers'] = []
                    myvpnopts['TunnelOptions'][i]['Phase1DHGroupNumbers'] = resmap['Mappings']['Resources'][res]['Tunnels'][i]['Phase1DHGroupNumbers']
                if 'Phase2EncryptionAlgorithms' in resmap['Mappings']['Resources'][res]['Tunnels'][i]:
                    myvpnopts['TunnelOptions'][i]['Phase2EncryptionAlgorithms'] = []
                    myvpnopts['TunnelOptions'][i]['Phase2EncryptionAlgorithms'] = resmap['Mappings']['Resources'][res]['Tunnels'][i]['Phase2EncryptionAlgorithms']
                if 'Phase2IntegrityAlgorithms' in resmap['Mappings']['Resources'][res]['Tunnels'][i]:
                    myvpnopts['TunnelOptions'][i]['Phase2IntegrityAlgorithms'] = []
                    myvpnopts['TunnelOptions'][i]['Phase2IntegrityAlgorithms'] = resmap['Mappings']['Resources'][res]['Tunnels'][i]['Phase2IntegrityAlgorithms']
                if 'Phase2DHGroupNumbers' in resmap['Mappings']['Resources'][res]['Tunnels'][i]:
                    myvpnopts['TunnelOptions'][i]['Phase2DHGroupNumbers'] = []
                    myvpnopts['TunnelOptions'][i]['Phase2DHGroupNumbers'] = resmap['Mappings']['Resources'][res]['Tunnels'][i]['Phase2DHGroupNumbers']
                if 'IKEVersions' in resmap['Mappings']['Resources'][res]['Tunnels'][i]:
                    myvpnopts['TunnelOptions'][i]['IKEVersions'] = {}
                    myvpnopts['TunnelOptions'][i]['IKEVersions'] = resmap['Mappings']['Resources'][res]['Tunnels'][i]['IKEVersions']
                if 'StartupAction' in resmap['Mappings']['Resources'][res]['Tunnels'][i]:
                    myvpnopts['TunnelOptions'][i]['StartupAction'] = {}
                    myvpnopts['TunnelOptions'][i]['StartupAction'] = resmap['Mappings']['Resources'][res]['Tunnels'][i]['StartupAction']
            if funct =='':
                # create Police for lambda function
                self.mylambdapolicy = iam.PolicyStatement(
                    actions=[
                        "ec2:DescribeVpnConnections",
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:DescribeLogGroups",
                        "logs:DescribeLogStreams",
                        "logs:PutLogEvents"
                    ],
                    resources=["*"],
                    effect=iam.Effect.ALLOW
                )
                self.mylambdaEC2VPNpolicy = iam.PolicyStatement(
                    actions=[
                        "ec2:ModifyVpnTunnelOptions",
                        "ec2:ModifyVpnConnectionOptions",
                        "ec2:ModifyVpnTunnelCertificate",
                        "ec2:ModifyVpnConnection",
                        "ec2:DeleteVpnConnection",
                        "ec2:DescribeVpnConnection",
                        "ec2:CreateVpnConnection"
                    ],
                    resources=["*"],
                    effect=iam.Effect.ALLOW
                )
                self.mylambdarole = iam.Role(
                    self,
                    "LambdaRole",
                    assumed_by=iam.ServicePrincipal(
                        'lambda.amazonaws.com'
                    ),
                    description=(
                        'Role for Lambda to create or modify vpn as Custom Resources in CloudFormation'
                    )
                )
                self.mylambdarole.add_to_policy(self.mylambdapolicy)
                self.mylambdarole.add_to_policy(self.mylambdaEC2VPNpolicy)
                # Create Lambda Function
                self.mylambda = lpython.PythonFunction(
                    self,
                    f"{construct_id}:Lambda",
                    handler="lambda_handler",
                    timeout=core.Duration.minutes(15),
                    runtime=lambda_.Runtime.PYTHON_3_8,
                    description="Lambda to create or modify vpn as Custom Resources in CloudFormation",
                    entry="lambda/VPNCust/",
                    role=(self.mylambdarole),
                    log_retention=log.RetentionDays.ONE_WEEK
                )
                core.CfnOutput(
                self,
                f"{construct_id}:LambdaArn",
                value=self.mylambda.function_arn,
                export_name=f"{construct_id}:LambdaArn"
                )
                funct = self.mylambda.function_arn
            # custom resource
            customopts = {}
            if gwtype == 'tgw':
                customopts = {
                    "Customer-Gateway-Id" : self.cgw.ref,
                    "Gateway-Id" : self.gwid.ref,
                    "Gateway-Type" : gwtype,
                    "VPNOptions" : myvpnopts
                }
            if gwtype == 'vgw':
                customopts = {
                    "Customer-Gateway-Id" : self.cgw.ref,
                    "Gateway-Id" : self.gwid.gateway_id,
                    "Gateway-Type" : gwtype,
                    "VPNOptions" : myvpnopts
                }
            self.mycustomvpn = core.CustomResource(
                self,
                f"{construct_id}:CustomResource",
                service_token=funct,
                properties=[customopts]
            )
            self.vpnid = core.CfnOutput(
                self,
                f"{construct_id}:VPNid",
                value=self.mycustomvpn.get_att_string("VPNid"),
                export_name=f"{construct_id}:VPNid"
            )
            ssm.StringParameter(
                self,
                "SSMVPNid",
                type=ssm.ParameterType("STRING"),
                parameter_name=f"/{region}/vpn/{self.stack_name}",
                description="VPNid",
                string_value=self.mycustomvpn.get_att_string("VPNid")
            )
            ssm.StringParameter(
                self,
                "SSMCGWIP",
                type=ssm.ParameterType("STRING"),
                parameter_name=f"/{region}/vpn/{self.stack_name}/CGWIP",
                description="CGWIP",
                string_value=cgwaddr.get_att_string("PublicIp")
            )
            ssm.StringParameter(
                self,
                "SSMEIPAllocid",
                type=ssm.ParameterType("STRING"),
                parameter_name=f"/{region}/vpn/{self.stack_name}/EIPAllocid",
                description="EIPAllocid",
                string_value=cgwaddr.get_att_string("AllocationId")
            )

            if gwtype == 'tgw':
                if tgwrtfunct =='':
                    # create Police for lambda function
                    self.tgwvpnattachlambdapolicy = iam.PolicyStatement(
                        actions=[
                            "ec2:DescribeTransitGatewayAttachments",
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:DescribeLogGroups",
                            "logs:DescribeLogStreams",
                            "logs:PutLogEvents"
                        ],
                        resources=["*"],
                        effect=iam.Effect.ALLOW
                    )
                    self.tgwvpnattachlambdarole = iam.Role(
                        self,
                        "tgwvpnattachLambdaRole",
                        assumed_by=iam.ServicePrincipal(
                            'lambda.amazonaws.com'
                        ),
                        description=(
                            'Role for Lambda to describe tgw attachment for vpn as Custom Resources in CloudFormation'
                        )
                    )
                    self.tgwvpnattachlambdarole.add_to_policy(self.tgwvpnattachlambdapolicy)
                    # Create Lambda Function
                    self.tgwvpnattachlambda = lpython.PythonFunction(
                        self,
                        f"{construct_id}:tgwvpnattachlambda",
                        handler="lambda_handler",
                        timeout=core.Duration.seconds(90),
                        runtime=lambda_.Runtime.PYTHON_3_8,
                        description="Lambda to describe tgw attachment for vpn as Custom Resources in CloudFormation",
                        entry="lambda/GetVpnTgwAttach/",
                        role=(self.tgwvpnattachlambdarole),
                        log_retention=log.RetentionDays.ONE_WEEK
                    )
                    core.CfnOutput(
                    self,
                    f"{construct_id}:tgwvpnattachlambdaArn",
                    value=self.tgwvpnattachlambda.function_arn,
                    export_name=f"{construct_id}:tgwvpnattachlambdaArn"
                    )
                    tgwrtfunct = self.tgwvpnattachlambda.function_arn
                self.tgwvpnattach = core.CfnCustomResource(
                    self,
                    f"{construct_id}:tgwvpnattach",
                    service_token=tgwrtfunct
                )
                self.tgwvpnattach.add_property_override("VPN", self.mycustomvpn.get_att_string("VPNid"))
                # associate vpn with route table
                vpnname = resmap['Mappings']['Resources'][res]['NAME']
                if tgwrt !='':
                    ec2.CfnTransitGatewayRouteTableAssociation(
                        self,
                        id=f"tgwrt-assvpn-{vpnname}",
                        transit_gateway_attachment_id=self.tgwvpnattach.get_att("TransitGatewayAttachmentId").to_string(),
                        transit_gateway_route_table_id=tgwrt
                    )
                elif self.tgwvpnattach.get_att("TransitGatewayRouteTableId").to_string() != "Not Found":
                    tgwrt = self.tgwvpnattach.get_att("TransitGatewayRouteTableId").to_string()
                if tgwprop !='':
                    ec2.CfnTransitGatewayRouteTablePropagation(
                        self,
                        id=f"tgwrt-propvpn-{vpnname}",
                        transit_gateway_attachment_id=self.tgwvpnattach.get_att("TransitGatewayAttachmentId").to_string(),
                        transit_gateway_route_table_id=tgwprop
                    )
                if route == 'static':
                    for rt in staticrt:
                        ec2.CfnTransitGatewayRoute(
                            self,
                            f"tgw-{region}-tgwrt-vpn-{self.vpn.ref}",
                            destination_cidr_block=rt,
                            transit_gateway_attachment_id=self.tgwvpnattach.get_att("TransitGatewayAttachmentId").to_string(),
                            transit_gateway_route_table_id=tgwrt
                        )

