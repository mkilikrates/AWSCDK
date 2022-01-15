import os
import json
from aws_cdk import (
    aws_ec2 as ec2,
    aws_ram as ram,
    aws_lambda as lambda_,
    aws_lambda_python as lpython,
    aws_iam as iam,
    aws_logs as log,
    aws_cloudformation as cfn,
    core,
)
account = os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"])
region = os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])
partition = core.Aws.PARTITION

with open('zonemap.cfg') as zonefile:
    zonemap = json.load(zonefile)

class mygw(core.Stack):
    def __init__(self, scope: core.Construct, construct_id: str, gwtype, route, res, ipstack, tgwstack = core.Stack, vpc = ec2.Vpc, vpcname = str, bastionsg = ec2.SecurityGroup, gwid = ec2.CfnTransitGateway, cross = bool, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # get imported objects
        self.vpc = vpc
        self.bastionsg = bastionsg
        self.route = route
        if self.route == 'bgp':
            # get prefix list from file to allow traffic from the office
            vgasn = zonemap['Mappings']['RegionMap'][region]['ASN']
        if self.route == 'static':
            vgasn = 64512
        if gwtype == 'tgw':
            resconf = "resourcesmap.cfg"
            with open(resconf) as resfile:
                resmap = json.load(resfile)
            # get data for resource sharing
            resname = resmap['Mappings']['Resources'][res]['NAME']
            resallowext = resmap['Mappings']['Resources'][res]['EXTERN']
            resaccept = resmap['Mappings']['Resources'][res]['AUTOACCEPT']
            resdefrt = resmap['Mappings']['Resources'][res]['DEFRT']
            resdefrtass = resmap['Mappings']['Resources'][res]['DEFRTASS']
            resmcast = resmap['Mappings']['Resources'][res]['MCAST']
            if tgwstack != '':
                gwid = tgwstack.gwId.import_value
            if gwid =='':
                # create transit gateway
                self.gw = ec2.CfnTransitGateway(
                    self,
                    id=f"tgw-{region}",
                    amazon_side_asn=vgasn,
                    auto_accept_shared_attachments=resaccept,
                    default_route_table_association=resdefrt,
                    default_route_table_propagation=resdefrtass,
                    multicast_support=resmcast,
                    tags=[
                        core.CfnTag(
                            key='Name',
                            value=f"tgw-{region}"
                        )
                    ]
                )
                gw = self.gw.ref
                self.gwId = core.CfnOutput(
                    self,
                    "gwId",
                    value=self.gw.ref,
                    export_name=f"{construct_id}:gwId"
                )
                self.gwArn = core.CfnOutput(
                    self,
                    "gwArn",
                    value=f"arn:{partition}:ec2:{region}:{account}:transit-gateway/{gw}",
                    export_name=f"{construct_id}:gwArn"
                )
                # share ram
                if 'Principals' in resmap['Mappings']['Resources'][res]:
                    resprinc = resmap['Mappings']['Resources'][res]['Principals']
                    arnlist = f"arn:{core.Aws.PARTITION}:ec2:{core.Aws.REGION}:{core.Aws.ACCOUNT_ID}:transit-gateway/{gw}"
                    self.ram = ram.CfnResourceShare(
                        self,
                        f"{construct_id}-ram",
                        name=resname,
                        allow_external_principals=resallowext,
                        principals=resprinc,
                        resource_arns=[arnlist]
                    )
                # create tgw route tables if needed
                if 'RT' in resmap['Mappings']['Resources'][res]:
                    for routetable in resmap['Mappings']['Resources'][res]['RT']:
                        rtname = routetable['Name']
                        self.mytgwrt = ec2.CfnTransitGatewayRouteTable(
                            self,
                            f"{construct_id}-tgwrt-{rtname}",
                            transit_gateway_id=gw,
                            tags=[
                                core.CfnTag(
                                    key='Name',
                                    value=f"tgwrt{rtname}"
                                )
                            ]
                        )
                        self.rt = core.CfnOutput(
                            self,
                            f"tgwrt{rtname}out",
                            value=self.mytgwrt.ref,
                            export_name=f"{self.stack_name}:tgwrt{rtname}out"
                        )
                        self.mytgwrt.override_logical_id(new_logical_id=(f"tgwrt{rtname}"))
                        self.rt.override_logical_id(new_logical_id=f"tgwrt{rtname}out")
                        
            else:
                gw = gwid
            # attach transit gateway to vpc
            self.gwattch = ec2.CfnTransitGatewayAttachment(
                self,
                id=f"tgw-vpc-{region}-attachment",
                transit_gateway_id=gw,
                vpc_id=self.vpc.vpc_id,
                subnet_ids=self.vpc.select_subnets(subnet_group_name='Endpoints',one_per_az=True).subnet_ids,
                tags=[
                    core.CfnTag(
                        key='Name',
                        value=f"tgw-{self.vpc.vpc_id}-attachment"
                    )
                ]
            )
            if 'APPLMODE' in resmap['Mappings']['Resources'][res]:
                    for vpc in resmap['Mappings']['Resources'][res]['APPLMODE']:
                        if vpc == vpcname:
                            # create Police for lambda function
                            self.mylambdapolicy = iam.PolicyStatement(
                                actions=[
                                    "ec2:ModifyTransitGatewayVpcAttachment",
                                    "ec2:DescribeTransitGatewayVpcAttachments",
                                    "logs:CreateLogGroup",
                                    "logs:CreateLogStream",
                                    "logs:DescribeLogGroups",
                                    "logs:DescribeLogStreams",
                                    "logs:PutLogEvents"
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
                                    'Role for Lambda to manage Transit Gateway Attachment as Custom Resources in CloudFormation'
                                )
                            )
                            self.mylambdarole.add_to_principal_policy(statement=self.mylambdapolicy)
                            # Create Lambda Function
                            self.mylambda = lpython.PythonFunction(
                                self,
                                f"{construct_id}:Lambda",
                                handler="lambda_handler",
                                timeout=core.Duration.seconds(90),
                                runtime=lambda_.Runtime.PYTHON_3_8,
                                description="Lambda to manage Transit Gateway Attachment as Custom Resources in CloudFormation",
                                entry="lambda/ModifyTGWAttach/",
                                role=(self.mylambdarole),
                                log_retention=log.RetentionDays.ONE_WEEK
                            )
                            self.mycustomresource = cfn.CfnCustomResource(
                                self,
                                f"{construct_id}:ModifyTransitGatewayVpcAttachment",
                                service_token=self.mylambda.function_arn,
                            )
                            self.mycustomresource.add_depends_on(self.gwattch)
                            self.mycustomresource.add_property_override("TgwInspectionVpcAttachmentId", self.gwattch.ref)

            if cross == False:
                # add tgw route tables
                if 'RT' in resmap['Mappings']['Resources'][res]:
                    for routetable in resmap['Mappings']['Resources'][res]['RT']:
                        rtname = routetable['Name']
                        if 'TGRT' in routetable:
                            rttgrt = routetable['TGRT']
                            if rttgrt == vpcname:
                                if 'Routes' in routetable:
                                    index = 0
                                    for rt in routetable['Routes']:
                                        myrt = ec2.CfnTransitGatewayRoute(
                                            self,
                                            f"tgw-{region}-tgwrt-{rtname}-{index}",
                                            destination_cidr_block=rt,
                                            transit_gateway_attachment_id=self.gwattch.ref,
                                            transit_gateway_route_table_id=(f"tgwrt{rtname}")
                                        )
                                        if tgwstack != '':
                                            myrt.add_property_override("TransitGatewayRouteTableId", { "Fn::ImportValue" : f"{tgwstack.stack_name}:tgwrt{rtname}out" })
                                        else:
                                            myrt.add_property_override("TransitGatewayRouteTableId", {"Ref" : f"tgwrt{rtname}"})
                                        index = index + 1
                        # VPC Propagation CIDR to TGW Route Table
                        if 'PROPAG' in routetable:
                            index = 0
                            for rtpropag in routetable['PROPAG']:
                                if rtpropag == vpcname:
                                    myrtpropag = ec2.CfnTransitGatewayRouteTablePropagation(
                                        self,
                                        f"tgwrt-prop-{rtname}-vpc-{vpcname}-{index}",
                                        transit_gateway_attachment_id=self.gwattch.ref,
                                        transit_gateway_route_table_id=(f"tgwrt{rtname}")
                                    )
                                    if tgwstack != '':
                                        myrtpropag.add_property_override("TransitGatewayRouteTableId", { "Fn::ImportValue" : f"{tgwstack.stack_name}:tgwrt{rtname}out" })
                                    else:
                                        myrtpropag.add_property_override("TransitGatewayRouteTableId", {"Ref" : f"tgwrt{rtname}"})
                        # VPC Association with TGW Route Table
                        if 'ASSOC' in routetable:
                            for rtassoc in routetable['ASSOC']:
                                if rtassoc == vpcname:
                                    myrtass = ec2.CfnTransitGatewayRouteTableAssociation(
                                        self,
                                        id=f"tgwrt-ass-{rtname}-vpc-{vpcname}",
                                        transit_gateway_attachment_id=self.gwattch.ref,
                                        transit_gateway_route_table_id=(f"tgwrt{rtname}")
                                    )
                                    if tgwstack != '':
                                        myrtass.add_property_override("TransitGatewayRouteTableId", { "Fn::ImportValue" : f"{tgwstack.stack_name}:tgwrt{rtname}out" })
                                    else:
                                        myrtass.add_property_override("TransitGatewayRouteTableId", {"Ref" : f"tgwrt{rtname}"})
            # add routes to tgw in vpc
            for subtype in resmap['Mappings']['Resources'][vpcname]['SUBNETS']:
                for each in subtype:
                    for sub in subtype[each]:
                        index = 0
                        if each == 'PRIVATE':
                            subnetlist = self.vpc.private_subnets
                        elif each == 'PUBLIC':
                            subnetlist = self.vpc.public_subnets
                        elif each == 'ISOLATED':
                            subnetlist = self.vpc.isolated_subnets
                        if 'TGWRT' in sub:
                            idx = 0
                            for rt in sub['TGWRT']:
                                idx2 = 0
                                for subnet in subnetlist:
                                    ec2.CfnRoute(
                                        self,
                                        id=f"vpc-rt-{each}-{subnet.availability_zone}-{index}-{idx}-{idx2}",
                                        route_table_id=subnet.route_table.route_table_id,
                                        destination_cidr_block=rt,
                                        transit_gateway_id=gw
                                    ).add_depends_on(self.gwattch)
                                    idx2 = idx2 + 1
                                idx = idx + 1
                            index = index + 1
        if gwtype == 'vgw':
            self.gw = gwid
            # create Virtual private gateway
            self.gw = ec2.VpnGateway(
                self,
                f"{construct_id}:vgw",
                type='ipsec.1',
                amazon_side_asn=vgasn,
            )
            self.gwId = core.CfnOutput(
                self,
                "gwId",
                value=self.gw.gateway_id,
                export_name=f"{construct_id}:gwId"
            )
            # attach VGW to VPC
            self.gwattch = ec2.CfnVPCGatewayAttachment(
                self,
                f"{construct_id}:vgw-att",
                vpc_id=self.vpc.vpc_id,
                vpn_gateway_id=self.gw.gateway_id
            )
            for subnet in self.vpc.public_subnets:
                ec2.CfnVPNGatewayRoutePropagation(
                    self,
                    f"vpc-rtpub-{subnet.availability_zone}-cwgpropag",
                    route_table_ids=[subnet.route_table.route_table_id],
                    vpn_gateway_id=self.gw.gateway_id
                ).add_depends_on(self.gwattch)
            for subnet in self.vpc.private_subnets:
                ec2.CfnVPNGatewayRoutePropagation(
                    self,
                    f"vpc-rtpriv-{subnet.availability_zone}-cwgpropag",
                    route_table_ids=[subnet.route_table.route_table_id],
                    vpn_gateway_id=self.gw.gateway_id
                ).add_depends_on(self.gwattch)
            for subnet in self.vpc.isolated_subnets:
                ec2.CfnVPNGatewayRoutePropagation(
                    self,
                    f"vpc-rtisol-{subnet.availability_zone}-cwgpropag",
                    route_table_ids=[subnet.route_table.route_table_id],
                    vpn_gateway_id=self.gw.gateway_id
                ).add_depends_on(self.gwattch)


