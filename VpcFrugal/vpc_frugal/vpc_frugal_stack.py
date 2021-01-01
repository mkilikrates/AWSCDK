import os
import json
from aws_cdk import (
    aws_lambda as lambda_,
    aws_lambda_python as lpython,
    aws_iam as iam,
    aws_events as events,
    aws_events_targets as targets,
    aws_logs as log,
    aws_autoscaling as asg,
    aws_ec2 as ec2,
    core,
)
account = os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"])
region = os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])
vpcconf = "vpcmap.cfg"
resconf = "resourcesmap.cfg"

class VpcFrugalStack(core.Stack):

    def __init__(self, scope: core.Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # The code that defines your stack goes here
        # create Police for lambda function
        mylambdapolicy = iam.PolicyStatement(
            actions=[
                "ec2:DescribeVpcs",
                "ec2:DescribeVpcAttribute",
                "ec2:DescribeInstances",
                "route53:GetHostedZone",
                "route53:ChangeResourceRecordSets",
                "route53:ListHostedZones",
                "route53:AssociateVPCWithHostedZone",
                "route53:DisassociateVPCFromHostedZone",
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:DescribeLogGroups",
                "logs:DescribeLogStreams",
                "logs:PutLogEvents"
            ],
            resources=["*"],
            effect=iam.Effect.ALLOW
        )
        mylambdarole = iam.Role(
            self,
            "LambdaRole",
            assumed_by=iam.ServicePrincipal(
                'lambda.amazonaws.com'
            ),
            description=(
                'Role for Lambda to update resources using Tags'
            )
        )
        mylambdarole.add_to_policy(mylambdapolicy)
        # Create Lambda Function
        mylambda = lpython.PythonFunction(
            self,
            'TagToLambda',
            handler="lambda_handler",
            timeout=core.Duration.seconds(90),
            runtime=lambda_.Runtime.PYTHON_3_8,
            description="Lambda to update resources using Tags",
            entry="lambda/usingtags/",
            role=(mylambdarole),
            log_retention=log.RetentionDays.ONE_WEEK
        )
        # Create Event Rule target Lambda
        myec2rule = events.Rule(
            self,
            "EC2TagsState",
            description="EventRule for EC2 state change",
            event_pattern=events.EventPattern(
                source=["aws.ec2"],
                detail_type=[
                    "EC2 Instance State-change Notification"
                ],
                detail={
                    "state":[
                        "running",
                        "shutting-down",
                        "stopping"
                    ]
                }
            ),
            enabled=True,
            targets=[
                targets.LambdaFunction(
                    handler=mylambda
                )
            ]
        )
        myvpcrule = events.Rule(
            self,
            "EC2TagsChange",
            description="EventRule for VPC Tagging",
            event_pattern=events.EventPattern(
                source=["aws.ec2"],
                detail_type=[
                    "AWS API Call via CloudTrail"
                ],
                detail={
                    "eventName":[
                        "DeleteVpc",
                        "CreateTags"
                    ]
                }
            ),
            enabled=True,
            targets=[
                targets.LambdaFunction(
                    handler=mylambda
                )
            ]
        )
        # get parameters from cfg file
        # get prefix list from file to allow traffic from the office
        with open(vpcconf) as vpcfile:
            vpcmap = json.load(vpcfile)
            vcpcidr = vpcmap['Mappings']['RegionMap'][region]['CIDR']

        # create vpc without nat-gateways
        myvpc = ec2.Vpc(self,
            f"" + region + "-vpc",
            cidr=vcpcidr,
            max_azs=2,
            nat_gateways=0,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    subnet_type=ec2.SubnetType.PUBLIC,
                    name="Public",
                    cidr_mask=24
                ), 
                ec2.SubnetConfiguration(
                    subnet_type=ec2.SubnetType.ISOLATED,
                    name="Private",
                    cidr_mask=24
                )
            ]
        )
        myvpc.node.add_dependency(myec2rule)
        myvpc.node.add_dependency(myvpcrule)
        # Log Group for Flow Logs
        myflowloggroup = log.LogGroup(
            self,
            "FlowLogsGroup",
            retention=log.RetentionDays.ONE_WEEK
        )
        # Policy Document for Flow Logs
        myflowpolicy = iam.PolicyStatement(
            actions=[
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:DescribeLogGroups",
                "logs:DescribeLogStreams",
                "logs:PutLogEvents"
            ],
            effect=iam.Effect.ALLOW,
        )
        # Add all resources to this policy document
        myflowpolicy.add_all_resources()
        # Iam Role
        myflowlogrole = iam.Role(
            self,
            "FlowLogsRole",
            assumed_by=iam.ServicePrincipal('vpc-flow-logs.amazonaws.com'),
            description="Role for Delivery VPC Flow Logs",
        )
        # Attach policy to Iam Role
        myflowlogrole.add_to_policy(myflowpolicy)
        # Create VPC Flow Log for VPC
        ec2.CfnFlowLog(
            self,
            "VpcFlowLogs",
            resource_id=myvpc.vpc_id,
            resource_type='VPC',
            traffic_type='ALL',
            deliver_logs_permission_arn=myflowlogrole.role_arn,
            log_destination_type='cloud-watch-logs',
            log_group_name=myflowloggroup.log_group_name,
            max_aggregation_interval=60,
            log_format=format('${version} ${vpc-id} ${subnet-id} ${instance-id} ${interface-id} ${account-id} ${type} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${pkt-srcaddr} ${pkt-dstaddr} ${protocol} ${bytes} ${packets} ${start} ${end} ${action} ${tcp-flags} ${log-status}'),
        )
                # add S3 Gateway Endpoint to All Route Tables on VPC
        myvpc.add_s3_endpoint(
            'S3Endpoint',
        )
        # create security group for Interface VPC Endpoints
        vpcesg = ec2.SecurityGroup(
            self,
            'MyVPCESG',
            allow_all_outbound=True,
            vpc=myvpc,
        )
        # add egress rule
        ec2.CfnSecurityGroupEgress(
            self,
            "MyVPCEEgressAllIpv4",
            ip_protocol="-1",
            cidr_ip="0.0.0.0/0",
            group_id=vpcesg.security_group_id
        )
        # add ingress rule
        ec2.CfnSecurityGroupIngress(
            self,
            "MyVPCEIngressVPCIpv4",
            ip_protocol="-1",
            cidr_ip=myvpc.vpc_cidr_block,
            group_id=vpcesg.security_group_id
        )
        # add ssm interface Endpoint
        # SSM
        myvpc.add_interface_endpoint(
            'SSMEndpoint',
            service=ec2.InterfaceVpcEndpointAwsService('ssm'),
            subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.ISOLATED),
            lookup_supported_azs=True,
            security_groups=[vpcesg]
        )
        # EC2
        myvpc.add_interface_endpoint(
            'EC2Endpoint',
            service=ec2.InterfaceVpcEndpointAwsService('ec2'),
            subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.ISOLATED),
            lookup_supported_azs=True,
            security_groups=[vpcesg]
        )
        # get prefix list from file to allow traffic from the office
        with open('zonemap.cfg') as zonefile:
            zonemap = json.load(zonefile)
            srcprefix = zonemap['Mappings']['RegionMap'][region]['PREFIXLIST']
            vgasn = int(zonemap['Mappings']['RegionMap'][region]['TGWASN'])
        # create prefix list for RFC1918
        mynet10rfc1918 = ec2.CfnPrefixList.EntryProperty(
            cidr='10.0.0.0/8',
            description='Network 10.0.0.0/8 from RFC1918'
        )
        mynet172rfc1918 = ec2.CfnPrefixList.EntryProperty(
            cidr='172.16.0.0/12',
            description='Network 172.16.0.0/12 from RFC1918'
        )
        mynet192rfc1918 = ec2.CfnPrefixList.EntryProperty(
            cidr='192.168.0.0/16',
            description='Network 192.168.0.0/16 from RFC1918'
        )
        myrfc1918 = ec2.CfnPrefixList(
            self,
            id=f"pl-rfc1918" + region,
            address_family='IPv4',
            max_entries=5,
            prefix_list_name=f"pl-rfc1918" + region,
            entries=[
                mynet10rfc1918,
                mynet172rfc1918,
                mynet192rfc1918
            ]
        )
        # create security group for bastion
        bastionsg = ec2.SecurityGroup(
            self,
            'MyBastionSG',
            allow_all_outbound=True,
            vpc=myvpc,
        )
        # add egress rule
        ec2.CfnSecurityGroupEgress(
            self,
            "MyBastionEgressAllIpv4",
            ip_protocol="-1",
            cidr_ip="0.0.0.0/0",
            group_id=bastionsg.security_group_id
        )
        # add ingress rule
        bastionsg.add_ingress_rule(
            ec2.Peer.prefix_list(srcprefix),
            ec2.Port.all_traffic()
        )
        bastionsg.add_ingress_rule(
            bastionsg,
            ec2.Port.all_traffic()
        )
        ec2.CfnSecurityGroupIngress(
            self,
            "MyBastionIngress10",
            ip_protocol="-1",
            source_prefix_list_id=myrfc1918.ref,
            group_id=bastionsg.security_group_id
        )
        # get data for bastion resource
        with open(resconf) as resfile:
            res = 'bastion'
            resmap = json.load(resfile)
            resname = resmap['Mappings']['Resources'][res]['NAME']
            ressize = resmap['Mappings']['Resources'][res]['SIZE']
            mykey = resmap['Mappings']['Resources'][res]['KEY'] + region
            usrdatafile = resmap['Mappings']['Resources'][res]['USRFILE']
            usrdata = open(usrdatafile, "r").read()
        # create bastion host instance
        bastion = ec2.BastionHostLinux(
            self,
            'MybastionLinux',
            vpc=myvpc,
            security_group=bastionsg,
            subnet_selection=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
            instance_type=ec2.InstanceType(ressize),
            machine_image=ec2.AmazonLinuxImage(
                user_data=ec2.UserData.custom(usrdata),
                edition=ec2.AmazonLinuxEdition.STANDARD,
                generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2,
            ),
            instance_name=resname + region,
        )
        # add my key
        bastion.instance.instance.add_property_override("KeyName", mykey)
        # create transit gateway
        # https://github.com/aws-samples/aws-cdk-transit-gateway-peering/blob/master/stacks/networks.py
        mytgw = ec2.CfnTransitGateway(
            self,
            id=f"TGW-" + region,
            amazon_side_asn=vgasn,
            auto_accept_shared_attachments='enable',
            default_route_table_association='enable',
            default_route_table_propagation='enable',
            multicast_support='enable',
            tags=[
                core.CfnTag(
                    key='Name',
                    value=f"tgw-" + region
                )
            ]
        )
        myvpctgwattach = ec2.CfnTransitGatewayAttachment(
            self,
            id=f"tgw-vpc-" + region + "-attachment",
            transit_gateway_id=mytgw.ref,
            vpc_id=myvpc.vpc_id,
            subnet_ids=[subnet.subnet_id for subnet in myvpc.isolated_subnets],
            tags=[
                core.CfnTag(
                    key='Name',
                    value=f"tgw-" + myvpc.vpc_id + "-attachment"
                )
            ]
        )
        myvpctgwattach.add_depends_on(mytgw)
        # add routes to tgw
        for subnet in myvpc.public_subnets:
            ec2.CfnRoute(
                self,
                id=f"vpc-rtpub-" + subnet.availability_zone + "-ne10-tgw",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='10.0.0.0/8',
                transit_gateway_id=mytgw.ref
            ).add_depends_on(myvpctgwattach)
        for subnet in myvpc.public_subnets:
            ec2.CfnRoute(
                self,
                id=f"vpc-rtpub-" + subnet.availability_zone + "-ne172-tgw",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='172.16.0.0/12',
                transit_gateway_id=mytgw.ref
            ).add_depends_on(myvpctgwattach)
        for subnet in myvpc.public_subnets:
            ec2.CfnRoute(
                self,
                id=f"vpc-rtpub-" + subnet.availability_zone + "-ne192-tgw",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='192.168.0.0/16',
                transit_gateway_id=mytgw.ref
            ).add_depends_on(myvpctgwattach)
        for subnet in myvpc.isolated_subnets:
            ec2.CfnRoute(
                self,
                id=f"vpc-rtisol-" + subnet.availability_zone + "-ne10-tgw",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='10.0.0.0/8',
                transit_gateway_id=mytgw.ref
            ).add_depends_on(myvpctgwattach)
        for subnet in myvpc.isolated_subnets:
            ec2.CfnRoute(
                self,
                id=f"vpc-rtisol-" + subnet.availability_zone + "-ne172-tgw",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='172.16.0.0/12',
                transit_gateway_id=mytgw.ref
            ).add_depends_on(myvpctgwattach)
        for subnet in myvpc.isolated_subnets:
            ec2.CfnRoute(
                self,
                id=f"vpc-rtisol-" + subnet.availability_zone + "-ne192-tgw",
                route_table_id=subnet.route_table.route_table_id,
                destination_cidr_block='192.168.0.0/16',
                transit_gateway_id=mytgw.ref
            ).add_depends_on(myvpctgwattach)

