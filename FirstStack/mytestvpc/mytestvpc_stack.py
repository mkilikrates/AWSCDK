import os
import json
import base64
import logging
from aws_cdk import (
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_autoscaling as asg,
    aws_elasticloadbalancingv2 as elb,
    aws_logs as log,
    aws_cloudwatch as cw,
    core
)
logger = logging.getLogger(__name__)
vcpcidr = "10.0.0.0/16"
vpcname = "Myvpcpythontest"
account=os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"])
region = os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])
tagName = core.CfnTag(key="Name", value=vpcname)
vpcenv = "production"
tagEnv = core.CfnTag(key="environment", value=vpcenv)

class MytestvpcStack(core.Stack):

    def __init__(self, scope: core.Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # from https://github.com/aws/aws-cdk/issues/894
        myvpc = ec2.Vpc(self,
            vpcname,
            cidr=vcpcidr,
            max_azs=3,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    subnet_type=ec2.SubnetType.PUBLIC,
                    name="Public",
                    cidr_mask=24
                ), 
                ec2.SubnetConfiguration(
                    subnet_type=ec2.SubnetType.PRIVATE,
                    name="Private",
                    cidr_mask=24
                ), 
                ec2.SubnetConfiguration(
                    subnet_type=ec2.SubnetType.ISOLATED,
                    name="Intercon",
                    cidr_mask=24
                )
            ]
        )
        core.CfnOutput(
            self,
            "vpc-id",
            value=myvpc.vpc_id
        )
         # IPv6 is currently not supported by CDK.
        # This is done manually now, based on:
        # https://gist.github.com/milesjordan/d86942718f8d4dc20f9f331913e7367a
        ipv6_block = ec2.CfnVPCCidrBlock(self, "Ipv6",
            vpc_id=myvpc.vpc_id,
            amazon_provided_ipv6_cidr_block=True
        )
        core.CfnOutput(
            self,
            "vpc-Cidrv6",
            value=core.Fn.select(
                0,
                myvpc.vpc_ipv6_cidr_blocks
            )
        )
        # We need to sniff out the InternetGateway the VPC is using, as we
        # need to assign this for IPv6 routing too.
        for child in myvpc.node.children:
            if isinstance(child, ec2.CfnInternetGateway):
                internet_gateway = child
                break
        else:
            raise Exception("Couldn't find the InternetGateway of the VPC")
        egressonlygateway = ec2.CfnEgressOnlyInternetGateway(
            self,
            "EgressOnlyInternetGateway",
            vpc_id=myvpc.vpc_id
        )
        #set counter to iterate with Fn.cidr select
        i = 0
        for index, subnet in enumerate(myvpc.public_subnets):
            subnet.add_route("DefaultIpv6Route",
                router_id=internet_gateway.ref,
                router_type=ec2.RouterType.GATEWAY,
                destination_ipv6_cidr_block="::/0",
            )
            # This is of course not the best way to do this, but it seems CDK
            # currently allows no other way to set the IPv6 CIDR on subnets.
            assert isinstance(subnet.node.children[0], ec2.CfnSubnet)
            # As IPv6 are allocated on provisioning, we need to use "Fn::Cidr"
            # to get a subnet out of it.
            subnet.node.children[0].ipv6_cidr_block = core.Fn.select(
                index,
                core.Fn.cidr(
                    core.Fn.select(
                        0,
                        myvpc.vpc_ipv6_cidr_blocks
                    ),
                    len(myvpc.public_subnets),
                    "64"
                )
            )
            # Not work because CFN not allow assign both public IP and ipv6 together
            #subnet.node.children[0].assign_ipv6_address_on_creation=True
            # Make sure the dependencies are correct, otherwise we might be
            # creating a subnet before IPv6 is added.
            subnet.node.add_dependency(ipv6_block)
            i = i + 1
        # Running again now for private subnets
        for index, subnet in enumerate(myvpc.private_subnets):
            subnet.add_route("DefaultIpv6Route",
                router_id=egressonlygateway.ref,
                router_type=ec2.RouterType.EGRESS_ONLY_INTERNET_GATEWAY,
                destination_ipv6_cidr_block="::/0",
            )
            assert isinstance(subnet.node.children[0], ec2.CfnSubnet)
            subnet.node.children[0].ipv6_cidr_block = core.Fn.select(
                i,
                core.Fn.cidr(
                    core.Fn.select(
                        0,
                        myvpc.vpc_ipv6_cidr_blocks
                    ),
                    len(myvpc.private_subnets) + len(myvpc.public_subnets),
                    "64"
                )
            )
            subnet.node.add_dependency(ipv6_block)
            i = i + 1
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
        myvpcflowlog = ec2.CfnFlowLog(
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
        # get prefix list from file to allow traffic from the office
        with open('zonemap.cfg') as zonefile:
            zonemap = json.load(zonefile)
            srcprefix = zonemap['Mappings']['RegionMap'][region]['PREFIXLIST']
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
            "BastionEgressAllIpv6",
            ip_protocol="-1",
            cidr_ipv6="::/0",
            group_id=bastionsg.security_group_id
        )
        ec2.CfnSecurityGroupEgress(
            self,
            "BastionEgressAllIpv4",
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
        # set variables to be used
        mykey = "Fedorawrkst-" + region
        usrdatafile = 'bastion'
        usrdata = open(usrdatafile + ".cfg", "r").read()
        # create bastion host instance
        bastion = ec2.BastionHostLinux(
            self,
            'MybastionLinux',
            vpc=myvpc,
            security_group=bastionsg,
            subnet_selection=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
            instance_type=ec2.InstanceType('t3.micro'),
            machine_image=ec2.AmazonLinuxImage(
                user_data=ec2.UserData.custom(usrdata),
                edition=ec2.AmazonLinuxEdition.STANDARD,
                generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2,
            )
        )
        #https://pypi.org/project/aws-cdk.aws-iam/
        # add manageged policy
        bastion.instance.role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name("AdministratorAccess"))
        # add my key
        bastion.instance.instance.add_property_override("KeyName", mykey)
        # enable ipv6 on this bastion
        bastion.instance.instance.add_property_override("Ipv6AddressCount", 1)
        core.CfnOutput(
            self,
            "Instance-ipv4",
            value=bastion.__getattribute__("instance_public_ip")
        )
        # set variables to be used on Auto Scale Group
        mykey = "mauranjo-" + region
        usrdatafile = 'simple_nginx'
        usrdata = open(usrdatafile + ".cfg", "r").read()
        # create security group for AutoScaleGroup
        asgsg = ec2.SecurityGroup(
            self,
            'MyASGSG',
            allow_all_outbound=True,
            vpc=myvpc
        )
        # dependency to get IPV6 allow
        asgsg.node.add_dependency(ipv6_block)
        # add egress rule
        ec2.CfnSecurityGroupEgress(
            self,
            "ASGEgressAllIpv6",
            ip_protocol="-1",
            cidr_ipv6="::/0",
            group_id=asgsg.security_group_id
        )
        ec2.CfnSecurityGroupEgress(
            self,
            "ASGEgressAllIpv4",
            ip_protocol="-1",
            cidr_ip="0.0.0.0/0",
            group_id=asgsg.security_group_id
        )
        # add ingress rule
        asgsg.add_ingress_rule(
            bastionsg,
            ec2.Port.all_traffic()
        )
        # create Auto Scalling Group
        myasg = asg.AutoScalingGroup(
            self,
            "MyASG",
            instance_type=ec2.InstanceType('t3.micro'),
            machine_image=ec2.AmazonLinuxImage(
                user_data=ec2.UserData.custom(usrdata),
                edition=ec2.AmazonLinuxEdition.STANDARD,
                generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2
            ),
            vpc=myvpc,
            security_group=asgsg,
            key_name=mykey,
            desired_capacity=2,
            min_capacity=0,
            max_capacity=2,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE)
        )
        myasg.scale_on_schedule(
            "PrescaleInTheMorning",
            schedule=asg.Schedule.cron(hour="9", minute="0"),
            desired_capacity=2
        )
        myasg.scale_on_schedule(
            "AllowDownscalingAtNight",
            schedule=asg.Schedule.cron(hour="20", minute="0"),
            desired_capacity=0
        )
        #create alb
        myalb = elb.ApplicationLoadBalancer(
            self,
            "myALB",
            vpc=myvpc,
            internet_facing=True,
            ip_address_type=elb.IpAddressType("DUAL_STACK"),
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
            #security_group=bastionsg
        )
        core.CfnOutput(
            self,
            "ALB DNS",
            value=myalb.load_balancer_dns_name
        )
        # create listener
        mylistnr = myalb.add_listener(
            "Listener_http",
            port=80,
            protocol=elb.ApplicationProtocol.HTTP,
        )
        # define asg
        mylistnr.connections.allow_from(
            myalb,
            ec2.Port.tcp(80)
        )
        mylistnr.connections.allow_default_port_from(
            other=ec2.Peer.any_ipv6(),
            description="Allow from anyone on port 80"
        )
        # associate listener to asg
        mylistnr.add_targets(
            "MyFleet from myasg",
            port=80,
            targets=[myasg]
        )
        

