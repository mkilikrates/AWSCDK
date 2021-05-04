import os
import boto3
import json
import time
import logging
import traceback
import requests
logger = logging.getLogger()
logger.setLevel(logging.INFO)
region = os.environ['AWS_REGION']
client_ec2 = boto3.client('ec2', region_name=region)

def lambda_handler(event, context):
    logger.info('event: {}'.format(event))
    logger.info('context: {}'.format(context))
    vpc_id = event['ResourceProperties']['0']['vpc-id']
    azname = event['ResourceProperties']['0']['availability-zone']
    subnetname = event['ResourceProperties']['0']['subnet-name']
    requestId = event['RequestId']
    stacktId = event['StackId']
    logresId = event['LogicalResourceId']
    response = {
        "Status": "SUCCESS",
        "RequestId": requestId,
        "StackId": stacktId,
        "LogicalResourceId": logresId,
        "Reason": "Nothing to do",
        "Data": {}
    }
    try:
        if event['RequestType'] == 'Delete':
            phyresId = event['PhysicalResourceId']
            action = client_ec2.describe_subnets(
                Filters=[
                    {
                        'Name': 'vpc-id',
                        'Values': [
                            vpc_id
                        ]
                    },
                    {
                        'Name': 'availabilityZone',
                        'Values': [
                            azname
                        ]
                    },
                    {
                        'Name': 'tag:aws-cdk:subnet-name',
                        'Values': [
                            subnetname
                        ]
                    }
                ]
            )
            subnetid = action['Subnets'][0]['SubnetId']
            action = client_ec2.describe_route_tables(
                Filters=[
                    {
                        'Name': 'association.subnet-id',
                        'Values': [
                            subnetid
                        ]
                    }
                ]
            )
            rtid = action['RouteTables'][0]['RouteTableId']
            response["Status"] = "SUCCESS"
            response["Reason"] = ("Route Table Id found!")
            response["PhysicalResourceId"] = phyresId
            response["Data"] = { "SubnetId" : subnetid, "RouteTableId" : rtid }
            logger.info('Action: Nothing to do here! - {}'.format(event['RequestType']))
        elif event['RequestType'] == 'Create':
            action = client_ec2.describe_subnets(
                Filters=[
                    {
                        'Name': 'vpc-id',
                        'Values': [
                            vpc_id
                        ]
                    },
                    {
                        'Name': 'availabilityZone',
                        'Values': [
                            azname
                        ]
                    },
                    {
                        'Name': 'tag:aws-cdk:subnet-name',
                        'Values': [
                            subnetname
                        ]
                    }
                ]
            )
            subnetid = action['Subnets'][0]['SubnetId']
            action = client_ec2.describe_route_tables(
                Filters=[
                    {
                        'Name': 'association.subnet-id',
                        'Values': [
                            subnetid
                        ]
                    }
                ]
            )
            rtid = action['RouteTables'][0]['RouteTableId']
            response["Status"] = "SUCCESS"
            response["PhysicalResourceId"] = rtid
            response["Reason"] = ("Route Table Id found!")
            response["Data"] = { "SubnetId" : subnetid, "RouteTableId" : rtid }
        else:
            phyresId = event['PhysicalResourceId']
            action = client_ec2.describe_subnets(
                Filters=[
                    {
                        'Name': 'vpc-id',
                        'Values': [
                            vpc_id
                        ]
                    },
                    {
                        'Name': 'availabilityZone',
                        'Values': [
                            azname
                        ]
                    },
                    {
                        'Name': 'tag:aws-cdk:subnet-name',
                        'Values': [
                            subnetname
                        ]
                    }
                ]
            )
            subnetid = action['Subnets'][0]['SubnetId']
            action = client_ec2.describe_route_tables(
                Filters=[
                    {
                        'Name': 'association.subnet-id',
                        'Values': [
                            subnetid
                        ]
                    }
                ]
            )
            rtid = action['RouteTables'][0]['RouteTableId']
            response["Status"] = "SUCCESS"
            response["Reason"] = ("Route Table Id found!")
            response["PhysicalResourceId"] = phyresId
            response["Data"] = { "SubnetId" : subnetid, "RouteTableId" : rtid }
    except Exception as e:
        response = {}
        logger.error('ERROR: {}'.format(e))
        traceback.print_exc()
        response["Status"] = "FAILED"
        response["Reason"] = str(e)
    logger.info('Sending Response')
    logger.info('response: {}'.format(response))
    response_data = json.dumps(response)
    headers = {
        'content-type': '',
        'content-length': str(len(response_data))
    }
    try:
        action = requests.put(event['ResponseURL'],data=response_data,headers=headers)
        logger.info('CloudFormation returned status code: {}'.format(response["Status"]))
        logger.info('CloudFormation returned Reason: {}'.format(response["Reason"]))
    except Exception as e:
        logger.info('send(..) failed executing requests.put(..): {}'.format(e))
        raise
    return response