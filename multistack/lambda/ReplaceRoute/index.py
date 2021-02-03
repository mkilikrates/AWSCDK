import os
import boto3
import json
import time
import logging
import traceback
import requests
region = os.environ['AWS_REGION']
logger = logging.getLogger()
logger.setLevel(logging.INFO)
ec2 = boto3.client('ec2', region_name=region)

def lambda_handler(event, context):
    logger.info('event: {}'.format(event))
    logger.info('context: {}'.format(context))
    rtid = event['ResourceProperties']['0']['RouteTable']
    cidr = event['ResourceProperties']['0']['CarrierGatewayId']
    cidr = event['ResourceProperties']['0']['DestinationCidrBlock']
    cidr = event['ResourceProperties']['0']['DestinationIpv6CidrBlock']
    cidr = event['ResourceProperties']['0']['DestinationPrefixListId']
    cidr = event['ResourceProperties']['0']['EgressOnlyInternetGatewayId']
    cidr = event['ResourceProperties']['0']['GatewayId']
    cidr = event['ResourceProperties']['0']['InstanceId']
    cidr = event['ResourceProperties']['0']['LocalGatewayId']
    cidr = event['ResourceProperties']['0']['LocalTarget']
    cidr = event['ResourceProperties']['0']['NatGatewayId']
    cidr = event['ResourceProperties']['0']['NetworkInterfaceId']
    cidr = event['ResourceProperties']['0']['NetworkInterfaceId']
    cidr = event['ResourceProperties']['0']['NetworkInterfaceId']
    requestId = event['RequestId']
    stacktId = event['StackId']
    logresId = event['LogicalResourceId']
    response = {
        "Status": "SUCCESS",
        "RequestId": requestId,
        "StackId": stacktId,
        "LogicalResourceId": logresId,
        "PhysicalResourceId" : "None",
        "Reason": "Nothing to do",
        "Data": {}
    }
    try:
        if event['RequestType'] == 'Delete':
            phyresId = event['PhysicalResourceId']
            action = client_ec2.release_address(
                AllocationId=phyresId
            )
            response["Status"] = "SUCCESS"
            response["Reason"] = ("IP deallocation succeed!")
        elif event['RequestType'] == 'Create':
            client_ec2 = boto3.client('ec2', region_name=allocregion)
            action = client_ec2.allocate_address(
                Domain='vpc'
            )
            phyresId = action['AllocationId']
            eip = action["PublicIp"]
            response["Status"] = "SUCCESS"
            response["Reason"] = ("IP allocation succeed!")
            response["PhysicalResourceId"] = phyresId
            response["Data"] = { "PublicIp" : eip, "AllocationId" : phyresId, "Region" : allocregion }
        else:
            phyresId = event['PhysicalResourceId']
            client_ec2 = boto3.client('ec2', region_name=allocregion)
            action = client_ec2.describe_addresses(
                AllocationIds=[
                    phyresId
                ]
            )
            phyresId = action['AllocationId']
            eip = action["PublicIp"]
            response["Status"] = "SUCCESS"
            response["Reason"] = ("IP allocation succeed! Nothing to do here!")
            response["PhysicalResourceId"] = phyresId
            response["Data"] = { "PublicIp" : eip }
            logger.info('Action: Nothing to do here! - {}'.format(event['RequestType']))
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
