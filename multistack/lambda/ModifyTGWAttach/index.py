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

def lambda_handler(event, context):
    logger.info('event: {}'.format(event))
    logger.info('context: {}'.format(context))
    tgwattach = event['ResourceProperties']['0']['TgwInspectionVpcAttachmentId']
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
            client_ec2 = boto3.client('ec2', region_name=region)
            action = client_ec2.modify_transit_gateway_vpc_attachment(
                TransitGatewayAttachmentId=tgwattach,
                Options={
                    'ApplianceModeSupport': 'disable'
                }
            )
            response["Status"] = "SUCCESS"
            response["Reason"] = ("Appliance Mode disable!")
            response["PhysicalResourceId"] = phyresId
            response["Data"] = { "TransitGatewayVpcAttachmentId" : tgwattach, "Appliancemode" : 'disable' }
        elif event['RequestType'] == 'Create':
            client_ec2 = boto3.client('ec2', region_name=region)
            action = client_ec2.modify_transit_gateway_vpc_attachment(
                TransitGatewayAttachmentId=tgwattach,
                Options={
                    'ApplianceModeSupport': 'enable'
                }
            )
            response["Status"] = "SUCCESS"
            response["PhysicalResourceId"] = tgwattach
            response["Reason"] = ("Appliance Mode enable!")
            response["Data"] = { "TransitGatewayVpcAttachmentId" : tgwattach, "Appliancemode" : 'enable' }
        else:
            phyresId = event['PhysicalResourceId']
            client_ec2 = boto3.client('ec2', region_name=region)
            action = client_ec2.modify_transit_gateway_vpc_attachment(
                TransitGatewayAttachmentId=tgwattach,
                Options={
                    'ApplianceModeSupport': 'enable'
                }
            )
            response["Status"] = "SUCCESS"
            response["Reason"] = ("Appliance Mode enable!")
            response["PhysicalResourceId"] = phyresId
            response["Data"] = { "TransitGatewayVpcAttachmentId" : tgwattach, "Appliancemode" : 'enable' }
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