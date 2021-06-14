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
    vpnid = event['ResourceProperties']['VPN']
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
            response["Status"] = "SUCCESS"
            response["Reason"] = ("Nothing to do here!")
            response["PhysicalResourceId"] = phyresId
            response["Data"] = { "vpnid" : vpnid, "tgwattachid" : phyresId }
            logger.info('Action: Nothing to do here! - {}'.format(event['RequestType']))
        elif event['RequestType'] == 'Create':
            action = client_ec2.describe_transit_gateway_attachments(
                Filters=[
                    {
                        'Name': 'resource-id',
                        'Values': [
                            vpnid
                        ]
                    }
                ]
            )
            response["Data"]['VPN'] = vpnid
            phyresId = action['TransitGatewayAttachments'][0]['TransitGatewayAttachmentId']
            response["Data"]['TransitGatewayAttachmentId'] = phyresId
            if 'Association' in action['TransitGatewayAttachments'][0]:
                if 'TransitGatewayRouteTableId' in action['TransitGatewayAttachments'][0]['Association']:
                    tgwrt=action['TransitGatewayAttachments'][0]['Association']['TransitGatewayRouteTableId']
                    response["Data"]['TransitGatewayRouteTableId'] = tgwrt
                else:
                    response["Data"]['TransitGatewayRouteTableId'] = "Not Found"
            else:
                response["Data"]['TransitGatewayRouteTableId'] = "Not Found"
            response["Status"] = "SUCCESS"
            response["PhysicalResourceId"] = phyresId
            response["Reason"] = ("Transit Gateway Attachment Id found!")
        else:
            phyresId = event['PhysicalResourceId']
            action = client_ec2.describe_transit_gateway_attachments(
                Filters=[
                    {
                        'Name': 'resource-id',
                        'Values': [
                            vpnid
                        ]
                    }
                ]
            )
            response["Data"]['VPN'] = vpnid
            phyresId = action['TransitGatewayAttachments'][0]['TransitGatewayAttachmentId']
            response["Data"]['TransitGatewayAttachmentId'] = phyresId
            if 'Association' in action['TransitGatewayAttachments'][0]:
                if 'TransitGatewayRouteTableId' in action['TransitGatewayAttachments'][0]['Association']:
                    tgwrt=action['TransitGatewayAttachments'][0]['Association']['TransitGatewayRouteTableId']
                    response["Data"]['TransitGatewayRouteTableId'] = tgwrt
                else:
                    response["Data"]['TransitGatewayRouteTableId'] = "Not Found"
            else:
                response["Data"]['TransitGatewayRouteTableId'] = "Not Found"
            response["Status"] = "SUCCESS"
            response["PhysicalResourceId"] = phyresId
            response["Reason"] = ("Transit Gateway Attachment Id found!")
    except Exception as e:
        response = {}
        logger.error('ERROR: {}'.format(e))
        if action != '':
            logger.error('API ERROR: {}'.format(action))
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