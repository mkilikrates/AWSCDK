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
    if logger.level == logging.DEBUG:
        logger.debug('event: {}'.format(event))
        logger.debug('context: {}'.format(context))
    key_name = event['ResourceProperties']['0']['KeyName']
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
            action = client_ec2.delete_key_pair(
                KeyName=key_name
            )
            response["Status"] = "SUCCESS"
            response["Reason"] = ("Keypair removed succeed!")
            response["Data"] = { "KeyContent" : "", "KeyName" : "", "Region" : region }
        elif event['RequestType'] == 'Create':
            action = client_ec2.create_key_pair(
                KeyName=key_name
            )
            phyresId = action['KeyPairId']
            KeyName = action['KeyName']
            KeyMaterial = action['KeyMaterial']
            response["Status"] = "SUCCESS"
            response["Reason"] = ("Keypair creation succeed!")
            response["PhysicalResourceId"] = phyresId
            response["Data"] = { "KeyName" : KeyName, "KeyMaterial" : KeyMaterial, "Region" : region }
        else:
            phyresId = event['PhysicalResourceId']
            action = client_ec2.describe_key_pairs(
                KeyNames=[key_name]
            )
            phyresId = action['KeyPairs'][0]['KeyPairId']
            KeyName = action['KeyPairs'][0]['KeyName']
            KeyMaterial = 'Nothing to do here!'
            response["Status"] = "SUCCESS"
            response["Reason"] = ("Describe Keypair succeed! Nothing to do here!")
            response["PhysicalResourceId"] = phyresId
            response["Data"] = { "KeyName" : KeyName, "KeyMaterial" : KeyMaterial, "Region" : region }
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