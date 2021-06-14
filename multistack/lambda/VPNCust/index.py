import os
import boto3
import json
import logging
import traceback
import requests
import time
logger = logging.getLogger()
logger.setLevel(logging.INFO)
region = os.environ['AWS_REGION']
ec2 = boto3.client('ec2', region_name=region)

def check_num(s):
  try:
    int(s)
    return True
  except:
    return False


def describe_vpn_connections(vpnid):
    try:
        response = ec2.describe_vpn_connections(
            VpnConnectionIds=[vpnid]
        )
        logger.info('EC2: Describing VPN Connection: {}'.format(vpnid))
        return response
    except Exception as e:
        logger.info('EC2: Describing VPN Connection Error: {}'.format(e))

def delete_vpn_connection(vpnid):
    try:
        response = ec2.delete_vpn_connection(
            VpnConnectionId=vpnid
        )
        logger.info('EC2: VPN Connection Deleted: {}'.format(vpnid))
        return response
    except Exception as e:
        logger.info('EC2: VPN Connection Delete Error: {}'.format(e))

def create_vpn_connection(keylist):
    try:
        response = ec2.create_vpn_connection(**keylist)
        vpnid = response["VpnConnection"]["VpnConnectionId"]
        logger.info('EC2: VPN Connection Created: {}'.format(vpnid))
        return response
    except Exception as e:
        logger.info('EC2: VPN Connection Creation Error: {}'.format(e))

def lambda_handler(event, context):
    logger.info('event: {}'.format(event))
    logger.info('context: {}'.format(context))
    cgwid = event['ResourceProperties']['0']['Customer-Gateway-Id']
    gwtype = event['ResourceProperties']['0']['Gateway-Type']
    gwid = event['ResourceProperties']['0']['Gateway-Id']
    tunnelopt = event['ResourceProperties']['0']['VPNOptions']['TunnelOptions']
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
            # get vpn configuration
            delete_vpn_connection(phyresId)
            response["Status"] = "SUCCESS"
            response["Reason"] = ("VPN Config deletion succeed!")
        elif event['RequestType'] == 'Create':
            tid = 0
            for tunnelid in tunnelopt:
                for k,v in tunnelid.items():        
                    if isinstance(v,list):
                        itid = 0
                        for item in v:
                            if isinstance(item,dict):
                                for k1,v1 in item.items():
                                    if check_num(v1) == True:
                                        tunnelopt[tid][k][itid][k1] = int(v1)
                                    if v1 == 'false' or v1 == 'False':
                                        tunnelopt[tid][k][itid][k1] = False
                                    if v1 == 'true' or v1 == 'True':
                                        tunnelopt[tid][k][itid][k1] = True
                            elif isinstance(v,list):
                                it1id = 0
                                for item1 in v:
                                    if isinstance(item1,dict):
                                        for k2,v2 in item1.items():
                                            if check_num(v2) == True:
                                                tunnelopt[tid][k][itid][k1][it1id][k2] = int(v2)
                                            if v2 == 'false' or v2 == 'False':
                                                tunnelopt[tid][k][itid][k1][it1id][k2] = False
                                            if v2 == 'true' or v2 == 'True':
                                                tunnelopt[tid][k][itid][k1][it1id][k2] = True
                                    it1id = it1id + 1
                            itid = itid + 1
                    elif isinstance(v,dict):
                        logger.info("Debug: {0}".format(v))
                        for k1,v1 in item.items():
                            if check_num(v1) == True:
                                tunnelopt[tid][k][k1] = int(v1)
                            if v1 == 'false' or v1 == 'False':
                                tunnelopt[tid][k][k1] = False
                            if v1 == 'true' or v1 == 'True':
                                tunnelopt[tid][k][k1] = True
                    else:
                        if check_num(v) == True:
                            v = int(v)
                            tunnelopt[tid][k] = int(v)
                        if v == 'false' or v == 'False':
                            tunnelopt[tid][k] = False
                        if v == 'true' or v == 'True':
                            tunnelopt[tid][k] = True
                tid = tid + 1
            vpnopts = event['ResourceProperties']['0']['VPNOptions']
            for k,v in vpnopts.items():        
                if v == 'false' or v == 'False':
                    vpnopts[k] = False
                if v == 'true' or v == 'True':
                    vpnopts[k] = True
            if gwtype == 'vgw':
                keylist = {}
                keylist['CustomerGatewayId'] = {}
                keylist['CustomerGatewayId'] = cgwid
                keylist['Type'] = {}
                keylist['Type'] = 'ipsec.1'
                keylist['VpnGatewayId'] = {}
                keylist['VpnGatewayId'] = gwid
                keylist['Options'] = {}
                keylist['Options'] = vpnopts
            elif gwtype == 'tgw':
                keylist = {}
                keylist['CustomerGatewayId'] = {}
                keylist['CustomerGatewayId'] = cgwid
                keylist['Type'] = {}
                keylist['Type'] = 'ipsec.1'
                keylist['TransitGatewayId'] = {}
                keylist['TransitGatewayId'] = gwid
                keylist['Options'] = {}
                keylist['Options'] = vpnopts
            vpn = create_vpn_connection(keylist)
            phyresId = vpn["VpnConnection"]["VpnConnectionId"]
            state = vpn["VpnConnection"]["State"]
            response["Status"] = "SUCCESS"
            response["Reason"] = ("VPN Connection Created!")
            response["PhysicalResourceId"] = phyresId
            response["Data"] = { "VPNid" : phyresId }
            while state == "pending":
                logger.info("Waiting 30 seconds for VPN State be ready")
                time.sleep(30)
                vpn = describe_vpn_connections(phyresId)
                state = vpn["VpnConnections"][0]["State"]
        else:
            phyresId = event['PhysicalResourceId']
            response["Status"] = "SUCCESS"
            response["Reason"] = ("Nothing to do now!")
            response["PhysicalResourceId"] = phyresId
            response["Data"] = { "VPNid" : phyresId }
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
        requests.put(event['ResponseURL'],data=response_data,headers=headers)
        logger.info('CloudFormation returned status code: {}'.format(response["Status"]))
        logger.info('CloudFormation returned Reason: {}'.format(response["Reason"]))
    except Exception as e:
        logger.info('send(..) failed executing requests.put(..): {}'.format(e))
        raise
    return response
