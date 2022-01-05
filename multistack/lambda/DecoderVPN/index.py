import os
import sys
import base64
import boto3
import json
import time
import logging
import traceback
import requests
import socket
import struct
import xmltodict
from jinja2 import Template
region = os.environ['AWS_REGION']
logger = logging.getLogger()
logger.setLevel(logging.INFO)
s3 = boto3.client('s3')

def createsecret(keylist,vpnregion):
    try:
        secret = boto3.client('secretsmanager', region_name=vpnregion)
        action = secret.create_secret(**keylist)
        return action
    except Exception as e:
        logger.info('SecretsMgr: Create Secret Error: {}'.format(e))

def putsecret(keylist,vpnregion):
    try:
        secret = boto3.client('secretsmanager', region_name=vpnregion)
        action = secret.put_secret_value(**keylist)
        return action
    except Exception as e:
        logger.info('SecretsMgr: Put Secret Error: {}'.format(e))

def deletesecret(keylist,vpnregion):
    try:
        secret = boto3.client('secretsmanager', region_name=vpnregion)
        action = secret.delete_secret(**keylist)
        return action
    except Exception as e:
        logger.info('SecretsMgr: Delete Secret Error: {}'.format(e))

def putparameter(keylist,vpnregion):
    try:
        ssm = boto3.client('ssm', region_name=vpnregion)
        action = ssm.put_parameter(**keylist)
        return action
    except Exception as e:
        logger.info('SSM STORE: Put Parameter Error: {}'.format(e))

def deleteparameter(keylist,vpnregion):
    try:
        ssm = boto3.client('ssm', region_name=vpnregion)
        action = ssm.delete_parameter(**keylist)
        return action
    except Exception as e:
        logger.info('SSM STORE: Delete Parameter Error: {}'.format(e))

def getparameter(keylist,vpnregion):
    try:
        ssm = boto3.client('ssm', region_name=vpnregion)
        action = ssm.get_parameter(**keylist)
        return action
    except Exception as e:
        logger.info('SSM STORE: Get Parameter Error: {}'.format(e))

def fileupload(mycfgfile, bucketname, myobj):
    try:
        with open(mycfgfile, "rb") as data:
            action = s3.upload_fileobj(data, bucketname, myobj)
            logger.info('S3: Upload object Success: {}'.format(mycfgfile))
            return action
    except Exception as e:
        logger.info('S3: Creation of folder Error: {}'.format(e))

def createfolder(bucketname, folder):
    # create config folder to vpn files
    try:
        action = s3.put_object(Bucket=bucketname, Key=(folder))
        logger.info('S3: Creation of folder Success: {}'.format(folder))
        return action
    except Exception as e:
        logger.info('S3: Creation of folder Error: {}'.format(e))

def deletevpnfolder(bucketname, folder):
    # remove folder and vpn files
    try:
        action = s3.list_objects_v2(Bucket=bucketname, Prefix=folder)
        for obj in action['Contents']:
            # remove content
            if folder != obj['Key']:
                s3.delete_object(Bucket=bucketname, Key=obj['Key'])
                logger.info('S3: Deletion of object Success: {}'.format(obj['Key']))
        #remove folder
        s3.delete_object(Bucket=bucketname, Key=folder)
        logger.info('S3: Deletion of folder Success: {}'.format(folder))
        return action
    except Exception as e:
        logger.info('S3: Deletion of folder Error: {}'.format(e))

def describevpn(vpnid,vpnregion):
    # Get VPN Configuration XML
    try:
        ec2 = boto3.client('ec2', region_name=vpnregion)
        action = ec2.describe_vpn_connections(
            VpnConnectionIds=[
                vpnid,
            ]
        )
        logger.info('EC2: VPN Configuration Received Success: {}'.format(vpnid))
        return action
    except Exception as e:
        logger.info('EC2: VPN Configuration Error: {}'.format(e))

def create_presigned_url(bucketname, myobj, expiration=3600):
    # remove folder and vpn files
    try:
        action = s3.generate_presigned_url(
            'get_object',
            Params={
                'Bucket': bucketname,
                'Key': myobj,
            },
            ExpiresIn=expiration
        )
        logger.info('S3: PreSigned URL creation Success: {}'.format(action))
        return action
    except Exception as e:
        logger.info('S3: PreSigned URL creation Error: {}'.format(e))

def lambda_handler(event, context):
    logger.info('event: {}'.format(event))
    logger.info('context: {}'.format(context))
    vpnregion = event['ResourceProperties']['0']['Region']
    vpnstackname = event['ResourceProperties']['0']['VPN']
    requestId = event['RequestId']
    eventtype = event['RequestType']
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
    startact = ''
    keych = ''
    ike = ''
    esp = ''
    rkfz = ''
    rkmg = ''
    rplw = ''
    dpdact = ''
    if vpnstackname.startswith('vpn-'):
        vpnid = vpnstackname
    else:
        keylist = {}
        keylist['Name'] = f"/vpn/{region}/{vpnstackname}"
        action = getparameter(keylist, vpnregion)
        vpnid = action['Parameter']['Value']
    # get allocation id for CGW
    keylist = {}
    keylist['Name'] = f"/vpn/{region}/{vpnstackname}/EIPAllocid"
    action = getparameter(keylist, vpnregion)
    cgwalloc = action['Parameter']['Value']
    response["Data"]["EIPAllocid"] = cgwalloc
    # write allocation id for CGW
    keylist = {}
    keylist['Name'] = f"/vpn/{vpnregion}/{vpnid}/CGW-Allocid"
    keylist['Description'] = f"CGW Elastic IP Allocation id"
    keylist['Value'] = cgwalloc
    keylist['Type'] = 'String'
    keylist['Overwrite'] = True
    keylist['Tier'] = 'Standard'
    ssmput = putparameter(keylist, region)
    routetype = event['ResourceProperties']['0']['Route']
    if 'S3' in event['ResourceProperties']['0']:
        bucketname = event['ResourceProperties']['0']['S3']
        mys3vpnfolder = f"vpn/{vpnid}/"
        mylocalfolder = '/tmp/'
    if 'ApplianceKind' in event['ResourceProperties']['0']:
        ec2type = event['ResourceProperties']['0']['ApplianceKind']
    else:
        ec2type = ''
    if 'LocalCidr' in event['ResourceProperties']['0']:
        localcidr = event['ResourceProperties']['0']['LocalCidr']
        localnet = []
        localnetmask = []
        if type(localcidr) == list:
            for each in localcidr:
                net, bits = each.split('/')
                hostbits = 32 - int(bits)
                localnet.append(net)
                localnetmask.append(socket.inet_ntoa(struct.pack('!I', (1 << 32) - (1 << hostbits))))
                localnetsize = len(localnet)
        else:
            net, bits = localcidr.split('/')
            hostbits = 32 - int(bits)
            localnet.append(net)
            localnetmask.append(socket.inet_ntoa(struct.pack('!I', (1 << 32) - (1 << hostbits))))
            localnetsize = 1
    else:
        localcidr = ''
        localnet = ''
        localnetmask = ''
        localnetsize = ''
    if 'RemoteCidr' in event['ResourceProperties']['0']:
        remotecidr = event['ResourceProperties']['0']['RemoteCidr']
        remotenet = []
        remotenetmask = []
        if type(remotecidr) == list:
            for each in remotecidr:
                net, bits = each.split('/')
                hostbits = 32 - int(bits)
                remotenet.append(net)
                remotenetmask.append(socket.inet_ntoa(struct.pack('!I', (1 << 32) - (1 << hostbits))))
                remotenetsize = len(remotenet)
        else:
            net, bits = remotecidr.split('/')
            hostbits = 32 - int(bits)
            remotenet.append(net)
            remotenetmask.append(socket.inet_ntoa(struct.pack('!I', (1 << 32) - (1 << hostbits))))
            remotenetsize = 1
    else:
        remotecidr = ''
        remotenet = ''
        remotenetmask = ''
        remotenetsize = ''
    try:
        if eventtype == 'Delete':
            phyresId = event['PhysicalResourceId']
            # get vpn configuration
            if bucketname != '':
                deletevpnfolder(bucketname,mys3vpnfolder)
            keylist = {}
            keylist['SecretId'] = f"/vpn/{vpnregion}/{vpnid}/usr-data"
            keylist['ForceDeleteWithoutRecovery'] = True
            action = deletesecret(keylist, region)
            keylist = {}
            keylist['Name'] = f"/vpn/{vpnregion}/{vpnid}/VGW-1"
            action = deleteparameter(keylist, region)
            keylist = {}
            keylist['Name'] = f"/vpn/{vpnregion}/{vpnid}/VGW-2"
            action = deleteparameter(keylist, region)
            keylist = {}
            keylist['Name'] = f"/vpn/{vpnregion}/{vpnid}/CGW-Allocid"
            action = deleteparameter(keylist, region)
            response["Status"] = "SUCCESS"
            response["Reason"] = ("VPN Config deletion succeed!")
        else:
            # get vpn configuration
            vpn = describevpn(vpnid,vpnregion)
            # create config folder to vpn files
            if bucketname != '':
                createfolder(bucketname,mys3vpnfolder)
            # read template files
            if ec2type == 'strongswan':
                with open('ipsec_conf_fsw.tmpl') as f:
                    ipsec_conf_fsw = f.read()
                templatefsw = Template(ipsec_conf_fsw)
                f.close()
            if ec2type == 'strongswan' or ec2type == 'libreswan':
                with open('ipsec_conf_osw.tmpl') as f:
                    ipsec_conf_osw = f.read()
                templateosw = Template(ipsec_conf_osw)
                f.close()
                with open('bgpd_conf.tmpl') as f:
                    bgpd_conf = f.read()
                templatequa = Template(bgpd_conf)
                f.close()
            if ec2type == 'CSR':
                with open('cisco_asr_conf.tmpl') as f:
                    ipsec_conf_asr = f.read()
                templateasr = Template(ipsec_conf_asr)
                f.close()
            # parse configuration
            myvpnconfig = vpn['VpnConnections'][0]['CustomerGatewayConfiguration']
            myvpnxml = xmltodict.parse(myvpnconfig)
            tunnels = myvpnxml['vpn_connection']['ipsec_tunnel']
            # using custom values not in xml but in json
            if 'Options' in vpn['VpnConnections'][0]:
                if 'LocalIpv4NetworkCidr' in vpn['VpnConnections'][0]['Options']:
                    leftsubnet = vpn['VpnConnections'][0]['Options']['LocalIpv4NetworkCidr']
                else:
                    leftsubnet = ''
                if 'LocalIpv6NetworkCidr' in vpn['VpnConnections'][0]['Options']:
                    leftsubnet = vpn['VpnConnections'][0]['Options']['LocalIpv6NetworkCidr']
                else:
                    leftsubnet = ''
                if 'RemoteIpv4NetworkCidr' in vpn['VpnConnections'][0]['Options']:
                    rightsubnet = vpn['VpnConnections'][0]['Options']['RemoteIpv4NetworkCidr']
                else:
                    rightsubnet = ''
                if 'RemoteIpv6NetworkCidr' in vpn['VpnConnections'][0]['Options']:
                    rightsubnet = vpn['VpnConnections'][0]['Options']['RemoteIpv6NetworkCidr']
                else:
                    rightsubnet = ''
            # set iterator
            tnum = 1
            for index, tun in enumerate(tunnels):
                # get variables
                cgw_out_addr = tun['customer_gateway']['tunnel_outside_address']['ip_address']
                keylist = {}
                keylist['Name'] = f"/vpn/{vpnregion}/{vpnid}/VGW-{tnum}"
                keylist['Description'] = f"VGW-{tnum} Endpoint Address"
                keylist['Value'] = cgw_out_addr
                keylist['Type'] = 'String'
                keylist['Overwrite'] = True
                keylist['Tier'] = 'Standard'
                ssmput = putparameter(keylist, region)
                if 'tunnel_inside_address' in tun['customer_gateway']:
                    cgw_in_addr = tun['customer_gateway']['tunnel_inside_address']['ip_address']
                    cgw_in_mask = tun['customer_gateway']['tunnel_inside_address']['network_mask']
                    cgw_in_cidr = tun['customer_gateway']['tunnel_inside_address']['network_cidr']
                else:
                    cgw_in_addr = ''
                    cgw_in_cidr = ''
                if 'tunnel_inside_ipv6_address' in tun['customer_gateway']:
                    cgw_in_v6addr = tun['customer_gateway']['tunnel_inside_ipv6_address']['ip_address']
                    cgw_in_v6cidr = tun['customer_gateway']['tunnel_inside_ipv6_address']['prefix_length']
                else:
                    cgw_in_v6addr = ''
                    cgw_in_v6cidr = ''
                if 'bgp' in tun['customer_gateway']:
                    cgw_bgp_asn = tun['customer_gateway']['bgp']['asn']
                    cgw_bgp_ht = tun['customer_gateway']['bgp']['hold_time']
                else:
                    cgw_bgp_asn = ''
                    cgw_bgp_ht = ''
                if 'bgp' in tun['vpn_gateway']:
                    vgw_bgp_asn = tun['vpn_gateway']['bgp']['asn']
                    vgw_bgp_ht = tun['vpn_gateway']['bgp']['hold_time']
                else:
                    vgw_bgp_asn = ''
                    vgw_bgp_ht = ''
                vgw_out_addr = tun['vpn_gateway']['tunnel_outside_address']['ip_address']
                if 'tunnel_inside_address' in tun['vpn_gateway']:
                    vgw_in_addr = tun['vpn_gateway']['tunnel_inside_address']['ip_address']
                    vgw_in_cidr = tun['vpn_gateway']['tunnel_inside_address']['network_cidr']
                else:
                    vgw_in_addr = ''
                    vgw_in_cidr = ''
                if 'tunnel_inside_ipv6_address' in tun['vpn_gateway']:
                    vgw_in_v6addr = tun['vpn_gateway']['tunnel_inside_ipv6_address']['ip_address']
                    vgw_in_v6cidr = tun['vpn_gateway']['tunnel_inside_ipv6_address']['prefix_length']
                else:
                    vgw_in_v6addr = ''
                    vgw_in_v6cidr = ''
                ike_authentication_protocol = tun['ike']['authentication_protocol']
                ike_encryption_protocol = ''.join(tun['ike']['encryption_protocol'].split('-')[:2])
                ike_lifetime = tun['ike']['lifetime']
                ike_perfect_forward_secrecy = tun['ike']['perfect_forward_secrecy'][-1]
                ike_mode = tun['ike']['mode']
                ike_pre_shared_key = tun['ike']['pre_shared_key']
                ipsec_protocol = tun['ipsec']['protocol']
                ipsec_authentication_protocol = tun['ipsec']['authentication_protocol']
                ipsec_encryption_protocol = ''.join(tun['ipsec']['encryption_protocol'].split('-')[:2])
                ipsec_lifetime = tun['ipsec']['lifetime']
                ipsec_perfect_forward_secrecy = tun['ipsec']['perfect_forward_secrecy'][-1]
                ipsec_mode = tun['ipsec']['mode']
                ipsec_clear_df_bit = tun['ipsec']['clear_df_bit']
                ipsec_fragmentation_before_encryption = tun['ipsec']['fragmentation_before_encryption']
                ipsec_tcp_mss_adjustment = tun['ipsec']['tcp_mss_adjustment']
                dpd_delay = tun['ipsec']['dead_peer_detection']['interval']
                dpd_retry = tun['ipsec']['dead_peer_detection']['retries']
                # using custom values not in xml but in json
                if 'Options' in vpn['VpnConnections'][0]:
                    if len(vpn['VpnConnections'][0]['Options']['TunnelOptions']) > 0 :
                        if 'Phase1LifetimeSeconds' in vpn['VpnConnections'][0]['Options']['TunnelOptions'][index]:
                            ike_lifetime = vpn['VpnConnections'][0]['Options']['TunnelOptions'][index]['Phase1LifetimeSeconds']
                        if 'Phase2LifetimeSeconds' in vpn['VpnConnections'][0]['Options']['TunnelOptions'][index]:
                            ipsec_lifetime = vpn['VpnConnections'][0]['Options']['TunnelOptions'][index]['Phase2LifetimeSeconds']
                        if 'RekeyMarginTimeSeconds' in vpn['VpnConnections'][0]['Options']['TunnelOptions'][index]:
                            rkmg = vpn['VpnConnections'][0]['Options']['TunnelOptions'][index]['RekeyMarginTimeSeconds']
                        else:
                            rkmg = ''
                        if 'RekeyFuzzPercentage' in vpn['VpnConnections'][0]['Options']['TunnelOptions'][index]:
                            rkfz = vpn['VpnConnections'][0]['Options']['TunnelOptions'][index]['RekeyFuzzPercentage']
                        else:
                            rkfz = ''
                        if 'ReplayWindowSize' in vpn['VpnConnections'][0]['Options']['TunnelOptions'][index]:
                            rplw = vpn['VpnConnections'][0]['Options']['TunnelOptions'][index]['ReplayWindowSize']
                        else:
                            rplw = 1024
                        if 'DpdTimeoutAction' in vpn['VpnConnections'][0]['Options']['TunnelOptions'][index]:
                            dpdact = vpn['VpnConnections'][0]['Options']['TunnelOptions'][index]['DpdTimeoutAction']
                        else:
                            dpdact = ''
                        if 'DpdTimeoutSeconds' in vpn['VpnConnections'][0]['Options']['TunnelOptions'][index]:
                            dpdtimeout = vpn['VpnConnections'][0]['Options']['TunnelOptions'][index]['DpdTimeoutSeconds']
                        else:
                            dpdtimeout = ''
                        if 'IkeVersions' in vpn['VpnConnections'][0]['Options']['TunnelOptions'][index]:
                            keychlst =[]
                            for item in vpn['VpnConnections'][0]['Options']['TunnelOptions'][index]['IkeVersions']:
                                keych = item['Value']
                                ckeych = keych
                                keychlst.append(keych)
                            keych = ",".join(keychlst)
                        if 'Phase1EncryptionAlgorithms' in vpn['VpnConnections'][0]['Options']['TunnelOptions'][index]:
                            ikelst =[]
                            cikeenc = ''
                            cgcm = ''
                            for item in vpn['VpnConnections'][0]['Options']['TunnelOptions'][index]['Phase1EncryptionAlgorithms']:
                                ph1enc = item['Value']
                                if ph1enc == 'AES128':
                                    if ckeych == 'ikev2':
                                        cikeenc = 'aes-cbc-128'
                                    else:
                                        cikeenc = 'aes 128'
                                if ph1enc == 'AES256':
                                    if ckeych == 'ikev2':
                                        cikeenc = 'aes-cbc-256'
                                    else:
                                        cikeenc = 'aes 256'
                                if ph1enc == 'AES128-GCM-16':
                                    cgcm = 1
                                    if ckeych == 'ikev2':
                                        cikeenc = 'aes-gcm-128'
                                    else:
                                        cikeenc = 'aes 128'
                                if ph1enc == 'AES256-GCM-16':
                                    cgcm = 1
                                    if ckeych == 'ikev2':
                                        cikeenc = 'aes 256'
                                    else:
                                        cikeenc = 'aes-gcm-256'
                                ike = (ph1enc.replace("-","")).lower()
                                if 'Phase1IntegrityAlgorithms' in vpn['VpnConnections'][0]['Options']['TunnelOptions'][index]:
                                    cikeint = ''
                                    for item2 in vpn['VpnConnections'][0]['Options']['TunnelOptions'][index]['Phase1IntegrityAlgorithms']:
                                        ph1int = item2['Value']
                                        if ph1int == 'SHA1':
                                            if cikeint == '':
                                                cikeint = 'sha1'
                                            else:
                                                cikeint = f"{cikeint} sha1"
                                        if ph1int == 'SHA2-256':
                                            if cikeint == '':
                                                cikeint = 'sha256'
                                            else:
                                                cikeint = f"{cikeint} sha256"
                                        if ph1int == 'SHA2-384':
                                            if cikeint == '':
                                                cikeint = 'sha384'
                                            else:
                                                cikeint = f"{cikeint} sha384"
                                        if ph1int == 'SHA2-512':
                                            if cikeint == '':
                                                cikeint = 'sha512'
                                            else:
                                                cikeint = f"{cikeint} sha512"
                                        ike = ike + "-" + (ph1int.replace("-","_")).lower()
                                if 'Phase1DHGroupNumbers' in vpn['VpnConnections'][0]['Options']['TunnelOptions'][index]:
                                    cph1dh = ''
                                    for item3 in vpn['VpnConnections'][0]['Options']['TunnelOptions'][index]['Phase1DHGroupNumbers']:
                                        ph1dh = item3['Value']
                                        if cph1dh == '':
                                            cph1dh = ph1dh
                                        else:
                                            cph1dh = f"{cph1dh} {ph1dh}"
                                        if ph1dh == 2:
                                            ike = ike + "-modp1024"
                                        if ph1dh == 14:
                                            ike = ike + "-modp2048"
                                        if ph1dh == 15:
                                            ike = ike + "-modp3072"
                                        if ph1dh == 16:
                                            ike = ike + "-modp4096"
                                        if ph1dh == 17:
                                            ike = ike + "-modp6144"
                                        if ph1dh == 18:
                                            ike = ike + "-modp8192"
                                        if ph1dh == 19:
                                            ike = ike + "-ecp256"
                                        if ph1dh == 20:
                                            ike = ike + "-ecp384"
                                        if ph1dh == 21:
                                            ike = ike + "-ecp521"
                                        if ph1dh == 22:
                                            ike = ike + "-modp1024s160"
                                        if ph1dh == 23:
                                            ike = ike + "-modp2048s224"
                                        if ph1dh == 24:
                                            ike = ike + "-modp2048s256"
                                ikelst.append(ike)
                            ike = ",".join(ikelst)
                        if 'Phase2EncryptionAlgorithms' in vpn['VpnConnections'][0]['Options']['TunnelOptions'][index]:
                            esplst =[]
                            cespenc = ''
                            for item in vpn['VpnConnections'][0]['Options']['TunnelOptions'][index]['Phase2EncryptionAlgorithms']:
                                ph2enc = item['Value']
                                if ph2enc == 'AES128':
                                    cespenc = 'esp-aes'
                                if ph2enc == 'AES256':
                                    cespenc = 'esp-aes 256'
                                if ph2enc == 'AES128-GCM-16':
                                    cespenc = 'esp-gcm'
                                    cgcm = 1
                                if ph2enc == 'AES256-GCM-16':
                                    cespenc = 'esp-gcm 256'
                                    cgcm = 1
                                esp = (ph2enc.replace("-","")).lower()
                                if 'Phase2IntegrityAlgorithms' in vpn['VpnConnections'][0]['Options']['TunnelOptions'][index]:
                                    cespint = ''
                                    for item2 in vpn['VpnConnections'][0]['Options']['TunnelOptions'][index]['Phase2IntegrityAlgorithms']:
                                        ph2int = item2['Value']
                                        if ph2int == 'SHA1':
                                            cespint = 'esp-sha-hmac'
                                        if ph2int == 'SHA2-256':
                                            cespint = 'esp-sha256-hmac'
                                        if ph2int == 'SHA2-384':
                                            cespint = 'esp-sha384-hmac'
                                        if ph2int == 'SHA2-512':
                                            cespint = 'esp-sha512-hmac'
                                        esp = esp + "-" + (ph2int.replace("-","_")).lower()
                                if 'Phase2DHGroupNumbers' in vpn['VpnConnections'][0]['Options']['TunnelOptions'][index]:
                                    for item3 in vpn['VpnConnections'][0]['Options']['TunnelOptions'][index]['Phase2DHGroupNumbers']:
                                        ph2dh = item3['Value']
                                        cph2dh = f"group{ph2dh}"
                                        if ph2dh == 2:
                                            esp = esp + "-modp1024"
                                        if ph2dh == 5:
                                            esp = esp + "-modp1536"
                                        if ph2dh == 14:
                                            esp = esp + "-modp2048"
                                        if ph2dh == 15:
                                            esp = esp + "-modp3072"
                                        if ph2dh == 16:
                                            esp = esp + "-modp4096"
                                        if ph2dh == 17:
                                            esp = esp + "-modp6144"
                                        if ph2dh == 18:
                                            esp = esp + "-modp8192"
                                        if ph2dh == 19:
                                            esp = esp + "-ecp256"
                                        if ph2dh == 20:
                                            esp = esp + "-ecp384"
                                        if ph2dh == 21:
                                            esp = esp + "-ecp521"
                                        if ph2dh == 22:
                                            esp = esp + "-modp1024s160"
                                        if ph2dh == 23:
                                            esp = esp + "-modp2048s224"
                                        if ph2dh == 24:
                                            esp = esp + "-modp2048s256"
                                esplst.append(esp)
                            esp = ",".join(esplst)
                        if 'StartupAction' in vpn['VpnConnections'][0]['Options']['TunnelOptions'][index]:
                            startact = vpn['VpnConnections'][0]['Options']['TunnelOptions'][index]['StartupAction']
                        else:
                            startact = 'start'
                    else:
                        startact = ''
                        keych = ''
                        ike = ''
                        esp = ''
                        rkfz = ''
                        rplw = 1024
                        rkmg = ''
                        dpdact = ''
                        cgcm = ''
                        ckeych = 'ikev1'
                        cikeenc = 'aes 128'
                        cikeint = 'sha'
                        cph1dh = 2
                        cph2dh = 'group2'
                        cespenc = 'esp-aes'
                        cespint = 'esp-sha-hmac'
                # generate config files
                # secret file for openswan/libreswan
                if ec2type == 'strongswan' or ec2type == 'libreswan':                
                    output = ('#Tunnel {0}\n{1} {2} : PSK "{3}"\n'.format(tnum, cgw_out_addr, vgw_out_addr, ike_pre_shared_key))
                    mycfgfile = f"{mylocalfolder}ipsec.secrets"
                    if tnum == 1:
                        outputfile = open(mycfgfile, 'w')
                    else:
                        outputfile = open(mycfgfile, 'a')
                    outputfile.write(output)
                    outputfile.close()
                    logger.info('Writing cfg file Success: {}'.format(mycfgfile))
                # vpnid.conf
                if ec2type == 'strongswan':
                    output = templatefsw.render(
                        tnum = tnum,
                        cgw_out_addr = cgw_out_addr,
                        vgw_out_addr = vgw_out_addr,
                        cgw_in_addr = cgw_in_addr,
                        cgw_in_cidr = cgw_in_cidr,
                        vgw_in_addr = vgw_in_addr,
                        vgw_in_cidr = vgw_in_cidr,
                        localcidr = localcidr,
                        ipsec_mode = ipsec_mode,
                        ike_encryption_protocol = ike_encryption_protocol,
                        ike_authentication_protocol = ike_authentication_protocol,
                        ike_lifetime = int(ike_lifetime)/3600,
                        ipsec_encryption_protocol = ipsec_encryption_protocol,
                        ipsec_authentication_protocol = (ipsec_authentication_protocol.split('-')[1]),
                        ipsec_lifetime = int(ipsec_lifetime)/3600,
                        dpd_delay = int(dpd_delay),
                        dpdtimeout = int(dpd_retry)*int(dpd_delay),
                        startact = startact,
                        keych = keych,
                        ike = ike,
                        esp = esp, 
                        leftsubnet = leftsubnet,
                        rightsubnet = rightsubnet,
                        rkfz = rkfz,
                        rkmg = rkmg,
                        rplw = rplw,
                        dpdact = dpdact
                    )
                    output = (output.replace("\n\n","\n")).replace("\n\n","\n")
                    mycfgfile = f"{mylocalfolder}{vpnid}.conf"
                    if tnum == 1:
                        outputfile = open(mycfgfile, 'w')
                    else:
                        outputfile = open(mycfgfile, 'a')
                    outputfile.write(output)
                    outputfile.close()
                    logger.info('Writing cfg file Success: {}'.format(mycfgfile))
                # ipsec.conf
                if ec2type == 'strongswan':
                    output = templateosw.render(
                        tnum = tnum,
                        cgw_out_addr = cgw_out_addr,
                        vgw_out_addr = vgw_out_addr,
                        cgw_in_addr = cgw_in_addr,
                        cgw_in_cidr = cgw_in_cidr,
                        vgw_in_addr = vgw_in_addr,
                        vgw_in_cidr = vgw_in_cidr,
                        localcidr = localcidr,
                        remotecidr = remotecidr,
                        ipsec_mode = ipsec_mode,
                        ike_encryption_protocol = ike_encryption_protocol,
                        ike_authentication_protocol = ike_authentication_protocol,
                        ike_lifetime = ike_lifetime,
                        ipsec_encryption_protocol = ipsec_encryption_protocol,
                        ipsec_authentication_protocol = (ipsec_authentication_protocol.split('-')[1]),
                        ipsec_lifetime = ipsec_lifetime,
                        dpd_delay = int(dpd_delay),
                        dpdtimeout = int(dpd_retry)*int(dpd_delay),
                        ipsec_fragmentation_before_encryption = ipsec_fragmentation_before_encryption,
                        startact = startact,
                        keych = keych,
                        ike = ike,
                        esp = esp, 
                        leftsubnet = leftsubnet,
                        rightsubnet = rightsubnet,
                        rkfz = rkfz,
                        rkmg = rkmg,
                        rplw = rplw,
                        dpdact = dpdact
                    )
                    output = (output.replace("\n\n","\n")).replace("\n\n","\n")
                    mycfgfile = f"{mylocalfolder}ipsec.conf"
                    if tnum == 1:
                        outputfile = open(mycfgfile, 'w')
                    else:
                        outputfile = open(mycfgfile, 'a')
                    outputfile.write(output)
                    outputfile.close()
                    logger.info('Writing cfg file Success: {}'.format(mycfgfile))
                    # bgp.conf
                    if routetype == 'bgp':
                        output = templatequa.render(
                            tnum = tnum,
                            cgw_bgp_asn = cgw_bgp_asn,
                            vgw_in_addr = vgw_in_addr,
                            cgw_in_addr = cgw_in_addr,
                            vgw_in_v6addr = vgw_in_v6addr,
                            cgw_in_v6addr = cgw_in_v6addr,
                            vgw_bgp_asn = vgw_bgp_asn,
                            cgw_bgp_ht = cgw_bgp_ht,
                            localcidr = localcidr
                        )
                        output = (output.replace("\n\n","\n")).replace("\n\n","\n")
                        mycfgfile = f"{mylocalfolder}bgp.conf"
                        if tnum == 1:
                            outputfile = open(mycfgfile, 'w')
                        else:
                            outputfile = open(mycfgfile, 'a')
                        outputfile.write(output)
                        outputfile.close()
                        logger.info('Writing cfg file Success: {}'.format(mycfgfile))
                # cisco_asr.conf
                if ec2type == 'CSR':
                    output = templateasr.render(
                        tnum = tnum,
                        vpnid = vpnid,
                        routetype = routetype,
                        cgw_out_addr = cgw_out_addr,
                        vgw_out_addr = vgw_out_addr,
                        cgw_in_addr = cgw_in_addr,
                        cgw_in_mask = cgw_in_mask,
                        vgw_in_addr = vgw_in_addr,
                        localnet = localnet,
                        localnetmask = localnetmask,
                        localnetsize = localnetsize,
                        remotenet = remotenet,
                        remotenetmask = remotenetmask,
                        remotenetsize = remotenetsize,
                        cgcm = cgcm,
                        remotecidr = remotecidr,
                        ike_encryption_protocol = cikeenc,
                        ike_authentication_protocol = cikeint,
                        cph1dh = cph1dh,
                        cph2dh = cph2dh,
                        ike_pre_shared_key = ike_pre_shared_key,
                        ike_lifetime = int(ike_lifetime),
                        ipsec_encryption_protocol = cespenc,
                        ipsec_authentication_protocol = cespint,
                        ipsec_lifetime = int(ipsec_lifetime),
                        dpd_delay = int(dpd_delay),
                        dpd_retry = int(dpd_retry),
                        keych = ckeych,
                        leftsubnet = leftsubnet,
                        rightsubnet = rightsubnet,
                        rkfz = rkfz,
                        rkmg = rkmg,
                        rplw = rplw,
                        cgw_bgp_asn = cgw_bgp_asn,
                        vgw_bgp_asn = vgw_bgp_asn,
                        cgw_bgp_ht = cgw_bgp_ht,
                        dpdact = dpdact
                    )
                    output = (output.replace("\n\n","\n")).replace("\n\n","\n")
                    mycfgfile = f"{mylocalfolder}cisco_asr.conf"
                    if tnum == 1:
                        outputfile = open(mycfgfile, 'w')
                    else:
                        outputfile = open(mycfgfile, 'a')
                    outputfile.write(output)
                    outputfile.close()
                    logger.info('Writing cfg file Success: {}'.format(mycfgfile))
                tnum += 1
            # generate installation files
            if ec2type == 'strongswan':
                if bucketname != '':
                    # bash file to install strongswan
                    installlstswan = []
                    installlstswan.append("amazon-linux-extras install -y epel")
                    installlstswan.append("yum install -y strongswan")
                    installlstswan.append("export GATEWAY=$(/sbin/ip route | awk '/default/ { print $3 }')")
                    if type(localcidr) == list:
                        for each in localcidr:
                            installlstswan.append(f"route add -net {each} gw $GATEWAY")
                        installlstswan.append(f"echo {each} via $GATEWAY >>/etc/sysconfig/network-scripts/route-eth0")
                    else:
                        installlstswan.append(f"route add -net {localcidr} gw $GATEWAY")
                        installlstswan.append(f"echo {localcidr} via $GATEWAY >>/etc/sysconfig/network-scripts/route-eth0")
                    installlstswan.append(f"aws s3 cp s3://{bucketname}/{mys3vpnfolder}ipsec.conf /etc/strongswan/ipsec.conf")
                    installlstswan.append(f"aws s3 cp s3://{bucketname}/{mys3vpnfolder}ipsec.secrets /etc/strongswan/ipsec.secrets")
                    installlstswan.append(f"aws s3 cp s3://{bucketname}/vpn/common/aws-updown.sh /etc/strongswan/ipsec.d/aws-updown.sh")
                    installlstswan.append("systemctl enable strongswan")
                    if routetype == 'bgp':
                        installlstswan.append("yum install -y quagga")
                        installlstswan.append(f"aws s3 cp s3://{bucketname}/{mys3vpnfolder}bgpd.conf /etc/quagga/bgpd.conf")
                        installlstswan.append("systemctl enable zebra")
                        installlstswan.append("systemctl enable bgpd")
                    installlstswan.append("echo 'ClientAliveInterval 60' | tee --append /etc/ssh/sshd_config")
                    installlstswan.append("echo 'ClientAliveCountMax 2' | tee --append /etc/ssh/sshd_config")
                    installlstswan.append("systemctl restart sshd.service")
                    installlstswan.append("yum update -y")
                    installlstswan.append("reboot")
                    output = '\n'.join(installlstswan)
                    mycfgfile = f"{mylocalfolder}install_strongswan.sh"
                    outputfile = open(mycfgfile, 'w')
                    outputfile.write(output)
                    outputfile.close()
                    logger.info('Writing cfg file Success: {}'.format(mycfgfile))
                    # upload install_strongswan.sh
                    myobj = f"{mys3vpnfolder}install_strongswan.sh"
                    fileupload(mycfgfile, bucketname, myobj)
                # ipsec.conf
                mycfgfile = f"{mylocalfolder}ipsec.conf"
                myobj = f"{mys3vpnfolder}ipsec.conf"
                if bucketname != '':
                    fileupload(mycfgfile, bucketname, myobj)
                    urlipsecconf = create_presigned_url(bucketname, myobj)
                # ipsec.secrets
                mycfgfile = f"{mylocalfolder}ipsec.secrets"
                myobj = f"{mys3vpnfolder}ipsec.secrets"
                if bucketname != '':
                    fileupload(mycfgfile, bucketname, myobj)
                    urlsecrets = create_presigned_url(bucketname, myobj)
                myobj = "vpn/common/aws-updown.sh"
                urlcommon = create_presigned_url(bucketname, myobj)
                if routetype == 'bgp':
                    # bgp.conf
                    mycfgfile = f"{mylocalfolder}bgp.conf"
                    myobj = f"{mys3vpnfolder}bgp.conf"
                    if bucketname != '':
                        fileupload(mycfgfile, bucketname, myobj)
                        urlbgpd = create_presigned_url(bucketname, myobj)
                # configuration to install strongswan and upload on secret manager
                installlstswan = []
                installlstswan.append("amazon-linux-extras install -y epel")
                installlstswan.append("export GATEWAY=$(/sbin/ip route | awk '/default/ { print $3 }')")
                if type(localcidr) == list:
                    for each in localcidr:
                        installlstswan.append(f"route add -net {each} gw $GATEWAY")
                    installlstswan.append(f"echo {each} via $GATEWAY >>/etc/sysconfig/network-scripts/route-eth0")
                else:
                    installlstswan.append(f"route add -net {localcidr} gw $GATEWAY")
                    installlstswan.append(f"echo {localcidr} via $GATEWAY >>/etc/sysconfig/network-scripts/route-eth0")
                installlstswan.append("yum install -y strongswan")
                installlstswan.append(f"curl \'{urlipsecconf}\' -o /etc/strongswan/ipsec.conf")
                installlstswan.append(f"curl \'{urlsecrets}\' -o /etc/strongswan/ipsec.secrets")
                installlstswan.append(f"curl \'{urlcommon}\' -o /etc/strongswan/ipsec.d/aws-updown.sh")
                installlstswan.append("chmod +x /etc/strongswan/ipsec.d/aws-updown.sh")
                installlstswan.append("systemctl enable strongswan")
                if routetype == 'bgp':
                    installlstswan.append("yum install -y quagga")
                    installlstswan.append(f"curl \'{urlbgpd}\' -o  /etc/quagga/bgpd.conf")
                    installlstswan.append("chown quagga:quaggavt /etc/quagga/bgpd.conf")
                    installlstswan.append("systemctl enable zebra")
                    installlstswan.append("systemctl enable bgpd")
                installlstswan.append("echo 'ClientAliveInterval 60' | tee --append /etc/ssh/sshd_config")
                installlstswan.append("echo 'ClientAliveCountMax 2' | tee --append /etc/ssh/sshd_config")
                installlstswan.append("systemctl restart sshd.service")
                installlstswan.append("yum update -y")
                installlstswan.append("reboot")
                secretdata = '\n'.join(installlstswan)
                #secretdata = base64.b64encode(lines.encode("ascii")).decode("ascii")
                if eventtype == 'Create':
                    logger.info('Debug: I enter here-Create')
                    keylist = {}
                    keylist['Name'] = f"/vpn/{vpnregion}/{vpnid}/usr-data"
                    keylist['Description'] = f"StrongSwan User-Data User-Data"
                    keylist['SecretString'] = secretdata
                    secretsput = createsecret(keylist, region)
                    if secretsput['ResponseMetadata']['HTTPStatusCode'] != 200:
                        logger.info('Secrets: Put Secret Error: {}'.format(secretsput))
                elif eventtype == 'Update':
                    logger.info('Debug: I enter here-Update')
                    keylist = {}
                    keylist['SecretId'] = f"/vpn/{vpnregion}/{vpnid}/usr-data"
                    keylist['SecretString'] = secretdata
                    secretsput = putsecret(keylist, region)
                    if secretsput['ResponseMetadata']['HTTPStatusCode'] != 200:
                        logger.info('Secrets: Put Secret Error: {}'.format(secretsput))
                else:
                    logger.info('Secrets: Nothing to do! : {}'.format(eventtype))
                response["Data"]["USRDATA"] = secretsput['ARN']
            # bash file to install libreswan
            if ec2type == 'libreswan':
                if bucketname != '':
                    installlstlibre = []
                    installlstlibre.append("amazon-linux-extras install -y epel")
                    installlstlibre.append("export GATEWAY=$(/sbin/ip route | awk '/default/ { print $3 }')")
                    if type(localcidr) == list:
                        for each in localcidr:
                            installlstlibre.append(f"route add -net {each} gw $GATEWAY")
                        installlstlibre.append(f"echo {each} via $GATEWAY >>/etc/sysconfig/network-scripts/route-eth0")
                    else:
                        installlstlibre.append(f"route add -net {localcidr} gw $GATEWAY")
                        installlstlibre.append(f"echo {localcidr} via $GATEWAY >>/etc/sysconfig/network-scripts/route-eth0")
                    installlstlibre.append("yum install -y libreswan")
                    installlstlibre.append(f"aws s3 cp s3://{bucketname}/{mys3vpnfolder}{vpnid}.conf /etc/ipsec.d/{vpnid}.conf")
                    installlstlibre.append(f"aws s3 cp s3://{bucketname}/{mys3vpnfolder}ipsec.secrets /etc/ipsec.d/ipsec.secrets")
                    installlstlibre.append(f"aws s3 cp s3://{bucketname}/vpn/common/aws-updown.sh /etc/ipsec.d/aws-updown.sh")
                    installlstlibre.append("chmod +x /etc/ipsec.d/aws-updown.sh")
                    installlstlibre.append("systemctl enable ipsec.service")
                    if routetype == 'bgp':
                        installlstlibre.append("yum install -y quagga")
                        installlstlibre.append(f"aws s3 cp s3://{bucketname}/{mys3vpnfolder}bgpd.conf /etc/quagga/bgpd.conf")
                        installlstlibre.append("chown quagga:quaggavt /etc/quagga/bgpd.conf")
                        installlstlibre.append("systemctl enable zebra")
                        installlstlibre.append("systemctl enable bgpd")
                    installlstlibre.append("echo 'ClientAliveInterval 60' | tee --append /etc/ssh/sshd_config")
                    installlstlibre.append("echo 'ClientAliveCountMax 2' | tee --append /etc/ssh/sshd_config")
                    installlstlibre.append("systemctl restart sshd.service")
                    installlstlibre.append("yum update -y")
                    installlstlibre.append("reboot")
                    output = '\n'.join(installlstlibre)
                    mycfgfile = f"{mylocalfolder}install_libreswan.sh"
                    outputfile = open(mycfgfile, 'w')
                    outputfile.write(output)
                    outputfile.close()
                    logger.info('Writing cfg file Success: {}'.format(mycfgfile))
                    # upload install_libreswan.sh
                    mycfgfile = f"{mylocalfolder}install_libreswan.sh"
                    fileupload(mycfgfile, bucketname, myobj)
                # vpnid.conf
                mycfgfile = f"{mylocalfolder}{vpnid}.conf"
                myobj = f"{mys3vpnfolder}{vpnid}.conf"
                if bucketname != '':
                    fileupload(mycfgfile, bucketname, myobj)
                    urlipsecconf = create_presigned_url(bucketname, myobj)
                # ipsec.secrets
                mycfgfile = f"{mylocalfolder}ipsec.secrets"
                myobj = f"{mys3vpnfolder}ipsec.secrets"
                if bucketname != '':
                    fileupload(mycfgfile, bucketname, myobj)
                    urlsecrets = create_presigned_url(bucketname, myobj)
                myobj = "vpn/common/aws-updown.sh"
                urlcommon = create_presigned_url(bucketname, myobj)
                if routetype == 'bgp':
                    # bgp.conf
                    mycfgfile = f"{mylocalfolder}bgp.conf"
                    myobj = f"{mys3vpnfolder}bgp.conf"
                    if bucketname != '':
                        fileupload(mycfgfile, bucketname, myobj)
                        urlbgpd = create_presigned_url(bucketname, myobj)
                # configuration to install strongswan and upload on secret manager
                installlstlibre = []
                installlstlibre.append("amazon-linux-extras install -y epel")
                installlstlibre.append("yum install -y libreswan")
                installlstlibre.append("export GATEWAY=$(/sbin/ip route | awk '/default/ { print $3 }')")
                if type(localcidr) == list:
                    for each in localcidr:
                        installlstlibre.append(f"route add -net {each} gw $GATEWAY")
                    installlstlibre.append(f"echo {each} via $GATEWAY >>/etc/sysconfig/network-scripts/route-eth0")
                else:
                    installlstlibre.append(f"route add -net {localcidr} gw $GATEWAY")
                    installlstlibre.append(f"echo {localcidr} via $GATEWAY >>/etc/sysconfig/network-scripts/route-eth0")
                installlstlibre.append(f"curl \'{urlipsecconf}\' -o /etc/ipsec.d/{vpnid}.conf")
                installlstlibre.append(f"curl \'{urlsecrets}\' -o /etc/ipsec.d/ipsec.secrets")
                installlstlibre.append(f"curl \'{urlcommon}\' -o /etc/ipsec.d/aws-updown.sh")
                installlstlibre.append("systemctl enable ipsec.service")
                if routetype == 'bgp':
                    installlstlibre.append("yum install -y quagga")
                    installlstlibre.append(f"curl \'{urlbgpd}\' -o /etc/quagga/bgpd.conf")
                    installlstlibre.append("systemctl enable zebra")
                    installlstlibre.append("systemctl enable bgpd")
                installlstlibre.append("echo 'ClientAliveInterval 60' | tee --append /etc/ssh/sshd_config")
                installlstlibre.append("echo 'ClientAliveCountMax 2' | tee --append /etc/ssh/sshd_config")
                installlstlibre.append("systemctl restart sshd.service")
                installlstlibre.append("yum update -y")
                installlstlibre.append("reboot")
                secretdata = '\n'.join(installlstlibre)
                #secretdata = base64.b64encode(lines.encode("ascii")).decode("ascii")
                if eventtype == 'Create':
                    keylist = {}
                    keylist['Name'] = f"/vpn/{vpnregion}/{vpnid}/usr-data"
                    keylist['Description'] = f"LibreSwan User-Data User-Data"
                    keylist['SecretString'] = secretdata
                    secretsput = createsecret(keylist, region)
                    if secretsput['ResponseMetadata']['HTTPStatusCode'] != 200:
                        logger.info('Secrets: Put Secret Error: {}'.format(secretsput))
                elif eventtype == 'Update':
                    keylist = {}
                    keylist['SecretId'] = f"/vpn/{vpnregion}/{vpnid}/usr-data"
                    keylist['SecretString'] = secretdata
                    secretsput = putsecret(keylist, region)
                    if secretsput['ResponseMetadata']['HTTPStatusCode'] != 200:
                        logger.info('Secrets: Put Secret Error: {}'.format(secretsput))
                else:
                    logger.info('Secrets: Nothing to do! : {}'.format(eventtype))
                response["Data"]["USRDATA"] = secretsput['ARN']
            # cisco_asr.conf
            if ec2type == 'CSR':            
                mycfgfile = f"{mylocalfolder}cisco_asr.conf"
                with open(mycfgfile, 'r') as f:
                    lines = f.read()
                lines = lines.split("\n")                
                output = []
                index = 1
                for line in lines:
                    if line != '':
                        output.append(f"ios-config-{index}=\"{line}\"\n")
                        index = index + 1
                with open(mycfgfile, 'w') as f:
                    f.writelines(output)
                myobj = f"{mys3vpnfolder}cisco_asr.conf"
                if bucketname != '':
                    fileupload(mycfgfile, bucketname, myobj)
                with open(mycfgfile, 'r') as f:
                    lines = f.read()
                secretdata = base64.b64encode(lines.encode("ascii")).decode("ascii")
                if eventtype == 'Create':
                    keylist = {}
                    keylist['Name'] = f"/vpn/{vpnregion}/{vpnid}/usr-data"
                    keylist['Description'] = f"Cisco CSR VGW Endpoint User-Data"
                    keylist['SecretString'] = secretdata
                    secretsput = createsecret(keylist, region)
                    if secretsput['ResponseMetadata']['HTTPStatusCode'] != 200:
                        logger.info('Secrets: Put Secret Error: {}'.format(secretsput))
                elif eventtype == 'Update':
                    keylist = {}
                    keylist['SecretId'] = f"/vpn/{vpnregion}/{vpnid}/usr-data"
                    keylist['SecretString'] = secretdata
                    secretsput = putsecret(keylist, region)
                    if secretsput['ResponseMetadata']['HTTPStatusCode'] != 200:
                        logger.info('Secrets: Put Secret Error: {}'.format(secretsput))
                else:
                    logger.info('Secrets: Put Secret Success! : {}'.format(secretsput))
                response["Data"]["USRDATA"] = secretsput['ARN']
            # generate response
            phyresId = vpnid
            response["Status"] = "SUCCESS"
            response["Reason"] = ("Configuration upload succeed!")
            response["PhysicalResourceId"] = phyresId
            response["Data"]["VPNid"] = phyresId
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