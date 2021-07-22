import os
import sys
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

def fileupload(mycfgfile, bucketname, myobj):
    try:
        with open(mycfgfile, "rb") as data:
            response = s3.upload_fileobj(data, bucketname, myobj)
            logger.info('S3: Upload object Success: {}'.format(mycfgfile))
            return response
    except Exception as e:
        logger.info('S3: Creation of folder Error: {}'.format(e))


def createfolder(bucketname, folder):
    # create config folder to vpn files
    try:
        response = s3.put_object(Bucket=bucketname, Key=(folder))
        logger.info('S3: Creation of folder Success: {}'.format(folder))
        return response
    except Exception as e:
        logger.info('S3: Creation of folder Error: {}'.format(e))

def deletevpnfolder(bucketname, folder):
    # remove folder and vpn files
    try:
        response = s3.list_objects_v2(Bucket=bucketname, Prefix=folder)
        for obj in response['Contents']:
            # remove content
            if folder != obj['Key']:
                s3.delete_object(Bucket=bucketname, Key=obj['Key'])
                logger.info('S3: Deletion of object Success: {}'.format(obj['Key']))
        #remove folder
        s3.delete_object(Bucket=bucketname, Key=folder)
        logger.info('S3: Deletion of folder Success: {}'.format(folder))
        return response
    except Exception as e:
        logger.info('S3: Deletion of folder Error: {}'.format(e))

def describevpn(vpnid,vpnregion):
    # Get VPN Configuration XML
    try:
        ec2 = boto3.client('ec2', region_name=vpnregion)
        response = ec2.describe_vpn_connections(
            VpnConnectionIds=[
                vpnid,
            ]
        )
        logger.info('EC2: VPN Configuration Received Success: {}'.format(vpnid))
        return response
    except Exception as e:
        logger.info('EC2: VPN Configuration Error: {}'.format(e))

def lambda_handler(event, context):
    logger.info('event: {}'.format(event))
    logger.info('context: {}'.format(context))
    #region = event['region']
    vpnid = event['ResourceProperties']['0']['VPN']
    routetype = event['ResourceProperties']['0']['Route']
    bucketname = event['ResourceProperties']['0']['S3']
    vpnregion = event['ResourceProperties']['0']['Region']
    localcidr = event['ResourceProperties']['0']['LocalCidr']
    localnet, localnetbits = localcidr.split('/')
    localhostbits = 32 - int(localnetbits)
    localnetmask = socket.inet_ntoa(struct.pack('!I', (1 << 32) - (1 << localhostbits)))
    if routetype == 'static':
        remotecidr = event['ResourceProperties']['0']['RemoteCidr']
        remotenet, remotenetbits = remotecidr.split('/')
        remotehostbits = 32 - int(remotenetbits)
        remotenetmask = socket.inet_ntoa(struct.pack('!I', (1 << 32) - (1 << remotehostbits)))
    else:
        remotecidr = ''
        remotenet = ''
        remotenetmask = ''
    mys3vpnfolder = f"vpn/{vpnid}/"
    mylocalfolder = '/tmp/'
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
            deletevpnfolder(bucketname,mys3vpnfolder)
            response["Status"] = "SUCCESS"
            response["Reason"] = ("VPN Config deletion succeed!")
        else:
            # get vpn configuration
            vpn = describevpn(vpnid,vpnregion)
            # create config folder to vpn files
            createfolder(bucketname,mys3vpnfolder)
            # read template files
            with open('ipsec_conf_fsw.tmpl') as f:
                ipsec_conf_fsw = f.read()
            templatefsw = Template(ipsec_conf_fsw)
            f.close()
            with open('ipsec_conf_osw.tmpl') as f:
                ipsec_conf_osw = f.read()
            templateosw = Template(ipsec_conf_osw)
            f.close()
            with open('bgpd_conf.tmpl') as f:
                bgpd_conf = f.read()
            templatequa = Template(bgpd_conf)
            f.close()
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
                logger.info('Tunnel {0}: Content: {1}'.format(tnum, tun))
                cgw_out_addr = tun['customer_gateway']['tunnel_outside_address']['ip_address']
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
                            rplw = ''
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
                                    if keych == 'ikev2':
                                        cikeenc = 'aes-cbc-128'
                                    else:
                                        cikeenc = 'aes 128'
                                if ph1enc == 'AES256':
                                    if keych == 'ikev2':
                                        cikeenc = 'aes-cbc-256'
                                    else:
                                        cikeenc = 'aes 256'
                                if ph1enc == 'AES128-GCM-16':
                                    cgcm = 1
                                    if keych == 'ikev2':
                                        cikeenc = 'aes-gcm-128'
                                    else:
                                        cikeenc = 'aes 128'
                                if ph1enc == 'AES256-GCM-16':
                                    cgcm = 1
                                    if keych == 'ikev2':
                                        cikeenc = 'aes 256'
                                    else:
                                        cikeenc = 'aes-gcm-256'
                                ike = (ph1enc.replace("-","")).lower()
                                if 'Phase1IntegrityAlgorithms' in vpn['VpnConnections'][0]['Options']['TunnelOptions'][index]:
                                    cikeint = ''
                                    for item2 in vpn['VpnConnections'][0]['Options']['TunnelOptions'][index]['Phase1IntegrityAlgorithms']:
                                        ph1int = item2['Value']
                                        if ph1int == 'SHA-1':
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
                                        if ph2int == 'SHA-1':
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
                        rplw = ''
                        rkmg = ''
                        dpdact = ''
                # generate installation files
                # bash file to install openswan
                if routetype == 'bgp':
                    installlstswan = [
                        "amazon-linux-extras install -y epel",
                        "yum install -y strongswan quagga",
                        "yum update -y",
                        "export GATEWAY=$(/sbin/ip route | awk '/default/ { print $3 }')",
                        f"route add -net {localcidr} gw $GATEWAY",
                        f"echo {localcidr} via $GATEWAY >>/etc/sysconfig/network-scripts/route-eth0",
                        f"aws s3 cp s3://{bucketname}/{mys3vpnfolder}ipsec.conf /etc/strongswan/ipsec.conf",
                        f"aws s3 cp s3://{bucketname}/{mys3vpnfolder}ipsec.secrets /etc/strongswan/ipsec.secrets",
                        f"aws s3 cp s3://{bucketname}/{mys3vpnfolder}bgpd.conf /etc/quagga/bgpd.conf",
                        f"aws s3 cp s3://{bucketname}/vpn/common/aws-updown.sh /etc/strongswan/ipsec.d/aws-updown.sh",
                        "systemctl enable strongswan",
                        "systemctl enable zebra",
                        "systemctl enable bgpd",
                        "echo 'ClientAliveInterval 60' | tee --append /etc/ssh/sshd_config",
                        "echo 'ClientAliveCountMax 2' | tee --append /etc/ssh/sshd_config",
                        "systemctl restart sshd.service",
                        "reboot"
                    ]
                else:
                    installlstswan = [
                        "amazon-linux-extras install -y epel",
                        "yum install -y strongswan",
                        "yum update -y",
                        f"aws s3 cp s3://{bucketname}/{mys3vpnfolder}ipsec.conf /etc/strongswan/ipsec.conf",
                        f"aws s3 cp s3://{bucketname}/{mys3vpnfolder}ipsec.secrets /etc/strongswan/ipsec.secrets",
                        f"aws s3 cp s3://{bucketname}/vpn/common/aws-updown.sh /etc/strongswan/ipsec.d/aws-updown.sh",
                        "systemctl enable strongswan",
                        "systemctl enable zebra",
                        "echo 'ClientAliveInterval 60' | tee --append /etc/ssh/sshd_config",
                        "echo 'ClientAliveCountMax 2' | tee --append /etc/ssh/sshd_config",
                        "systemctl restart sshd.service",
                        "reboot"
                    ]
                output = '\n'.join(installlstswan)
                mycfgfile = f"{mylocalfolder}install_strongswan.sh"
                if tnum == 1:
                    outputfile = open(mycfgfile, 'w')
                    outputfile.write(output)
                    outputfile.close()
                    logger.info('Writing cfg file Success: {}'.format(mycfgfile))
                # bash file to install libreswan
                if routetype == 'bgp':
                    installlstlibre = [
                        "amazon-linux-extras install -y epel",
                        "yum install -y libreswan quagga",
                        "yum update -y",
                        "export GATEWAY=$(/sbin/ip route | awk '/default/ { print $3 }')",
                        f"route add -net {localcidr} gw $GATEWAY",
                        f"echo {localcidr} via $GATEWAY >>/etc/sysconfig/network-scripts/route-eth0",
                        f"aws s3 cp s3://{bucketname}/{mys3vpnfolder}{vpnid}.conf /etc/ipsec.d/{vpnid}.conf",
                        f"aws s3 cp s3://{bucketname}/{mys3vpnfolder}ipsec.secrets /etc/ipsec.d/ipsec.secrets",
                        f"aws s3 cp s3://{bucketname}/{mys3vpnfolder}bgpd.conf /etc/quagga/bgpd.conf",
                        f"aws s3 cp s3://{bucketname}/vpn/common/aws-updown.sh /etc/ipsec.d/aws-updown.sh",
                        "systemctl enable ipsec.service",
                        "systemctl enable zebra",
                        "systemctl enable bgpd",
                        "echo 'ClientAliveInterval 60' | tee --append /etc/ssh/sshd_config",
                        "echo 'ClientAliveCountMax 2' | tee --append /etc/ssh/sshd_config",
                        "systemctl restart sshd.service",
                        "reboot"
                    ]
                else:
                    installlstlibre = [
                        "amazon-linux-extras install -y epel",
                        "yum install -y libreswan",
                        "yum update -y",
                        f"aws s3 cp s3://{bucketname}/{mys3vpnfolder}{vpnid}.conf /etc/ipsec.d/{vpnid}.conf",
                        f"aws s3 cp s3://{bucketname}/{mys3vpnfolder}ipsec.secrets /etc/ipsec.d/ipsec.secrets",
                        f"aws s3 cp s3://{bucketname}/vpn/common/aws-updown.sh /etc/ipsec.d/aws-updown.sh",
                        "systemctl enable ipsec.service",
                        "systemctl enable zebra",
                        "echo 'ClientAliveInterval 60' | tee --append /etc/ssh/sshd_config",
                        "echo 'ClientAliveCountMax 2' | tee --append /etc/ssh/sshd_config",
                        "systemctl restart sshd.service",
                        "reboot"
                    ]
                output = '\n'.join(installlstlibre)
                mycfgfile = f"{mylocalfolder}install_libreswan.sh"
                if tnum == 1:
                    outputfile = open(mycfgfile, 'w')
                    outputfile.write(output)
                    outputfile.close()
                    logger.info('Writing cfg file Success: {}'.format(mycfgfile))
                # generate config files
                # secret file for openswan/libreswan
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
                output = templateasr.render(
                    tnum = tnum,
                    vpnid = vpnid,
                    cgw_out_addr = cgw_out_addr,
                    vgw_out_addr = vgw_out_addr,
                    cgw_in_addr = cgw_in_addr,
                    cgw_in_mask = cgw_in_mask,
                    vgw_in_addr = vgw_in_addr,
                    localnet = localnet,
                    localnetmask = localnetmask,
                    remotenet = remotenet,
                    remotenetmask = remotenetmask,
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
            # upload files
            # install_strongswan.sh
            mycfgfile = f"{mylocalfolder}install_strongswan.sh"
            myobj = f"{mys3vpnfolder}install_strongswan.sh"
            fileupload(mycfgfile, bucketname, myobj)
            # install_libreswan.sh
            mycfgfile = f"{mylocalfolder}install_libreswan.sh"
            myobj = f"{mys3vpnfolder}install_libreswan.sh"
            fileupload(mycfgfile, bucketname, myobj)
            # vpnid.conf
            mycfgfile = f"{mylocalfolder}{vpnid}.conf"
            myobj = f"{mys3vpnfolder}{vpnid}.conf"
            fileupload(mycfgfile, bucketname, myobj)
            # ipsec.conf
            mycfgfile = f"{mylocalfolder}ipsec.conf"
            myobj = f"{mys3vpnfolder}ipsec.conf"
            fileupload(mycfgfile, bucketname, myobj)
            if routetype == 'bgp':
                # bgp.conf
                mycfgfile = f"{mylocalfolder}bgp.conf"
                myobj = f"{mys3vpnfolder}bgp.conf"
                fileupload(mycfgfile, bucketname, myobj)
            # ipsec.secrets
            mycfgfile = f"{mylocalfolder}ipsec.secrets"
            myobj = f"{mys3vpnfolder}ipsec.secrets"
            fileupload(mycfgfile, bucketname, myobj)
            # cisco_asr.conf
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
            fileupload(mycfgfile, bucketname, myobj)
            # generate response
            phyresId = vpnid
            response["Status"] = "SUCCESS"
            response["Reason"] = ("Configuration upload succeed!")
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