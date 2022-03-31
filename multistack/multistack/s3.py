import os
import json
from aws_cdk import (
    aws_iam as iam,
    aws_logs as log,
    aws_kms as kms,
    aws_s3 as s3,
    core,
)
account = core.Aws.ACCOUNT_ID
region = core.Aws.REGION
class main(core.Stack):

    def __init__(self, scope: core.Construct, construct_id: str, res, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # The code that defines your stack goes here
        # create Police for lambda function
        resconf = "resourcesmap.cfg"
        with open(resconf) as resfile:
            resmap = json.load(resfile)
        if 'CRYPT' in resmap['Mappings']['Resources'][res]:
            resencrypt = True
            resencrest = resmap['Mappings']['Resources'][res]['CRYPT']
            if 'Crypkey' in resencrest:
                cripkey = kms.KeySpec(value=resencrest['Crypkey'])
            else:
                cripkey = kms.KeySpec.SYMMETRIC_DEFAULT
            if 'keyrot' in resencrest:
                keyrot = resencrest['keyrot']
            else:
                keyrot = False

            if 'penwin' in resencrest:
                penwin = core.Duration.days(resencrest['penwin'])
            else:
                penwin = core.Duration.days(7)
            if 'rempol' in resencrest:
                rempol = core.RemovalPolicy(resencrest['rempol'])
            else:
                rempol = core.RemovalPolicy.DESTROY
            encryptkey = kms.Key(
                self,
                f"{construct_id}Key",
                alias=resencrest['Keyid'],
                description="Key for EFS Encrypt at Rest",
                key_usage=kms.KeyUsage.ENCRYPT_DECRYPT,
                enabled=True,
                key_spec=cripkey,
                policy=None,
                enable_key_rotation=keyrot,
                removal_policy=rempol,
                pending_window=penwin,
            )
            restypeencrypt = s3.BucketEncryption.KMS
            if 'TYPECRYPT' in resencrest:
                if resencrest['TYPECRYPT'] == 'KMS_MANAGED':
                    restypeencrypt = s3.BucketEncryption.KMS_MANAGED
                elif resencrest['TYPECRYPT'] == 'KMS_MANAGED':
                    restypeencrypt = s3.BucketEncryption.S3_MANAGED
                else:
                    restypeencrypt = s3.BucketEncryption.UNENCRYPTED
            else:
                restypeencrypt = s3.BucketEncryption.UNENCRYPTED
        else:
            resencrypt = False
            encryptkey = None
            restypeencrypt = s3.BucketEncryption.UNENCRYPTED
        if 'NAME' in resmap['Mappings']['Resources'][res]:
            resname = resmap['Mappings']['Resources'][res]['NAME']
        else:
            resname = None
        if 'ACCESSCONTROL' in resmap['Mappings']['Resources'][res]:
            if resmap['Mappings']['Resources'][res]['ACCESSCONTROL'] == 'AUTHENTICATED_READ':
                resaccesscontrol = s3.BucketAccessControl.AUTHENTICATED_READ
            elif resmap['Mappings']['Resources'][res]['ACCESSCONTROL'] == 'AWS_EXEC_READ':
                resaccesscontrol = s3.BucketAccessControl.AWS_EXEC_READ
            elif resmap['Mappings']['Resources'][res]['ACCESSCONTROL'] == 'BUCKET_OWNER_FULL_CONTROL':
                resaccesscontrol = s3.BucketAccessControl.BUCKET_OWNER_FULL_CONTROL
            elif resmap['Mappings']['Resources'][res]['ACCESSCONTROL'] == 'BUCKET_OWNER_READ':
                resaccesscontrol = s3.BucketAccessControl.BUCKET_OWNER_READ
            elif resmap['Mappings']['Resources'][res]['ACCESSCONTROL'] == 'LOG_DELIVERY_WRITE':
                resaccesscontrol = s3.BucketAccessControl.LOG_DELIVERY_WRITE
            elif resmap['Mappings']['Resources'][res]['ACCESSCONTROL'] == 'PUBLIC_READ':
                resaccesscontrol = s3.BucketAccessControl.PUBLIC_READ
            elif resmap['Mappings']['Resources'][res]['ACCESSCONTROL'] == 'PUBLIC_READ_WRITE':
                resaccesscontrol = s3.BucketAccessControl.PUBLIC_READ_WRITE
            else:
                resaccesscontrol = s3.BucketAccessControl.PRIVATE
        else:
            resaccesscontrol = s3.BucketAccessControl.PRIVATE
        if 'AUTODEL' in resmap['Mappings']['Resources'][res]:
            resnautodel = resmap['Mappings']['Resources'][res]['AUTODEL']
        else:
            resnautodel = True
        if 'REMPOL' in resmap['Mappings']['Resources'][res]:
            resrempol = core.RemovalPolicy(resmap['Mappings']['Resources'][res]['REMPOL'])
        else:
            resrempol = core.RemovalPolicy.DESTROY
        if 'BLOCKPUB' in resmap['Mappings']['Resources'][res]:
            if resmap['Mappings']['Resources'][res]['BLOCKPUB'] == 'BLOCK_ACLS':
                resblockpub = s3.BlockPublicAccess.BLOCK_ACLS
            else:
                resblockpub = s3.BlockPublicAccess.BLOCK_ALL
        else:
            resblockpub = s3.BlockPublicAccess.BLOCK_ALL
        if 'SSL' in resmap['Mappings']['Resources'][res]:
            resssl = resmap['Mappings']['Resources'][res]['SSL']
        else:
            resssl = True
        # add cors rules
            rescors = None

        self.bucket = s3.Bucket(
            self,
            f"{construct_id}",
            access_control=resaccesscontrol,
            auto_delete_objects=resnautodel,
            removal_policy=resrempol,
            block_public_access=resblockpub,
            bucket_key_enabled=resencrypt,
            encryption=restypeencrypt,
            encryption_key=encryptkey,
            bucket_name=resname,
            cors=rescors,
            enforce_ssl=resssl
        )
