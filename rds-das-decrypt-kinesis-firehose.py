from __future__ import print_function
import os
import json
import boto3
import base64
import zlib
import aws_encryption_sdk
from requests_aws4auth import AWS4Auth
from aws_encryption_sdk import CommitmentPolicy
from aws_encryption_sdk.internal.crypto import WrappingKey
from aws_encryption_sdk.key_providers.raw import RawMasterKeyProvider
from aws_encryption_sdk.identifiers import WrappingAlgorithm, EncryptionKeyType

REGION_NAME = os.environ['AWS_REGION']
RESOURCE_ID = os.environ['resource_id']

enc_client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
kms = boto3.client('kms', region_name=REGION_NAME)

class MyRawMasterKeyProvider(RawMasterKeyProvider):
    provider_id = "BC"
    def __new__(cls, *args, **kwargs):
        obj = super(RawMasterKeyProvider, cls).__new__(cls)
        return obj
    def __init__(self, plain_key):
        RawMasterKeyProvider.__init__(self)
        self.wrapping_key = WrappingKey(wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
                                        wrapping_key=plain_key, wrapping_key_type=EncryptionKeyType.SYMMETRIC)
    def _get_raw_key(self, key_id):
        return self.wrapping_key

def decrypt_payload(payload, data_key):
    my_key_provider = MyRawMasterKeyProvider(data_key)
    my_key_provider.add_master_key("DataKey")
    #Decrypt the records using the master key.
    decrypted_plaintext, header = enc_client.decrypt(
        source=payload,
        materials_manager=aws_encryption_sdk.materials_managers.default.DefaultCryptoMaterialsManager(master_key_provider=my_key_provider))
    return decrypted_plaintext

# Function to decompress payload
def decrypt_decompress(payload, key):
    decrypted = decrypt_payload(payload, key)
    try:
        return zlib.decompress(decrypted, zlib.MAX_WBITS + 16)
    except Exception as e:
        print("An exception occurred:", e)

def lambda_handler(event, context):
    for record in event['records']:
        output=[]
        data = base64.b64decode(record['data'])
        record_data = json.loads(data)
        
        # Decode and decrypt the payload
        payload_decoded = base64.b64decode(record_data['databaseActivityEvents'])
        data_key_decoded = base64.b64decode(record_data['key'])

        if 'db' in RESOURCE_ID:
            EncryptionContext={'aws:rds:db-id': RESOURCE_ID}
        else:
            EncryptionContext={'aws:rds:dbc-id': RESOURCE_ID}
            
        data_key_decrypt_result = kms.decrypt(CiphertextBlob=data_key_decoded,EncryptionContext=EncryptionContext)

        if decrypt_decompress(payload_decoded, data_key_decrypt_result['Plaintext']) is None:
            continue

        plaintext = decrypt_decompress(payload_decoded, data_key_decrypt_result['Plaintext']).decode('utf8')

        # Decode JSON DAS record
        events = json.loads(plaintext)
        plain_event = plaintext.encode("utf-8")
        output_record = {
                'recordId': record['recordId'],
                'result': 'Ok',
                'data': base64.b64encode(plaintext.encode("utf-8")).decode('utf-8')
                }
        output.append(output_record)
        return {'records': output}