from __future__ import print_function
import os
import json
import boto3
import base64
import zlib
import uuid
import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy
from aws_encryption_sdk.internal.crypto import WrappingKey
from aws_encryption_sdk.key_providers.raw import RawMasterKeyProvider
from aws_encryption_sdk.identifiers import WrappingAlgorithm, EncryptionKeyType

REGION_NAME = os.environ['AWS_REGION']
RDS_RESOURCE_ID = os.environ['rds_resource_id']
LOG_GROUP_NAME = os.environ['log_group_name']
LOG_STREAM_NAME = os.environ['log_stream_name']

enc_client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
kms = boto3.client('kms', region_name=REGION_NAME)
logs = boto3.client('logs', region_name=REGION_NAME)

# MasterKeyProvider class
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

# Function to decrypt the payload
def decrypt_payload(payload, data_key):
    my_key_provider = MyRawMasterKeyProvider(data_key)
    my_key_provider.add_master_key("DataKey")
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
    # Ensure log group and stream exist
    try:
        logs.create_log_group(logGroupName=LOG_GROUP_NAME)
    except logs.exceptions.ResourceAlreadyExistsException:
        pass
    
    try:
        logs.create_log_stream(logGroupName=LOG_GROUP_NAME, logStreamName=LOG_STREAM_NAME)
    except logs.exceptions.ResourceAlreadyExistsException:
        pass

    for record in event['Records']:
        data = base64.b64decode(record['kinesis']['data'])
        record_data = json.loads(data)
        
        # Decode and decrypt the payload
        payload_decoded = base64.b64decode(record_data['databaseActivityEvents'])
        data_key_decoded = base64.b64decode(record_data['key'])
        if 'db' in RDS_RESOURCE_ID:
            EncryptionContext={'aws:rds:db-id': RDS_RESOURCE_ID}
        else:
            EncryptionContext={'aws:rds:dbc-id': RDS_RESOURCE_ID}
        data_key_decrypt_result = kms.decrypt(CiphertextBlob=data_key_decoded,EncryptionContext=EncryptionContext)
        if decrypt_decompress(payload_decoded, data_key_decrypt_result['Plaintext']) is None:
            continue
        plaintext = decrypt_decompress(payload_decoded, data_key_decrypt_result['Plaintext']).decode('utf8')

        # Decode JSON DAS record
        events = json.loads(plaintext)

        # Filtering logic
        for dbEvent in events['databaseActivityEventList'][:]: 
            if dbEvent['type'] == "heartbeat" or (dbEvent['dbUserName'] and dbEvent["dbUserName"] in ("RDSADMIN","RDSSEC")):
                events['databaseActivityEventList'].remove(dbEvent)
    
        # Send events to CloudWatch Logs
        if len(events['databaseActivityEventList']) > 0:
            log_events = []
            for dbEvent in events['databaseActivityEventList']:
                log_event = {
                    'logTime': dbEvent['logTime'].split('.')[0].split('+')[0],
                    'pid': dbEvent['pid'],
                    'dbUserName': dbEvent['dbUserName'],
                    'databaseName': dbEvent['databaseName'],
                    'command': dbEvent['command'],
                    'commandText': dbEvent['commandText']
                }
                
                if 'engineNativeAuditFields' in dbEvent:
                    log_event['engineNativeAuditFields'] = dbEvent['engineNativeAuditFields']
                if 'startTime' in dbEvent and dbEvent['startTime'] is not None:
                    log_event['startTime'] = dbEvent['startTime'].split('.')[0].split('+')[0]
                if 'endTime' in dbEvent and dbEvent['endTime'] is not None:
                    log_event['endTime'] = dbEvent['endTime'].split('.')[0].split('+')[0]

                log_events.append({
                    'timestamp': int(context.get_remaining_time_in_millis()),
                    'message': json.dumps(log_event)
                })

            # Put log events in batches (CloudWatch Logs limit is 10000 events per batch)
            batch_size = 10000
            for i in range(0, len(log_events), batch_size):
                batch = log_events[i:i + batch_size]
                try:
                    logs.put_log_events(
                        logGroupName=LOG_GROUP_NAME,
                        logStreamName=LOG_STREAM_NAME,
                        logEvents=batch
                    )
                except Exception as e:
                    print(f"Error sending logs to CloudWatch: {str(e)}")