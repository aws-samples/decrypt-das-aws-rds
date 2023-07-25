from __future__ import print_function
import os
import json
import boto3
import base64
import zlib
import uuid
import aws_encryption_sdk
from requests_aws4auth import AWS4Auth
from opensearchpy import OpenSearch, RequestsHttpConnection
from aws_encryption_sdk import CommitmentPolicy
from aws_encryption_sdk.internal.crypto import WrappingKey
from aws_encryption_sdk.key_providers.raw import RawMasterKeyProvider
from aws_encryption_sdk.identifiers import WrappingAlgorithm, EncryptionKeyType

REGION_NAME = os.environ['AWS_REGION']
RESOURCE_ID = os.environ['resource_id']
OPENSEARCH_HOST = os.environ['opensearch_host']
OPENSEARCH_INDEX = os.environ['opensearch_index']
SECRET_NAME = os.environ['secret_name']

enc_client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
kms = boto3.client('kms', region_name=REGION_NAME)

#Function to get a secret from SecretsManager
def get_secret():
    session = boto3.session.Session()
    client = session.client(service_name='secretsmanager',region_name=REGION_NAME)
    get_secret_value_response = client.get_secret_value(SecretId=SECRET_NAME)
    return get_secret_value_response       

secret_string = json.loads(get_secret()['SecretString'])
auth = (secret_string['os.net.http.auth.user'], secret_string['os.net.http.auth.pass'])

#Signing HTTP requests to Amazon OpenSearch Service
search = OpenSearch(
    hosts = [{'host': OPENSEARCH_HOST, 'port': 443}],
    http_auth = auth,
    use_ssl = True,
    verify_certs = True,
    connection_class = RequestsHttpConnection
)

enc_client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
kms = boto3.client('kms', region_name=REGION_NAME)

# MasterPeyProvider class
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
    for record in event['Records']:
        data = base64.b64decode(record['kinesis']['data'])
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

       ## Filtering logic
        for dbEvent in events['databaseActivityEventList'][:]: 
            if dbEvent['type'] == "heartbeat" or (dbEvent['dbUserName'] and dbEvent["dbUserName"] in ("RDSADMIN","RDSSEC")):
                events['databaseActivityEventList'].remove(dbEvent)
    
        ## Ingest decrypted activities into opensearch
        ## Mapping document        
        index_mapping = {
            "settings": {
            "index": {
                "number_of_shards": 1,
                "number_of_replicas": 1
                    }
                }, 
            "mappings": {
                "properties": {
                    "logTime" : {
                        "type": "date",
                        "format": "yyyy-MM-dd HH:mm:ss||yyyy-MM-dd||epoch_millis"
                            },
                    "pid": {
                        "type": "keyword"
                            },
                    "dbUserName": {
                        "type": "keyword"
                        },
                    "databaseName": {
                        "type": "keyword"
                        },
	                "command": {
                        "type": "keyword"
                        },
                    "commandText": {
                        "type": "keyword"
		                },
                    "startTime" : {
                        "type": "date",
                        "format": "yyyy-MM-dd HH:mm:ss||yyyy-MM-dd||epoch_millis"
                        },
                    "endTime" : {
                        "type": "date",
                        "format": "yyyy-MM-dd HH:mm:ss||yyyy-MM-dd||epoch_millis"
                        }
                    }
                }
            }     
        
        ## create mapping if index doesn't exists 
        if not search.indices.exists(OPENSEARCH_INDEX):
            response = search.indices.create(OPENSEARCH_INDEX, body=index_mapping)
            print("New index with mapping created")
            print(response)

        ## create a dictionary which will be send to Opensearch 
        if len(events['databaseActivityEventList']) > 0:
            for dbEvent in events['databaseActivityEventList']:
                index_body = {}
                index_body['logTime'] = dbEvent['logTime'].split('.')[0].split('+')[0]
                index_body['pid'] = dbEvent['pid']
                index_body['dbUserName'] = dbEvent['dbUserName']
                index_body['databaseName'] = dbEvent['databaseName']
                index_body['command'] = dbEvent['command']
                index_body['commandText'] = dbEvent['commandText']
                if 'engineNativeAuditFields' in dbEvent:
                    index_body['engineNativeAuditFields'] = dbEvent['engineNativeAuditFields']
                if 'startTime' in dbEvent and dbEvent['startTime'] is not None:
                    index_body['startTime'] = dbEvent['startTime'].split('.')[0].split('+')[0]
                else:
                    index_body['startTime'] = None
                if 'endTime' in dbEvent and dbEvent['endTime'] is not None:
                    index_body['endTime'] = dbEvent['endTime'].split('.')[0].split('+')[0]
                else:
                    index_body['endTime'] = None
                search.index(index=OPENSEARCH_INDEX, doc_type="_doc", id=uuid.uuid4(), body=index_body)
