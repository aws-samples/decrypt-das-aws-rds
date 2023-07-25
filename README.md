# Processing a database activity stream using the AWS SDK for Python

Amazon RDS pushes activities to an Amazon Kinesis data stream in near real time. The Kinesis stream is created automatically and it contains encrypted audit records.The same AWS KMS key that you supplied when you launched the database activity stream can be used to decrypt these database activities. 

In this section, there are two lambda functions:

1. **rds-das-decrypt-kinesis-firehose.py** - This lambda function get invoke by Kinesis Data Firehose as a part of Data Transformation to decrypt the audit records and deliver the transformed data to destinations such as Amazon S3, AWS Opensearch, Splunk.
    
2. **rds-das-decrypt-kinesis-opensearch.py** - This lambda function decodes and decrypts the database activities using the KMS key you provided when starting the database activity stream, filters heartbeat events and any of the events that belong to the 'rdsadmin' and 'rdssec' users, flattens the array of database activities events into individual rows, creates an opensearch index with mapping and ingests records into Amazon Opensearch Service using signing HTTP request. 

### Prerequisites


You need to create a lambda layer to package libraries and other dependencies that you require to execute Lambda functions. To construct a lambda layer with the necessary dependencies like PyCrypto, aws-encryption-sdk, opensearch-py, requests-aws4auth, and cryptography, you can run the commands listed below in a Cloud9 environment.

```
mkdir -p das-rds && cd das-rds
python3 -m venv .venv
source ./.venv/bin/activate
pip3 install PyCrypto aws-encryption-sdk opensearch-py requests-aws4auth cryptography==3.4.8
deactivate
mkdir -p python && cd python
cp -r ../.venv/lib64/python3.7/site-packages/* .
cd ..
zip -r das_layer.zip python
aws lambda publish-layer-version --layer-name das-encryption --zip-file fileb://das_layer.zip --compatible-runtimes python3.9
```

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.