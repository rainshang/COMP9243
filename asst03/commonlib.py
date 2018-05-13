#!/usr/bin/python3
import importlib
import os
import json

DOMAIN = 'au.edu.unsw.comp9243.group4'
NAME_BUCKET_INPUT = DOMAIN + '.bucket.input'
NAME_BUCKET_OUTPUT = DOMAIN + '.bucket.output'
REGION = 'ap-southeast-2'
NAME_SQS = (DOMAIN + '.sqs.transcodetask').replace('.', '_')
TIMEOUT_SQS_MSG = '120'

__CONFIG_FILE_NAME = 'setup.json'
CONFIG_KEYFILE = 'keyfile'
CONFIG_KEYID = 'aws_access_key_id'
CONFIG_KEY = 'aws_secret_access_key'
CONFIG_SQS_URL = 'sqs_url'

def __checkBoto3():
    if importlib.util.find_spec('boto3') is None:
        # use pip to install boto3
        os.system('pip3 install boto3')

def addConfig(newDict):
    with open(__CONFIG_FILE_NAME, 'w+') as configFile:
        try:
            config = json.load(configFile)
        except json.decoder.JSONDecodeError:
            config = {}
    config.update(newDict)
    with open(__CONFIG_FILE_NAME, 'w') as configFile:
        json.dump(config, configFile)

def getConfig():
    with open(__CONFIG_FILE_NAME) as configFile:
        return json.load(configFile)

def boto3Resource(service_name):
    __checkBoto3()
    import boto3
    config = getConfig()
    return boto3.resource(service_name,
            aws_access_key_id = config[CONFIG_KEYID],
            aws_secret_access_key = config[CONFIG_KEY],
            region_name = REGION)