#!/usr/bin/python3
import importlib
import os
import json

DOMAIN = 'au.edu.unsw.comp9243.group4'
NAME_BUCKET_INPUT = DOMAIN + '.bucket.input'
NAME_BUCKET_OUTPUT = DOMAIN + '.bucket.output'
REGION = 'ap-southeast-2'
NAME_SQS = DOMAIN + '.sqs'
TIMEOUT_SQS_MSG = '120'

__KEY_AWS_KEYFILE = 'keyfile'
__KEY_AWS_ID = 'aws_access_key_id'
__KEY_AWS_KEY = 'aws_secret_access_key'

def __checkBoto3():
    if importlib.util.find_spec('boto3') is None:
        # use pip to install boto3
        os.system('pip3 install boto3')

def saveConfig(keyfile, aws_access_key_id, aws_secret_access_key):
    content = {
        __KEY_AWS_KEYFILE: keyfile,
        __KEY_AWS_ID: aws_access_key_id,
        __KEY_AWS_KEY: aws_secret_access_key
    }
    with open('config.json', 'w') as configFile:
        json.dump(content, configFile)

def getConfig():
    with open('config.json') as configFile:
        return json.load(configFile)

def boto3Resource(service_name):
    __checkBoto3()
    import boto3
    with open('config.json') as configFile:
        config = json.load(configFile)
    return boto3.resource(service_name,
            aws_access_key_id = config[__KEY_AWS_ID],
            aws_secret_access_key = config[__KEY_AWS_KEY],
            region_name = REGION)