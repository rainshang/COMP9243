#!/usr/bin/python3
import os
import json
import boto3
import socket

DEBUG = True

DOMAIN = 'au.edu.unsw.comp9243.group4'
REGION = 'ap-southeast-2'

NAME_SQS = (DOMAIN + '.sqs.transcodetask').replace('.', '_')
TIMEOUT_SQS_MSG = '120'

NAME_BUCKET_INPUT = DOMAIN + '.bucket.input'
NAME_BUCKET_OUTPUT = DOMAIN + '.bucket.output'

NAME_SECURITY_GROUP = DOMAIN
INSTANCE_FILTER_GROUP = {
                'Name': 'instance.group-name',
                'Values': [
                    NAME_SECURITY_GROUP
                ]
            }

DEFAULT_AMI = 'ami-d38a4ab1' if DEBUG else 'ami–96666ff5'
__INSTANCE_TYPE = 't2.micro' if DEBUG else 't2.small'

__INSTANCE_TAG_TYPE = 'Type'
TYPE_CLIENT = 'Client'
TYPE_WATCHDOG = 'Watchdog'
TYPE_TRANSCODE_SERVICE = 'Transcode service'

__INSTANCE_TAG_STATUS = 'Status'
STATUS_IDLE = 'idle'
STATUS_TRANSCODING = 'transcoding...'

__CONFIG_FILE_NAME = 'setup.json'
CONFIG_KEYFILE_NAME = 'keyfile_name'
CONFIG_KEYID = 'aws_access_key_id'
CONFIG_KEY = 'aws_secret_access_key'
CONFIG_SQS_URL = 'sqs_url'
CONFIG_TRANSCODE_SERVICE_AMI = 'transcode_service_ami'

ASW_EC2_USER = 'ubuntu'
CMD_SSH = 'ssh -o StrictHostKeyChecking=no -o ConnectionAttempts=100 -i {pem} {user}@{host}' + (' > /dev/null 2>&1' if not DEBUG else '')
CMD_SCP_UPLOAD = 'scp -o StrictHostKeyChecking=no -o ConnectionAttempts=100 -i {pem} {source} {user}@{host}:{target}' + (' > /dev/null 2>&1' if not DEBUG else '')
CMD_CHMOD = 'chmod {mode} {file}'
CMD_INSTALL_PIP = 'curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py && sudo python3 get-pip.py && rm get-pip.py'
CMD_INSTALL_BOTO3 = 'sudo pip3 install boto3'
__FILE_INSTANCE_ID = 'instance_id'
CMD_SAVE_INSTANCE_ID = 'echo \'{instance_id}\' > ' + __FILE_INSTANCE_ID
CMD_INSTALL_TRANSCODE_SUPPORT = 'sudo apt-get update && sudo apt-get -y install imagemagick libav-tools'
CMD_CRON_TRANSCODE = 'crontab transcode.cron'

def add_config(new_dict):
    if not os.path.exists(__CONFIG_FILE_NAME):
        config = {}
    else:
        with open(__CONFIG_FILE_NAME) as config_file:
            config = json.load(config_file)
    config.update(new_dict)
    with open(__CONFIG_FILE_NAME, 'w') as config_file:
        json.dump(config, config_file)

def get_config():
    with open(__CONFIG_FILE_NAME) as config_file:
        return json.load(config_file)

def clear_config():
    os.remove(__CONFIG_FILE_NAME)

def get_pem_on_instance():
    return get_config()[CONFIG_KEYFILE_NAME] + '.pem'

def ssh_do_cmd(pem, host_instance, cmd):
    os.system(CMD_SSH.format(
        pem = pem,
        user = ASW_EC2_USER,
        host = host_instance.public_dns_name
        )
        + ' \'{}\''.format(cmd))

def scp_upload(pem, source, host_instance):
    os.system(CMD_SCP_UPLOAD.format(
        pem = pem,
        source = source,
        user = ASW_EC2_USER,
        host = host_instance.public_dns_name,
        target = ''
    ))

def upload_config_file(pem, host_instance):
    scp_upload(pem, __CONFIG_FILE_NAME, host_instance)
    ssh_do_cmd(pem, host_instance, CMD_CHMOD.format(mode = 600, file = __CONFIG_FILE_NAME))

def boto3_resource(service_name):
    config = get_config()
    return boto3.resource(service_name,
        aws_access_key_id = config[CONFIG_KEYID],
        aws_secret_access_key = config[CONFIG_KEY],
        region_name = REGION)

def boto3_client(service_name):
    config = get_config()
    return boto3.client(service_name,
        aws_access_key_id = config[CONFIG_KEYID],
        aws_secret_access_key = config[CONFIG_KEY],
        region_name = REGION)

def boto3_create_instance(ec2, ami, type):
    tags = [
        {
            'Key': __INSTANCE_TAG_TYPE,
            'Value': type
        }
    ]
    if type is TYPE_TRANSCODE_SERVICE:
        tags.append(
            {
                'Key': __INSTANCE_TAG_STATUS,
                'Value': STATUS_IDLE
            }
        )
    instance = ec2.create_instances(
        ImageId = ami,
        MaxCount = 1,
        MinCount = 1,
        KeyName = get_config()[CONFIG_KEYFILE_NAME],
        InstanceType = __INSTANCE_TYPE,
        SecurityGroups = [NAME_SECURITY_GROUP],
        TagSpecifications = [
            {
                'ResourceType': 'instance',
                'Tags': tags
            }
        ]
    )[0]
    instance.wait_until_running()
    instance = ec2.Instance(instance.instance_id)
    return instance

def boto3_get_instances(ec2, type):
    return list(ec2.instances.filter(
        Filters = [
            INSTANCE_FILTER_GROUP,
            {
                'Name': 'tag:' + __INSTANCE_TAG_TYPE,
                'Values': [
                    type
                ]
            }
        ]
    ))

def boto3_get_self_instance(ec2):
    with open(__FILE_INSTANCE_ID) as file:
        instance_id = file.readline().strip()
    return ec2.Instance(instance_id)

def boto3_get_self_status(ec2):
    self_instance = boto3_get_self_instance(ec2)
    for key_value in self_instance.tags:
        if key_value['Key'] == __INSTANCE_TAG_TYPE:
            if key_value['Value'] != TYPE_TRANSCODE_SERVICE:
                raise TypeError('Not a supported instance type')
        elif key_value['Key'] == __INSTANCE_TAG_STATUS:
            return key_value['Value']

def boto3_set_self_status(ec2, status):
    self_instance = boto3_get_self_instance(ec2)
    for key_value in self_instance.tags:
        if key_value['Key'] == __INSTANCE_TAG_TYPE:
            if key_value['Value'] != TYPE_TRANSCODE_SERVICE:
                raise TypeError('Not a supported instance type')
            else:
                self_instance.create_tags(
                    Tags = [
                        {
                            'Key': __INSTANCE_TAG_STATUS,
                            'Value': status
                        }
                    ]
                )
                return

def boto3_delete_snapshots(ec2, ami):
    for snapshot in ec2.snapshots.filter(OwnerIds = ['self']):
        if snapshot.description.find(ami) != -1:
            snapshot.delete()
    