"""DocString: Scan for open buckets."""
import logging
import sys
import boto3
import re
import coloredlogs
import requests
import signal
from botocore.exceptions import ClientError, NoCredentialsError
from botocore.exceptions import HTTPClientError
from botocore.client import Config
from botocore import UNSIGNED


class TimeoutException(Exception):
    """."""

    pass


SIZE_CHECK_TIMEOUT = 30
file = ""
buck = ""
auto = False
AWS_CREDS_CONFIGURED = True


def time_limit(seconds):
    """."""
    def signal_handler(signum, frame):
        raise TimeoutException("Timed out!")
    signal.signal(signal.SIGALRM, signal_handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)


def check_input():
    """Check for inputs and exit if missing."""
    if '-f' in sys.argv:
        global file
        file = sys.argv[sys.argv.index('-f') + 1]
    elif '-s' in sys.argv:
        global buck
        buck = sys.argv[sys.argv.index('-s') + 1]
    else:
        global auto
        auto = True


def checkAwsCreds(slog):
    """Check to see if the user has credentials for AWS properly configured."""
    sts = boto3.client('sts')
    try:
        sts.get_caller_identity()
    except NoCredentialsError:
        global AWS_CREDS_CONFIGURED
        AWS_CREDS_CONFIGURED = False
        cred_error = "Warning: AWS credentials not configured."
        cred_error = cred_error + " Open buckets will be shown as closed. Run:"
        cred_error = cred_error + " `aws configure` to fix this.\n"
        slog.error(cred_error)
        return False
    except ClientError as e:
        if "ExpiredToken" in str(e):
            AWS_CREDS_CONFIGURED = False
            slog.error("AWS Token Expired")
            return False
    return True


def set_logger():
    """Set the logger."""
    flog = logging.getLogger('s3scanner-file')
    flog.setLevel(logging.DEBUG)

    fh = logging.FileHandler("buckets.txt")
    fh.setLevel(logging.DEBUG)

    flog.addHandler(fh)

    slog = logging.getLogger('s3scanner-screen')
    slog.setLevel(logging.INFO)

    levelStyles = {
            'info': {'color': 'cyan'},
            'warning': {'color': 'yellow'},
            'error': {'color': 'red'}
            }

    fieldStyles = {
            'asctime': {'color': 'white'}
            }

    coloredlogs.install(level='DEBUG', logger=slog,
                        fmt='%(asctime)s   %(message)s',
                        level_styles=levelStyles, field_styles=fieldStyles)
    return slog, flog


def checkBucketName(bucket_name):
    """Check to make sure bucket names input are valid.

    :param bucketName: Name of bucket to check
    :return: Boolean - whether or not the name is valid.
    """
    # Bucket names can be 3-63 (inclusively) characters long.
    # Bucket names may only contain lowercase letters, numbers,
    # periods, and hyphens
    pattern = r'(?=^.{3,63}$)(?!^(\d+\.)+\d+$)(^(([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])\.)*([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])$)'

    return bool(re.match(pattern, bucket_name))


def checkAcl(bucket):
    """
    Attempt to retrieve a bucket's ACL. This also functions as the main 'check if bucket exists' function.

    By trying to get the ACL, we combine 2 steps to minimize potentially slow network calls.
    :param bucket: Name of bucket to try to get the ACL of
    :return: A dictionary with 2 entries:
        found - Boolean. True/False whether or not the bucket was found
        acls - dictionary. If ACL was retrieved, contains 2 keys: 'allUsers' and 'authUsers'. If ACL was not
                            retrieved,
    """
    allUsersGrants = []
    authUsersGrants = []

    s3 = boto3.resource('s3')

    try:
        bucket_acl = s3.BucketAcl(bucket)
        bucket_acl.load()
    except s3.meta.client.exceptions.NoSuchBucket:
        return {"found": False, "acls": {}}

    except ClientError as e:
        if e.response['Error']['Code'] == "AccessDenied":
            return {"found": True, "acls": "AccessDenied"}
        elif e.response['Error']['Code'] == "AllAccessDisabled":
            return {"found": True, "acls": "AllAccessDisabled"}
        else:
            raise e
    all_users = "http://acs.amazonaws.com/groups/global/AllUsers"
    auth_users = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
    for grant in bucket_acl.grants:
        if 'URI' in grant['Grantee']:
            if grant['Grantee']['URI'] == all_users:
                allUsersGrants.append(grant['Permission'])
            elif grant['Grantee']['URI'] == auth_users:
                authUsersGrants.append(grant['Permission'])

    return {"found": True, "acls": {"allUsers": allUsersGrants,
                                    "authUsers": authUsersGrants}}


def checkBucketWithoutCreds(bucketName, triesLeft=2):
    """Check with REST and check the results."""
    if triesLeft == 0:
        return False

    bucketUrl = 'http://' + bucketName + '.s3.amazonaws.com'

    r = requests.head(bucketUrl)

    if r.status_code == 200:    # Successfully found a bucket!
        return True
    elif r.status_code == 403:  # Bucket exists,but not allowed to LIST it.
        return True
    elif r.status_code == 404:  # This is definitely not a valid bucket name.
        return False
    elif r.status_code == 503:
        return checkBucketWithoutCreds(bucketName, triesLeft - 1)
    else:
        raise ValueError("Got an unhandled status code back: " +
                         str(r.status_code) + " for bucket: " + bucketName +
                         ". Please open an issue at: https://github.allstate.com/cloud-engineering/s3-tools/issues and include this info.")


def getBucketSize(bucketName):
    """
    Use awscli to 'ls' the bucket which will give us the total size of the bucket.
    NOTE:
        Function assumes the bucket exists and doesn't catch errors if it doesn't.
    """
    s3 = boto3.client('s3')
    try:
        if AWS_CREDS_CONFIGURED is False:
            s3 = boto3.client('s3', config=Config(signature_version=UNSIGNED))
        size_bytes = 0
        # time_limit(SIZE_CHECK_TIMEOUT):
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucketName):
            if 'Contents' in page:
                for item in page['Contents']:
                    size_bytes += item['Size']
        return str(size_bytes) + " bytes"

    except TimeoutException as e:
        return "Unknown Size - timeout"
    except HTTPClientError as e:
        if "Timed out!" in str(e):
            return "Unknown Size - timeout"
        else:
            raise e
    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDenied':
            return "AccessDenied"
        elif e.response['Error']['Code'] == 'AllAccessDisabled':
            return "AllAccessDisabled"
        elif e.response['Error']['Code'] == 'NoSuchBucket':
            return "NoSuchBucket"
        else:
            raise e


def checkBucket(inBucket, slog, flog, argsDump, argsList):
    """Check if the bucket is open."""
    # Determine what kind of input we're given. Options:
    #   bucket name   i.e. mybucket
    #   domain name   i.e. flaws.cloud
    #   full S3 url   i.e. flaws.cloud.s3-us-west-2.amazonaws.com
    #   bucket:region i.e. flaws.cloud:us-west-2

    if ".amazonaws.com" in inBucket:    # We were given a full s3 url
        bucket = inBucket[:inBucket.rfind(".s3")]
    elif ":" in inBucket:    # We were given a bucket in 'bucket:region' format
        bucket = inBucket.split(":")[0]
    else:                   # We were either given a bucket name or domain name
        bucket = inBucket

    valid = checkBucketName(bucket)

    if not valid:
        message = "{0:>11} : {1}".format("[invalid]", bucket)
        slog.error(message)
        # continue
        return

    if AWS_CREDS_CONFIGURED:
        b = checkAcl(bucket)
    else:
        a = checkBucketWithoutCreds(bucket)
        b = {"found": a, "acls": "unknown - no aws creds"}
    # a = checkBucketWithoutCreds(bucket)
    # b = {"found": a, "acls": "unknown - no aws creds"}

    if b["found"]:
        size = getBucketSize(bucket)  # Try to get the size of the bucket
        # size = 0

        message = "{0:>11} : {1}".format("[found]", bucket + " | "
                                                           + str(size)
                                                           + " | ACLs: "
                                                           + str(b["acls"]))
        slog.info(message)
        flog.debug(bucket)
    else:
        message = "{0:>11} : {1}".format("[not found]", bucket)
        slog.error(message)


def list_all_buckets():
    """List all buckets in the AWS account."""
    list_to_return = []
    s3 = boto3.client('s3')
    test = s3.list_buckets()
    for bucket in test["Buckets"]:
        list_to_return.append(bucket["Name"])
    return list_to_return


def main():
    """Main."""
    check_input()

    slog, flog = set_logger()
    checkAwsCreds(slog)
    if not auto:
        if file != "":
            with open(file, 'r') as f:
                for line in f:
                    line = line.rstrip()          # Remove any extra whitespace
                    checkBucket(line, slog, flog, False, False)
        elif buck != "":
            checkBucket(buck, slog, flog, False, False)
    else:
        if not AWS_CREDS_CONFIGURED:
            sys.exit(1)
        bucket_list = list_all_buckets()
        slog.info("found: " + str(len(bucket_list)) + " buckets")
        for bucket in bucket_list:
            checkBucket(bucket, slog, flog, False, False)


if __name__ == "__main__":
    main()
