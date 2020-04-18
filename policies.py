"""DocString: Scan for buckets policies."""
from botocore.exceptions import ClientError
import json


def get_bucket_policy(bucket_name, s3client):
    """Get the bucket policy, Entry Function."""
    check, policy = get_existing_policy(bucket_name, s3client)
    if check:
        ssl, message = check_if_valid(policy)
        return(bucket_name, ssl, message)
    else:
        return(bucket_name, False, policy)


def get_existing_policy(bucket_name, s3client):
    """Get the Existing policy if found."""
    try:
        policy = s3client.get_bucket_policy(Bucket=bucket_name)
        return(True, policy)
    except ClientError as e:
        if "NoSuchBucketPolicy" in str(e):
            return(False, "No policy")
        else:
            return(False, "Error Getting policy"+str(e))


def check_if_valid(policy):
    """Check if a Policy is valid."""
    check_ssl = False
    ssl_msg = ""
    policy_json = json.loads(policy["Policy"])
    for statement in policy_json["Statement"]:
        condition = get_policy_condition(statement)
        if condition:
            ssl = check_if_ssl(condition)
            if ssl:
                check_ssl = True
                ssl_msg = "SSL secured"
        else:
            return(False, "Not Secured - No condition")
    return(check_ssl, ssl_msg)


def get_policy_condition(statement):
    """Check if a a policy have a condition and return it."""
    if "Condition" in statement:
        return(statement["Condition"])
    else:
        return(False)


def check_if_ssl(condition):
    """Check if a condition(policy) have SSL only enabled."""
    if "Bool" in condition:
        if "aws:SecureTransport" in condition["Bool"]:
            if condition["Bool"]["aws:SecureTransport"] == "false":
                return(True)
            else:
                return(False)
        else:
            return(False)
    else:
        return(False)


def set_bucket_policy(bucket_name, s3client):
    """Fix the policy by adding the required part(s)."""
    check, policy = get_existing_policy(bucket_name, s3client)
    if check:   # I have a policy
        policy_json = json.loads(policy["Policy"])
        new_policy = add_ssl_statement(bucket_name, policy_json)
        update_policy(bucket_name, new_policy, s3client)
        return(bucket_name, True, "SSL secured")
    else:   # I dont have a policy
        if policy == "No policy":
            new_policy = constuct_policy(bucket_name)
            update_policy(bucket_name, new_policy, s3client)
            return(bucket_name, True, "SSL secured")
        if "Error Getting policy" in policy:
            return(bucket_name, False, "Not secured")


def update_policy(bucket_name, new_policy, s3client):
    """Update the Policy in AWS."""
    try:
        s3client.put_bucket_policy(Bucket=bucket_name,
                                   Policy=json.dumps(new_policy))
        return(True)
    except ClientError:
        return(False)


def constuct_policy(bucket):
    """Construct the policy from scratch."""
    policy_head = {
        "Version": "2012-10-17",
        "Statement": []
    }
    new_policy = add_ssl_statement(bucket, policy_head)
    return(new_policy)


def add_ssl_statement(bucket, policy):
    """Add SSL statement to policy."""
    bucket_arn_obj = "arn:aws:s3:::" + bucket + "/*"
    ssl_statement = {
        "Effect": "Deny",
        "Principal": "*",
        "Action": "*",
        "Resource": bucket_arn_obj,
        "Condition": {
            "Bool": {
                "aws:SecureTransport": "false"
            }
        }
    }
    policy["Statement"].append(ssl_statement)
    return(policy)
