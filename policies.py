"""DocString: Scan for buckets policies."""
import logging
import json
import sys
import boto3
import coloredlogs
from botocore.exceptions import ClientError
s3 = boto3.client('s3')
ec2 = boto3.client('ec2')


def set_logger():
    """Set the logger."""
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
    return slog


def check_input():
    """Check for inputs and exit if missing."""
    fix = False
    buck = False
    if '-f' in sys.argv:
        fix = True
    if '-b' in sys.argv:
        buck = sys.argv[sys.argv.index('-b') + 1]
    return(buck, fix)


def list_all_buckets():
    """List all buckets in the AWS account."""
    list_to_return = []
    test = s3.list_buckets()
    for bucket in test["Buckets"]:
        list_to_return.append(bucket["Name"])
    return list_to_return


def get_existing_policy(bucket_name):
    """Get the Existing policy if found."""
    try:
        policy = s3.get_bucket_policy(Bucket=bucket_name)
        return(True, policy)
    except ClientError as e:
        if "NoSuchBucketPolicy" in str(e):
            # print(bucket_name + ": No policy")
            return(False, "No policy")
        else:
            # print("Error: " + str(e))
            return(False, "Error Getting policy"+str(e))


def get_bucket_policy(bucket_name):
    """Get the bucket policy."""
    check, policy = get_existing_policy(bucket_name)
    if check:
        ssl, vpc, message = check_if_valid(policy)
        return(bucket_name, ssl, vpc, message)
    else:
        return(bucket_name, False, False, policy)


def check_if_valid(policy):
    """Check if a Policy is valid."""
    check_vpc = False
    check_ssl = False
    vpc_msg = ""
    ssl_msg = ""
    policy_json = json.loads(policy["Policy"])
    for statement in policy_json["Statement"]:
        condition = get_policy_condition(statement)
        if condition:
            ssl = check_if_ssl(condition)
            vpc = check_if_vpc(condition)
            if ssl:
                check_ssl = True
                ssl_msg = "SSL secured"
            if vpc:
                check_vpc = True
                vpc_msg = "VPC secured"
        else:
            # print("Not Secured, No condition")
            return(False, False, "Not Secured - No condition")
    if check_vpc and check_ssl:
        return(True, True, "All good")
    else:
        return(check_ssl, check_vpc, ssl_msg+" "+vpc_msg)


def get_policy_condition(statement):
    """Check if a a policy have a condition and return it."""
    if "Condition" in statement:
        return(statement["Condition"])
    else:
        # print("Not Secured, No condition")
        return(False)


def check_if_ssl(condition):
    """Check if a condition(policy) have SSL only enabled."""
    if "Bool" in condition:
        # print("Bool")
        if "aws:SecureTransport" in condition["Bool"]:
            # print("have a aws:SecureTransport")
            if condition["Bool"]["aws:SecureTransport"] == "false":
                # print("SSL Secured")
                return(True)
            else:
                # print("Not SSL Secured")
                return(False)
        else:
            return(False)
            # print("Not SSL Secured")
    else:
        # print("Not SSL Secured")
        return(False)


def check_if_vpc(condition):
    """Check if a condition(policy) have VPC-only source."""
    if "StringNotLike" in condition:
        # print("StringNotLike")
        if "aws:sourceVpc" in condition["StringNotLike"]:
            # print("have a aws:sourceVpc")
            # print("VPC Secured")
            return(True)
        else:
            # print("No aws:sourceVpc Policy")
            return(False)
    else:
        # print("no StringNotLike Policy")
        return(False)


def get_vpc_list():
    """Get list of VPCs."""
    vpc_list = []
    vpcs = ec2.describe_vpcs()
    for vpc in vpcs["Vpcs"]:
        vpc_list.append(vpc["VpcId"])
    return(vpc_list)


def fix_policy(bucket_name, ssl, vpc, message):
    """Fix the policy by adding the required part(s)."""
    check, policy = get_existing_policy(bucket_name)
    if check:
        policy_json = json.loads(policy["Policy"])
        if not ssl:
            new_policy = add_ssl_statement(bucket_name, policy_json)
            update_policy(bucket_name, new_policy)
            return(True)
        if not vpc:
            new_policy = add_vpc_statement(bucket_name, policy_json)
            update_policy(bucket_name, new_policy)
            return(True)
    else:
        if policy == "No policy":
            new_policy = constuct_policy(bucket_name)
            update_policy(bucket_name, new_policy)
            return(True)
        if "Error Getting policy" in policy:
            return(False)


def update_policy(bucket_name, new_policy):
    """Update the Policy in AWS."""
    try:
        s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(new_policy))
        return(True)
    except ClientError:
        return(False)


def constuct_policy(bucket):
    """Construct the policy from scratch."""
    policy_head = {
        "Version": "2012-10-17",
        "Statement": []
    }
    new_policy = add_vpc_statement(bucket, policy_head)
    new_policy = add_ssl_statement(bucket, new_policy)
    return(new_policy)


def add_vpc_statement(bucket, policy):
    """Add VPC statement to policy."""
    bucket_arn = "arn:aws:s3:::" + bucket
    bucket_arn_obj = "arn:aws:s3:::" + bucket + "/*"
    vpcs = get_vpc_list()
    vpc_statement = {
            "Sid": "VPCe and SourceIP",
            "Effect": "Deny",
            "Principal": "*",
            "Action": [
                "s3:DeleteObject",
                "s3:GetObject",
                "s3:PutObject",
                "s3:ReplicateObject"
            ],
            "Resource": [
                bucket_arn,
                bucket_arn_obj
            ],
            "Condition": {
                "StringNotLike": {
                    "aws:sourceVpc": vpcs
                }
            }
        }
    policy["Statement"].append(vpc_statement)
    return(policy)


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


def main():
    """Main."""
    bucket, fix = check_input()
    f = open("s3results.csv", "w")
    f.write("Bucket Name,SSL,VPC,Message\n")
    slog = set_logger()
    bucket_list = list_all_buckets()

    if bucket:
        if bucket in bucket_list:
            name, ssl, vpc, message = get_bucket_policy(bucket)
            slog.info(name + "," + str(ssl) + "," + str(vpc) + "," + message)
            f.write(name + "," + str(ssl) + "," + str(vpc) +
                    "," + message + "\n")
            if fix:
                if not ssl or not vpc:
                    slog.info("Fixing " + name + " Policy")
                    fix_policy(name, ssl, vpc, message)
                else:
                    slog.info("Policy is good, nothing to fix")
        else:
            slog.error("Bucket Not Found: " + bucket)
    else:
        num_buckets = len(bucket_list)
        counter = 1
        slog.info("Found: " + str(len(bucket_list)) + " Buckets")
        for bucket in bucket_list:
            name, ssl, vpc, message = get_bucket_policy(bucket)
            slog.info(str(counter) + " of " + str(num_buckets) + " " +
                      name + "," + str(ssl) + "," + str(vpc) + "," + message)
            f.write(name + "," + str(ssl) + "," + str(vpc) + "," +
                    message + "\n")
            counter = counter + 1
            if fix:
                if not ssl or not vpc:
                    slog.info("Fixing " + name + " Policy")
                    fix_policy(name, ssl, vpc, message)
                    f.write(name + "," + str(ssl) + "," + str(vpc) + "," +
                            "Policy Fixed" + "\n")
                else:
                    slog.info("Policy is good, nothing to fix")
    f.close()


def exit_gracefully():
    """Handle ctrl+c."""
    print("\n")
    print("Things should be logged in s3results.csv file")
    print("\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    finally:
        exit_gracefully()
