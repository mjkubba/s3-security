"""DocString: Scan for buckets policies."""
import logging
import json
import sys
import boto3
import coloredlogs
from botocore.exceptions import ClientError
s3 = boto3.client('s3')


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


def get_bucket_versioning(bucket_name):
    try:
        versioning = s3.get_bucket_versioning(Bucket=bucket_name)
    except ClientError as e:
        print(versioning)
    print(versioning)


def main():
    """Main."""
    bucket, fix = check_input()
    f = open("s3Versioning.csv", "w")
    f.write("Bucket Name,Versioning\n")
    slog = set_logger()
    bucket_list = list_all_buckets()

    if bucket:
        if bucket in bucket_list:
            get_bucket_versioning(bucket)
        else:
            slog.error("Bucket Not Found: " + bucket)
    else:
        num_buckets = len(bucket_list)
        counter = 1
        slog.info("Found: " + str(len(bucket_list)) + " Buckets")
        for bucket in bucket_list:
            get_bucket_versioning(bucket)
        #     name, ssl, vpc, message = get_bucket_policy(bucket)
        #     slog.info(str(counter) + " of " + str(num_buckets) + " " +
        #               name + "," + str(ssl) + "," + str(vpc) + "," + message)
        #     f.write(name + "," + str(ssl) + "," + str(vpc) + "," +
        #             message + "\n")
            counter = counter + 1
        #     if fix:
        #         if not ssl or not vpc:
        #             slog.info("Fixing " + name + " Policy")
        #             fix_policy(name, ssl, vpc, message)
        #             f.write(name + "," + str(ssl) + "," + str(vpc) + "," +
        #                     "Policy Fixed" + "\n")
        #         else:
        #             slog.info("Policy is good, nothing to fix")
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
