"""DocString: Scan for buckets encryption."""
import boto3
import sys
import logging
import coloredlogs
from botocore.exceptions import ClientError

logger = logging.getLogger()

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


def encrypt_bucket(bucket_name):
    """Add AES256 encryption to the bucket."""
    global s3
    global logger
    global required_tags

    result = False
    try:
        s3.put_bucket_encryption(
          Bucket=bucket_name,
          ServerSideEncryptionConfiguration={
            'Rules': [
                    {
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'AES256'
                        }
                    },
                ]
            }
        )
        result = True
    except ClientError:
        result = False

    return result


def find_violation(bucket_name, remediate=False):
    """Find id the bucket is NON-COMPLIANT."""
    result = 'COMPLIANT'
    is_compliant = False
    is_remediated = False
    try:
        s3.get_bucket_encryption(
          Bucket=str(bucket_name)
        )
        is_compliant = True
    except ClientError:
        logger.info('Failed to obtain encryption')
        is_compliant = False
    if not is_compliant:
        logger.info('Encryption is missing.')
        if remediate:
            logger.info('S3 Encryption will be updated ')
            is_remediated = encrypt_bucket(bucket_name)
        if not is_remediated:
            result = 'NON_COMPLIANT'
    return result


def list_all_buckets():
    """List all buckets in the AWS account."""
    list_to_return = []
    test = s3.list_buckets()
    for bucket in test["Buckets"]:
        list_to_return.append(bucket["Name"])
    return list_to_return


def check_input():
    """Check for inputs and exit if missing."""
    fix = False
    buck = False
    if '-f' in sys.argv:
        fix = True
    if '-b' in sys.argv:
        buck = sys.argv[sys.argv.index('-b') + 1]
    return(buck, fix)


def main():
    """Main."""
    bucket, fix = check_input()
    f = open("S3EncResults.csv", "w")
    f.write("Bucket Name,Encryption\n")
    slog = set_logger()
    bucket_list = list_all_buckets()

    if bucket:
        if bucket in bucket_list:
            result = find_violation(bucket, fix)
            slog.info(bucket + "," + result)
            f.write(bucket + "," + result + "\n")
        else:
            slog.error("Bucket Not Found: " + bucket)
    else:
        num_buckets = len(bucket_list)
        counter = 1
        slog.info("Found: " + str(len(bucket_list)) + " Buckets")
        for bucket in bucket_list:
            result = find_violation(bucket, fix)
            slog.info(str(counter) + " of " + str(num_buckets) + " " +
                      bucket + "," + result)
            f.write(bucket + "," + result + "\n")
            counter = counter + 1
    f.close()


def exit_gracefully():
    """Handle ctrl+c."""
    print("\n")
    print("Things should be logged in S3EncResults.csv file")
    print("\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    finally:
        exit_gracefully()
