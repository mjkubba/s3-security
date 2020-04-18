"""DocString: Scan for buckets policies, versioning and encryption."""
import logging
import sys
import coloredlogs
import boto3
from versioning import get_bucket_versioning, set_bucket_versioning
from encryption import get_bucket_encryption, set_bucket_encryption
from policies import get_bucket_policy, set_bucket_policy


def set_logger():
    """Set the logger."""
    logger = logging.getLogger('s3scanner-screen')
    logger.setLevel(logging.INFO)

    level_styles = {
        'info': {'color': 'cyan'},
        'warning': {'color': 'yellow'},
        'error': {'color': 'red'}
        }

    field_styles = {
        'asctime': {'color': 'white'}
        }

    coloredlogs.install(level='DEBUG', logger=logger,
                        fmt='%(asctime)s   %(message)s',
                        level_styles=level_styles, field_styles=field_styles)
    return logger


def check_input():
    """Check for inputs and exit if missing."""
    fix = False
    buck = False
    if '-f' in sys.argv:
        fix = True
    if '-b' in sys.argv:
        buck = sys.argv[sys.argv.index('-b') + 1]
    return(buck, fix)


def list_all_buckets(s3client):
    """List all buckets in the AWS account."""
    list_to_return = []
    test = s3client.list_buckets()
    for bucket in test["Buckets"]:
        list_to_return.append(bucket["Name"])
    return list_to_return


def versioning(bucket, s3resource, logger, fix):
    """Check and enable versioning."""
    versioning = get_bucket_versioning(bucket, s3resource, logger)
    logger.info(bucket + " versioning is " + versioning)
    if fix:
        versioning = set_bucket_versioning(bucket, s3resource, logger)
        logger.info(bucket + " versioning is now " + versioning)
    return versioning


def encryption(bucket, s3client, logger, fix):
    """Check and Enable Encryption."""
    enc = get_bucket_encryption(bucket, s3client, logger)
    logger.info(bucket + " encryption is " + enc)
    if fix:
        enc = set_bucket_encryption(bucket, s3client, logger)
        logger.info(bucket + " encryption is now " + enc)
    return enc


def policies(bucket, s3client, logger, fix):
    """Check and Enable Encryption."""
    pol = get_bucket_policy(bucket, s3client)
    logger.info(bucket + " policy is " + pol[2])
    if fix:
        pol = set_bucket_policy(bucket, s3client)
        logger.info(bucket + " policy is now " + pol[2])
    return pol[2]


def main():
    """Main."""
    s3client = boto3.client('s3')
    s3resource = boto3.resource('s3')
    bucket, fix = check_input()
    results_file = open("s3results.csv", "w")
    results_file.write("Bucket Name,Versioning,Encryption\n")
    logger = set_logger()
    bucket_list = list_all_buckets(s3client)

    if bucket:
        if bucket in bucket_list:
            ver = versioning(bucket, s3resource, logger, fix)
            enc = encryption(bucket, s3client, logger, fix)
            pol = policies(bucket, s3client, logger, fix)
            results_file.write(bucket + "," + ver +
                               "," + enc + "," + pol + "\n")
        else:
            logger.error("Bucket Not Found: %s", bucket)
    else:
        num_buckets = len(bucket_list)
        counter = 1
        logger.info("Found: %d Buckets", num_buckets)
        for bucket in bucket_list:
            ver = versioning(bucket, s3resource, logger, fix, results_file)
            enc = encryption(bucket, s3client, logger, fix, results_file)
            logger.info("%d of %d", counter, num_buckets)
            counter = counter + 1
            results_file.write(bucket + "," + ver +
                               "," + enc + "," + pol + "\n")
    results_file.close()


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
