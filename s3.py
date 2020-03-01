
import logging
import sys
import coloredlogs
import boto3
from versioning import get_bucket_versioning


def set_logger():
    """Set the logger."""
    slog = logging.getLogger('s3scanner-screen')
    slog.setLevel(logging.INFO)

    level_styles = {
        'info': {'color': 'cyan'},
        'warning': {'color': 'yellow'},
        'error': {'color': 'red'}
        }

    field_styles = {
        'asctime': {'color': 'white'}
        }

    coloredlogs.install(level='DEBUG', logger=slog,
                        fmt='%(asctime)s   %(message)s',
                        level_styles=level_styles, field_styles=field_styles)
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


def list_all_buckets(s3client):
    """List all buckets in the AWS account."""
    list_to_return = []
    test = s3client.list_buckets()
    for bucket in test["Buckets"]:
        list_to_return.append(bucket["Name"])
    return list_to_return


def main():
    """Main."""
    s3client = boto3.client('s3')
    bucket, _ = check_input()
    results_file = open("s3results.csv", "w")
    results_file.write("Bucket Name,Versioning\n")
    slog = set_logger()
    bucket_list = list_all_buckets(s3client)

    if bucket:
        if bucket in bucket_list:
            get_bucket_versioning(bucket, s3client)
        else:
            slog.error("Bucket Not Found: %s", bucket)
    else:
        num_buckets = len(bucket_list)
        counter = 1
        slog.info("Found: %d Buckets", num_buckets)
        for bucket in bucket_list:
            versioning = get_bucket_versioning(bucket, s3client)
            print(versioning)
            slog.info("%d of %d", counter, num_buckets)
            results_file.write(bucket + "," + str(versioning) + "\n")
            counter = counter + 1
        #     if fix:
        #         if not ssl or not vpc:
        #             slog.info("Fixing " + name + " Policy")
        #             fix_policy(name, ssl, vpc, message)
        #             results_file.write("%d of %d", counter, num_buckets)
        #         else:
        #             slog.info("Policy is good, nothing to fix")
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
