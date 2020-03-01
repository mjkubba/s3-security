"""DocString: Scan for buckets policies."""
from botocore.exceptions import ClientError


def get_bucket_versioning(bucket_name, s3client):
    try:
        versioning = s3client.get_bucket_versioning(Bucket=bucket_name)
        print(versioning)
    except ClientError as error:
        if "AccessDenied" in str(error):
            print("No access to bucket: " + bucket_name)
        else:
            print(str(error))
