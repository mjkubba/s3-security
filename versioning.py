"""DocString: Scan for buckets policies."""
from botocore.exceptions import ClientError


def get_bucket_versioning(bucket_name, s3client):
    """Get the bucket Versioning information."""
    try:
        versioning = s3client.get_bucket_versioning(Bucket=bucket_name)
        if "Status" in versioning:
            return(versioning["versioning"])
        else:
            return("Disabled")
    except ClientError as error:
        if "AccessDenied" in str(error):
            return("Access Denied")
        else:
            return("Access Error")
