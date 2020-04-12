"""DocString: Scan for buckets policies."""

from botocore.exceptions import ClientError


def get_bucket_versioning(bucket_name, s3, logger):
    """Get the bucket versioning."""
    try:
        versioning = s3.get_bucket_versioning(Bucket=bucket_name)
    except ClientError as e:
        logger.error(versioning, str(e))
    if "Status" in versioning:
        if versioning["Status"] == "Suspended":
            return "Suspended"
        elif versioning["Status"] == "Enabled":
            return "Enabled"
    else:
        return "None"
