"""DocString: Scan for buckets policies."""

from botocore.exceptions import ClientError


def get_bucket_versioning(bucket_name, s3, logger):
    """Get the bucket versioning."""
    try:
        versioning = s3.BucketVersioning(bucket_name)
    except ClientError as e:
        logger.error(versioning, str(e))
    return str(versioning.status)


def set_bucket_versioning(bucket_name, s3, logger):
    """Get the bucket versioning."""
    try:
        versioning = s3.BucketVersioning(bucket_name)
    except ClientError as e:
        logger.error(versioning, str(e))
    versioning.enable()
    versioning.reload()
    return str(versioning.status)
