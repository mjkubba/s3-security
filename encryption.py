"""DocString: Scan for buckets policies."""

from botocore.exceptions import ClientError


def set_bucket_encryption(bucket_name, s3, logger):
    """Add AES256 encryption to the bucket."""

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
        return "Encrypted"
    except ClientError:
        return "Not-Encrypted"


def get_bucket_encryption(bucket_name, s3, logger):
    """Find id the bucket is NON-COMPLIANT."""
    try:
        encryption = s3.get_bucket_encryption(
          Bucket=str(bucket_name)
        )
        return "Encrypted"
    except ClientError as e:
        if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
            return "Not-Encrypted"
        else:
            return "Cannot determine encryption"
