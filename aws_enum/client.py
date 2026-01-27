"""boto3 client management with thread-local caching."""

import threading

import boto3
from botocore.config import Config

# boto3 client config with retries
BOTO_CONFIG = Config(retries={"max_attempts": 3, "mode": "adaptive"})

# Global SSO region (set when token is loaded)
_sso_region = "us-east-1"
_thread_local = threading.local()  # Thread-local storage for clients


def set_sso_region(region: str):
    """Set the SSO region for boto3 clients."""
    global _sso_region
    _sso_region = region


def get_sso_client():
    """Get or create a thread-local boto3 SSO client."""
    if not hasattr(_thread_local, "sso_client"):
        _thread_local.sso_client = boto3.client(
            "sso", region_name=_sso_region, config=BOTO_CONFIG
        )
    return _thread_local.sso_client


def get_client_with_credentials(
    service: str, credentials: dict, region: str | None = None
):
    """Create a boto3 client using assumed-role credentials.

    Args:
        service: AWS service name (e.g., 'route53', 'elbv2')
        credentials: Credentials dict from get_role_credentials()
        region: AWS region (optional for global services like Route53)
    """
    return boto3.client(
        service,
        region_name=region,
        aws_access_key_id=credentials["accessKeyId"],
        aws_secret_access_key=credentials["secretAccessKey"],
        aws_session_token=credentials["sessionToken"],
        config=BOTO_CONFIG,
    )
