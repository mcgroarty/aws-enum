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
