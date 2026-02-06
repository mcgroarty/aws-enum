"""SSO authentication handling."""

import configparser
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def get_sso_profile() -> str:
    """Get SSO profile from environment or default."""
    return os.environ.get("AWS_PROFILE", "default")


def _get_sso_profile_config(profile: str) -> tuple[Optional[str], Optional[str]]:
    """Return (sso_start_url, sso_region) for a profile from ~/.aws/config."""
    config_path = Path.home() / ".aws" / "config"
    if not config_path.exists():
        return None, None

    config = configparser.RawConfigParser()
    try:
        config.read(config_path)
    except configparser.Error:
        return None, None

    if profile == "default":
        section = "default"
    else:
        section = f"profile {profile}"
        # Note: skip has_section for "default" because configparser treats
        # [DEFAULT] (case-insensitive) as a magic section that doesn't appear
        # in has_section(). AWS uses [default] for the default profile.
        if not config.has_section(section):
            return None, None

    start_url = config.get(section, "sso_start_url", fallback=None)
    region = config.get(section, "sso_region", fallback=None)
    return start_url, region


def get_cached_access_token(profile: str) -> Optional[tuple[str, str]]:
    """Read valid access token from SSO cache.

    Returns:
        Tuple of (access_token, region) if found, None otherwise.
    """
    sso_cache_dir = Path.home() / ".aws" / "sso" / "cache"

    if not sso_cache_dir.exists():
        return None

    expected_start_url, expected_region = _get_sso_profile_config(profile)

    # Find the most recently modified valid token
    best_token = None
    best_mtime = 0

    for cache_file in sso_cache_dir.glob("*.json"):
        try:
            data = json.loads(cache_file.read_text())
            access_token = data.get("accessToken")
            expires_at = data.get("expiresAt")
            region = data.get("region", "us-east-1")
            start_url = data.get("startUrl")

            if not access_token or not expires_at:
                continue
            if expected_start_url and start_url != expected_start_url:
                continue
            if expected_region and region != expected_region:
                continue

            # Parse expiration and check validity
            exp_time = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            if exp_time > datetime.now(timezone.utc):
                mtime = cache_file.stat().st_mtime
                if mtime > best_mtime:
                    best_mtime = mtime
                    best_token = (access_token, region)
        except (json.JSONDecodeError, ValueError, KeyError):
            continue

    return best_token


def sso_login(profile: str) -> bool:
    """Initiate SSO login flow."""
    print(f"No valid SSO token found. Initiating login for profile '{profile}'...")
    result = subprocess.run(
        ["aws", "sso", "login", "--profile", profile], capture_output=False
    )
    return result.returncode == 0


def get_access_token(profile: str) -> tuple[str, str]:
    """Get valid access token, triggering login if needed.

    Returns:
        Tuple of (access_token, sso_region)
    """
    result = get_cached_access_token(profile)

    if result:
        return result

    if not sso_login(profile):
        print("ERROR: SSO login failed.", file=sys.stderr)
        sys.exit(1)

    result = get_cached_access_token(profile)
    if not result:
        print("ERROR: Still no valid token after login.", file=sys.stderr)
        sys.exit(1)

    return result
