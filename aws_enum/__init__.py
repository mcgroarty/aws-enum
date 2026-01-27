"""AWS Resource Enumeration Tool.

Enumerates various AWS resources across all AWS accounts accessible via AWS SSO.
"""

from .cli import main

__all__ = ["main"]
