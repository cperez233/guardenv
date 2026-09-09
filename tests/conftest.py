"""Shared fixtures.

Every credential in this directory is synthetic. Where a real provider embeds a
checksum (GitHub), the fixture is generated so the checksum is genuinely valid -
otherwise the validator tests would be meaningless.
"""

from __future__ import annotations

import zlib

import pytest

from guardenv.scanner import Scanner, ScanOptions

_BASE62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _base62_encode(number: int, width: int) -> str:
    digits = ""
    while number:
        number, remainder = divmod(number, 62)
        digits = _BASE62[remainder] + digits
    return digits.rjust(width, "0")


def make_github_token(prefix: str = "ghp", payload: str = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5") -> str:
    """Build a syntactically valid GitHub token with a correct CRC32 checksum."""
    assert len(payload) == 30, "GitHub tokens carry exactly 30 payload characters"
    checksum = _base62_encode(zlib.crc32(payload.encode("ascii")), 6)
    return f"{prefix}_{payload}{checksum}"


@pytest.fixture
def scanner() -> Scanner:
    return Scanner(ScanOptions())


@pytest.fixture
def rules_only_scanner() -> Scanner:
    return Scanner(ScanOptions(enable_entropy=False))


@pytest.fixture
def entropy_only_scanner() -> Scanner:
    return Scanner(ScanOptions(enable_rules=False))


@pytest.fixture
def leaky_env() -> str:
    return (
        "APP_ENV=production\n"
        "AWS_ACCESS_KEY_ID=AKIAZ4KJQ2WBXY7TDNPQ\n"
        'AWS_SECRET_ACCESS_KEY="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"\n'
        "DATABASE_URL=postgresql://svc:Tr0ub4dor3xK@db.internal:5432/billing\n"
        "DEBUG=false\n"
    )
