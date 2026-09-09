"""Demo fixture: a module GuardEnv should report as clean."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    database_url: str
    api_key: str
    region: str = "eu-west-1"

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            database_url=os.environ["DATABASE_URL"],
            api_key=os.environ["SERVICE_API_KEY"],
            region=os.environ.get("AWS_REGION", "eu-west-1"),
        )
