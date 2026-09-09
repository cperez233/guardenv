"""Demo fixture: a service module with credentials hardcoded by mistake."""

import os

import httpx

GITHUB_TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"
SLACK_WEBHOOK = "https://hooks.slack.com/services/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"

# Correct pattern: read from the environment, never inline.
SENTRY_DSN = os.environ["SENTRY_DSN"]


def notify(message: str) -> None:
    httpx.post(SLACK_WEBHOOK, json={"text": message}, timeout=5.0)


def open_pull_request(repo: str, title: str) -> httpx.Response:
    return httpx.post(
        f"https://api.github.com/repos/{repo}/pulls",
        headers={"Authorization": f"Bearer {GITHUB_TOKEN}"},
        json={"title": title, "head": "feature", "base": "main"},
        timeout=10.0,
    )
