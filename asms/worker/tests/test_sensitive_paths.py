"""Tests for the sensitive-paths probe (mocked HTTP)."""

from __future__ import annotations

import httpx
import pytest
import respx

from asms_worker.checks.base import CheckContext
from asms_worker.checks.sensitive_paths import SensitivePathsCheck


@pytest.fixture
def ctx() -> CheckContext:
    return CheckContext(url="https://target.example/app/", method="GET")


def test_exposed_git_repo_is_critical(ctx):
    with respx.mock(assert_all_called=False) as mock:
        for probe in [
            ".git/HEAD",
            ".env",
            ".DS_Store",
            "wp-config.php.bak",
            "phpinfo.php",
            "server-status",
            "actuator/env",
        ]:
            mock.get(f"https://target.example/app/{probe}").mock(
                return_value=httpx.Response(404, text="Not found")
            )
        # Replace the git probe with a "real" git HEAD.
        mock.get("https://target.example/app/.git/HEAD").mock(
            return_value=httpx.Response(200, text="ref: refs/heads/main\n")
        )

        findings = list(SensitivePathsCheck().run(ctx))

    types = {f.type for f in findings}
    assert "exposed-git-repo" in types
    git_finding = next(f for f in findings if f.type == "exposed-git-repo")
    assert git_finding.severity.value == "critical"
    assert git_finding.cvss == 9.8


def test_signature_mismatch_does_not_emit_false_positive(ctx):
    """A soft-404 page that returns 200 OK should not trigger findings."""
    with respx.mock(assert_all_called=False) as mock:
        mock.get(url__startswith="https://target.example/app/").mock(
            return_value=httpx.Response(200, text="<html>404 page</html>")
        )
        findings = list(SensitivePathsCheck().run(ctx))
    assert findings == []


def test_exposed_env_with_kv_pair(ctx):
    with respx.mock(assert_all_called=False) as mock:
        for probe in [
            ".git/HEAD",
            ".DS_Store",
            "wp-config.php.bak",
            "phpinfo.php",
            "server-status",
            "actuator/env",
        ]:
            mock.get(f"https://target.example/app/{probe}").mock(
                return_value=httpx.Response(404)
            )
        mock.get("https://target.example/app/.env").mock(
            return_value=httpx.Response(200, text="DATABASE_URL=postgres://x:y@db/prod\n")
        )
        findings = list(SensitivePathsCheck().run(ctx))
    assert any(f.type == "exposed-env-file" for f in findings)


def test_bad_url_is_noop():
    findings = list(SensitivePathsCheck().run(CheckContext(url="not-a-url")))
    assert findings == []
