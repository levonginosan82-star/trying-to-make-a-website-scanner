"""Tests for the SAST secrets scanner."""

from __future__ import annotations

from pathlib import Path

import pytest

from asms_worker.checks.base import CheckContext
from asms_worker.checks.secrets import SecretsCheck


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text(
        "AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n"
        "DB_PASSWORD = 'super-secret-password-1234567890'\n"
    )
    (tmp_path / "src" / "config.js").write_text(
        "const ghToken = 'ghp_abcdef1234567890abcdef1234567890ABCD'\n"
    )
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "bigfile.js").write_text(
        "AKIAIOSFODNN7EXAMPLE = 'should not be flagged - in skipped dir'"
    )
    (tmp_path / "image.png").write_bytes(b"\x89PNG\r\n" + b"\x00" * 32)
    return tmp_path


def test_finds_aws_and_github_secrets(repo):
    findings = list(SecretsCheck().run(CheckContext(url=str(repo))))
    types = {f.type for f in findings}
    assert "leaked-aws-access-key" in types
    assert "leaked-github-token" in types
    assert "leaked-generic-secret-assignment" in types


def test_skips_node_modules(repo):
    findings = list(SecretsCheck().run(CheckContext(url=str(repo))))
    # Substring matching against the absolute path is unreliable because
    # pytest names its tmp directory after the test function — which here
    # contains the literal string "node_modules". Compare path *parts* instead.
    assert not any("node_modules" in Path(f.url).parts for f in findings)
    assert not any("bigfile.js" == Path(f.url).name for f in findings)


def test_redacts_match(repo):
    findings = list(SecretsCheck().run(CheckContext(url=str(repo))))
    aws = next(f for f in findings if f.type == "leaked-aws-access-key")
    assert "AKIA" in aws.evidence["preview"]
    # The middle of the key must be masked.
    assert "*" in aws.evidence["preview"]
    # And the raw key should never appear in the description.
    assert "AKIAIOSFODNN7EXAMPLE" not in aws.description


def test_private_key_detected(tmp_path):
    (tmp_path / "deploy.pem").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIE…\n-----END RSA PRIVATE KEY-----\n"
    )
    findings = list(SecretsCheck().run(CheckContext(url=str(tmp_path))))
    assert any(f.type == "leaked-private-key" for f in findings)


def test_missing_path_is_noop(tmp_path):
    findings = list(
        SecretsCheck().run(CheckContext(url=str(tmp_path / "no-such")))
    )
    assert findings == []


def test_single_file_input(tmp_path):
    f = tmp_path / "secret.txt"
    f.write_text("aws_access = AKIAIOSFODNN7EXAMPLE")
    findings = list(SecretsCheck().run(CheckContext(url=str(f))))
    assert any(x.type == "leaked-aws-access-key" for x in findings)
