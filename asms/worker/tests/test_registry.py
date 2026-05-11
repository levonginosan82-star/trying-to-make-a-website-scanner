"""Smoke test for the registry."""

from asms_worker.registry import REGISTRY


def test_security_headers_check_is_registered() -> None:
    assert "dast.headers" in REGISTRY.names()
    check = REGISTRY.get("dast.headers")
    assert check.category == "dast"
