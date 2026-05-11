"""Smoke test for the registry."""

from asms_worker.registry import REGISTRY


def test_security_headers_check_is_registered() -> None:
    assert "dast.headers" in REGISTRY.names()
    check = REGISTRY.get("dast.headers")
    assert check.category == "dast"


def test_all_built_in_checks_registered() -> None:
    expected = {
        "dast.headers",
        "dast.tls",
        "dast.sensitive_paths",
        "dast.tech_disclosure",
        "easm.dns",
        "sast.secrets",
    }
    assert expected.issubset(set(REGISTRY.names()))


def test_unknown_check_raises_with_known_listed() -> None:
    import pytest

    with pytest.raises(KeyError) as excinfo:
        REGISTRY.get("does-not-exist")
    assert "dast.headers" in str(excinfo.value)
