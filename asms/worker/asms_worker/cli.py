"""asms-worker CLI: run a single check directly without Celery/RabbitMQ."""

from __future__ import annotations

import json
import sys

import click

from asms_worker.checks.base import CheckContext
from asms_worker.registry import REGISTRY


@click.group()
def cli() -> None:
    """ASMS scanner worker CLI."""


@cli.command()
@click.option("--url", required=True, help="Target URL to scan.")
@click.option("--method", default="GET", show_default=True)
@click.option(
    "--check",
    "check_name",
    default="dast.headers",
    show_default=True,
    help="Registered check to run.",
)
@click.option(
    "--timeout",
    default=15.0,
    show_default=True,
    type=float,
    help="HTTP timeout in seconds.",
)
def scan(url: str, method: str, check_name: str, timeout: float) -> None:
    """Run one check against a URL and print findings as JSON."""
    check = REGISTRY.get(check_name)
    ctx = CheckContext(url=url, method=method, options={"timeout_s": timeout})
    findings = [f.to_dict() for f in check.run(ctx)]
    json.dump(findings, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")


@cli.command(name="scan-secrets")
@click.option(
    "--path",
    "root",
    default=".",
    show_default=True,
    help="Directory or file to scan for hardcoded secrets.",
)
def scan_secrets(root: str) -> None:
    """Walk a directory tree and emit secret-leak findings as JSON.

    Convenient for CI: ``asms-worker scan-secrets --path .`` and fail the
    build on any critical/high severity output.
    """
    check = REGISTRY.get("sast.secrets")
    ctx = CheckContext(url=root, method="N/A")
    findings = [f.to_dict() for f in check.run(ctx)]
    json.dump(findings, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")
    # Non-zero exit when high-impact findings are present so CI can gate on it.
    blocking = {"critical", "high"}
    if any(f["severity"] in blocking for f in findings):
        sys.exit(2)


@cli.command(name="list-checks")
def list_checks() -> None:
    """List registered checks."""
    for name in REGISTRY.names():
        click.echo(name)


if __name__ == "__main__":
    cli()
