"""Celery app and task definitions.

A real deployment configures the broker (RabbitMQ/Redis) and a result backend
via environment variables. This module is import-safe even without those
configured so unit tests can run in isolation.
"""

from __future__ import annotations

import os

from celery import Celery

BROKER_URL = os.environ.get("ASMS_BROKER_URL", "memory://")
RESULT_BACKEND = os.environ.get("ASMS_RESULT_BACKEND", "cache+memory://")

app = Celery("asms_worker", broker=BROKER_URL, backend=RESULT_BACKEND)
app.conf.task_default_queue = "dast.headers"
app.conf.task_acks_late = True
app.conf.task_reject_on_worker_lost = True
app.conf.worker_prefetch_multiplier = 4

# Importing tasks triggers registration with the app.
from asms_worker import tasks  # noqa: E402,F401
