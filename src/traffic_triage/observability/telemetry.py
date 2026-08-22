"""OpenTelemetry instrumentation and structured logging utilities."""

import logging
import sys
from typing import Any

import structlog
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider


def setup_observability(service_name: str = "agentic-traffic-threat-triage") -> None:
    """Configures structured logging and OpenTelemetry tracing provider."""
    # Structlog configuration
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
    )

    # OpenTelemetry Tracer setup
    provider = TracerProvider()
    trace.set_tracer_provider(provider)


def get_tracer(module_name: str) -> trace.Tracer:
    return trace.get_tracer(module_name)


def get_logger(name: str) -> Any:
    return structlog.get_logger(name)
