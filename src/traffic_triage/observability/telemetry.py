"""OpenTelemetry instrumentation and structured logging utilities."""

import logging
import sys
from typing import Any

import structlog
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SpanProcessor

_TRACER_PROVIDER: TracerProvider | None = None


def setup_observability(
    service_name: str = "agentic-traffic-threat-triage",
    span_processor: SpanProcessor | None = None,
) -> TracerProvider:
    """Configures structured logging and OpenTelemetry tracing provider."""
    global _TRACER_PROVIDER
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
    if span_processor is not None:
        provider.add_span_processor(span_processor)
    trace.set_tracer_provider(provider)
    _TRACER_PROVIDER = provider
    return provider


def get_tracer(module_name: str) -> trace.Tracer:
    return trace.get_tracer(module_name)


def get_logger(name: str) -> Any:
    return structlog.get_logger(name)
