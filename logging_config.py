#!/usr/bin/env python3
"""JSON structured logging for echo-crm.

Configures Python ``logging`` to emit one JSON object per line and write to
``echo-crm.log`` under the fleet logs directory (``O:\\ECHO_OMEGA_PRIME\\logs``
on Windows hosts; Linux builders resolve the workspace / FORGE equivalent).
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

SERVICE = "echo-crm"
VERSION = os.environ.get("ECHO_CRM_VERSION", "2.2.0-resilience")

_SKIP_FIELDS = frozenset(
    {
        "name",
        "msg",
        "args",
        "levelname",
        "levelno",
        "pathname",
        "filename",
        "module",
        "exc_info",
        "exc_text",
        "stack_info",
        "lineno",
        "funcName",
        "created",
        "msecs",
        "relativeCreated",
        "thread",
        "threadName",
        "processName",
        "process",
        "taskName",
        "message",
    }
)

# Candidate log directories (Windows O: path + Linux workspace / FORGE mirrors).
_DEFAULT_LOG_DIR_CANDIDATES = (
    os.environ.get("ECHO_CRM_LOG_DIR", ""),
    os.environ.get("ECHO_LOG_DIR", ""),
    r"O:\ECHO_OMEGA_PRIME\logs",
    "O:/ECHO_OMEGA_PRIME/logs",
    "/home/forge/ECHO_OMEGA_PRIME/logs",
    str(Path(__file__).resolve().parents[2] / "O" / "ECHO_OMEGA_PRIME" / "logs"),
    str(Path(__file__).resolve().parents[2] / "logs"),
    "/tmp/echo-crm-logs",
)

LOG_FILENAME = "echo-crm.log"

_configured = False


class JsonFormatter(logging.Formatter):
    """Emit each log record as a single-line JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        """Serialize *record* to a single-line JSON string.

        Standard ``LogRecord`` bookkeeping fields are stripped; extra fields
        passed via ``logger.info("msg", extra={...})`` are forwarded verbatim.
        """
        ts = datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat()
        payload: dict[str, Any] = {
            "ts": ts,
            "timestamp": ts,
            "level": record.levelname.lower(),
            "msg": record.getMessage(),
            "message": record.getMessage(),
            "service": SERVICE,
            "version": VERSION,
            "logger": record.name,
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        for key, val in record.__dict__.items():
            if key in _SKIP_FIELDS or key.startswith("_") or key in payload:
                continue
            try:
                json.dumps(val, default=str)
                payload[key] = val
            except (TypeError, ValueError):
                payload[key] = str(val)
        return json.dumps(payload, default=str)


def resolve_log_dir() -> Path:
    """Pick the first writable fleet log directory from known candidates."""
    for raw in _DEFAULT_LOG_DIR_CANDIDATES:
        if not raw:
            continue
        path = Path(raw)
        try:
            path.mkdir(parents=True, exist_ok=True)
            probe = path / ".echo_crm_write_probe"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink(missing_ok=True)
            return path
        except OSError:
            continue
    fallback = Path("/tmp/echo-crm-logs")
    fallback.mkdir(parents=True, exist_ok=True)
    return fallback


def log_file_path() -> Path:
    """Absolute path to ``echo-crm.log``."""
    return resolve_log_dir() / LOG_FILENAME


def configure(
    level: Optional[str] = None,
    *,
    log_file: Optional[str | Path] = None,
    force: bool = False,
) -> logging.Logger:
    """Configure root + service loggers for structured JSON output.

    Always attaches a StreamHandler (stdout) and a FileHandler targeting
    ``echo-crm.log`` in the resolved fleet logs directory unless *log_file*
    is provided.

    Args:
        level: Log level name (default LOG_LEVEL env or INFO).
        log_file: Optional explicit path to the log file.
        force: Reconfigure even if already configured.

    Returns:
        The ``echo_crm`` service logger.
    """
    global _configured
    if _configured and not force:
        return logging.getLogger("echo_crm")

    level_name = (level or os.environ.get("LOG_LEVEL", "INFO")).upper()
    log_level = getattr(logging, level_name, logging.INFO)
    formatter = JsonFormatter()

    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
        try:
            handler.close()
        except Exception:
            pass

    stream = logging.StreamHandler()
    stream.setFormatter(formatter)
    stream.setLevel(log_level)
    root.addHandler(stream)

    target = Path(log_file) if log_file else log_file_path()
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(target, encoding="utf-8")
        file_handler.setFormatter(formatter)
        file_handler.setLevel(log_level)
        root.addHandler(file_handler)
    except OSError as exc:
        # Fall back to stream-only if the log path is not writable.
        stream_logger = logging.getLogger("echo_crm.logging_config")
        stream_logger.warning(
            "Could not open log file %s: %s", target, exc
        )

    root.setLevel(log_level)

    # Silence noisy access loggers that conflict with structured request logs.
    for noisy in ("uvicorn.access", "uvicorn.error"):
        logging.getLogger(noisy).propagate = False

    service_logger = logging.getLogger("echo_crm")
    service_logger.setLevel(log_level)
    service_logger.propagate = True

    _configured = True
    service_logger.info(
        "structured logging configured",
        extra={
            "event": "logging_configured",
            "log_file": str(target),
            "log_level": level_name,
        },
    )
    return service_logger


def get_logger(name: str = "echo_crm") -> logging.Logger:
    """Return a named logger after ensuring configuration."""
    if not _configured:
        configure()
    return logging.getLogger(name)


def log_event(
    logger: logging.Logger,
    level: str,
    message: str,
    **context: Any,
) -> None:
    """Emit a structured log event with optional context fields."""
    lvl = getattr(logging, level.upper(), logging.INFO)
    # Map common short names used by the service.
    if level.lower() in ("warn", "warning"):
        lvl = logging.WARNING
    record = logger.makeRecord(
        logger.name,
        lvl,
        "(logging_config)",
        0,
        message,
        args=(),
        exc_info=None,
    )
    for key, value in context.items():
        setattr(record, key, value)
    logger.handle(record)
