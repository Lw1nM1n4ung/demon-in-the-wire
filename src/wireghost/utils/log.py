"""Logging setup with Rich console handler and optional file handler."""

from __future__ import annotations

import logging
from pathlib import Path

from rich.logging import RichHandler


def setup_logging(
    output_dir: str | Path | None = None,
    verbose: bool = False,
) -> logging.Logger:
    """Configure and return the ``wireghost`` logger.

    Parameters
    ----------
    output_dir:
        If given, a ``wireghost.log`` file handler is added under this directory.
    verbose:
        If ``True`` the level is set to ``DEBUG``; otherwise ``INFO``.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logger = logging.getLogger("wireghost")
    logger.setLevel(level)

    # Avoid adding duplicate handlers on repeated calls
    if not logger.handlers:
        rich_handler = RichHandler(
            rich_tracebacks=True,
            show_path=False,
            markup=True,
        )
        rich_handler.setLevel(level)
        logger.addHandler(rich_handler)

    if output_dir is not None:
        log_path = Path(output_dir) / "wireghost.log"
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(str(log_path))
            file_handler.setLevel(logging.DEBUG)
            fmt = logging.Formatter(
                "%(asctime)s %(levelname)-8s %(name)s - %(message)s"
            )
            file_handler.setFormatter(fmt)
            logger.addHandler(file_handler)
        except PermissionError:
            logger.warning(
                "Cannot write log to %s (permission denied). "
                "Run: sudo chown -R $(whoami) %s",
                log_path, log_path.parent,
            )

    return logger
