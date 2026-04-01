"""
Central paths and directories for Lupin (local, Docker, Railway).

Override with environment variables when the filesystem layout differs.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

APP_ROOT = Path(__file__).resolve().parent


def evidence_dir() -> Path:
    """Absolute path for avatar + raw_scan storage (must be writable)."""
    return Path(os.environ.get("LUPIN_EVIDENCE_DIR", str(APP_ROOT / "evidence"))).resolve()


def data_dir() -> Path:
    """Absolute path for SQLite and other local state."""
    return Path(os.environ.get("LUPIN_DATA_DIR", str(APP_ROOT / "data"))).resolve()


def dashboard_dir() -> Path:
    return (APP_ROOT / "dashboard").resolve()


def ensure_evidence_writable(path: Optional[Path] = None) -> Path:
    """
    Create evidence directory if needed and verify we can write files.
    Raises RuntimeError if the volume is read-only or permission denied.
    """
    root = path if path is not None else evidence_dir()
    root.mkdir(parents=True, exist_ok=True)
    probe = root / ".lupin_write_probe"
    try:
        probe.write_text("ok", encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(
            f"Lupin evidence directory is not writable: {root} ({exc}). "
            "Set LUPIN_EVIDENCE_DIR to a writable path (e.g. /tmp/lupin-evidence on read-only images)."
        ) from exc
    try:
        probe.unlink()
    except OSError:
        pass
    return root
