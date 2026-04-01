"""
Background investigation workers: one Playwright browser + asyncio loop per job (thread-isolated).
"""

from __future__ import annotations

import asyncio
import logging
import queue
import threading
from pathlib import Path
from typing import Optional

from database import ReportDatabase
from forensic_report import run_full_investigation
from scanner import ProxyManager

logger = logging.getLogger("lupin.jobs")


def _run_async_investigation(
    username: str,
    *,
    proxy_server: Optional[str],
    evidence_root: Path,
    public_evidence_base_url: str,
    timeout_s: int,
) -> tuple:  # (report_dict, Optional[int])
    async def _inner():
        return await asyncio.wait_for(
            run_full_investigation(
                username,
                evidence_root=evidence_root,
                proxy_server=proxy_server,
                include_avatar_base64=False,
                public_evidence_base_url=public_evidence_base_url,
            ),
            timeout=timeout_s,
        )

    return asyncio.run(_inner())


def process_single_job(
    job_id: str,
    db: ReportDatabase,
    proxy_manager: ProxyManager,
    *,
    evidence_root: Path,
    public_evidence_base_url: str,
    timeout_s: int,
) -> None:
    row = db.get_job(job_id)
    if not row:
        logger.warning("Unknown job_id %s", job_id)
        return

    username = row["username"]
    db.update_job_status(job_id, "processing")

    cached = db.get_fresh_cached_report(username)
    if cached is not None:
        report, http_status = cached
        db.complete_job(job_id, report, http_status)
        logger.info("Job %s served from cache (%s)", job_id, username)
        return

    proxy = proxy_manager.pick_random()
    if proxy:
        logger.info("Job %s using proxy %s", job_id, proxy.split("@")[-1])

    try:
        report, err_status = _run_async_investigation(
            username,
            proxy_server=proxy,
            evidence_root=evidence_root,
            public_evidence_base_url=public_evidence_base_url,
            timeout_s=timeout_s,
        )
    except asyncio.TimeoutError:
        db.fail_job(job_id, f"Investigation timed out after {timeout_s}s")
        logger.warning("Job %s timeout", job_id)
        return
    except Exception as exc:
        db.fail_job(job_id, str(exc))
        logger.exception("Job %s failed: %s", job_id, exc)
        return

    http_status = 200 if err_status is None else int(err_status)
    db.upsert_report_cache(username, report, http_status)
    db.complete_job(job_id, report, http_status)
    logger.info("Job %s completed http=%s", job_id, http_status)


def worker_loop(
    job_queue: "queue.Queue[str]",
    db: ReportDatabase,
    proxy_manager: ProxyManager,
    *,
    evidence_root: Path,
    public_evidence_base_url: str,
    timeout_s: int,
    stop_event: threading.Event,
) -> None:
    while not stop_event.is_set():
        try:
            job_id = job_queue.get(timeout=0.5)
        except queue.Empty:
            continue
        try:
            process_single_job(
                job_id,
                db,
                proxy_manager,
                evidence_root=evidence_root,
                public_evidence_base_url=public_evidence_base_url,
                timeout_s=timeout_s,
            )
        finally:
            job_queue.task_done()


def start_worker_threads(
    job_queue: "queue.Queue[str]",
    db: ReportDatabase,
    proxy_manager: ProxyManager,
    *,
    evidence_root: Path,
    public_evidence_base_url: str,
    timeout_s: int,
    num_workers: int,
    stop_event: threading.Event,
) -> list[threading.Thread]:
    threads: list[threading.Thread] = []
    for i in range(max(1, num_workers)):
        t = threading.Thread(
            target=worker_loop,
            name=f"lupin-worker-{i}",
            kwargs={
                "job_queue": job_queue,
                "db": db,
                "proxy_manager": proxy_manager,
                "evidence_root": evidence_root,
                "public_evidence_base_url": public_evidence_base_url,
                "timeout_s": timeout_s,
                "stop_event": stop_event,
            },
            daemon=True,
        )
        t.start()
        threads.append(t)
    return threads
