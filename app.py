"""
Lupin Forensic Suite — production-style Flask API.

- GET/POST /api/investigate/<username> → queue job (always JSON; use from the dashboard / scripts)
- GET      /api/status/<job_id>        → job state + result when completed
- GET/POST /investigate/<username>     → legacy; browser GET may redirect to /?target=…
- GET      /status/<job_id>            → same as /api/status (legacy)
- GET      /evidence/<path>           → static files under evidence dir
- GET      /health                    → {"status": "ok"} (load balancers / Railway)

Run locally: python3 app.py
Production: gunicorn --bind 0.0.0.0:8080 app:app --timeout 120
"""

from __future__ import annotations

import json
import logging
import os
import queue
import threading
import uuid
from pathlib import Path
from urllib.parse import quote

from flask import Flask, jsonify, redirect, request, send_from_directory
from flask_cors import CORS

from config import dashboard_dir, data_dir, ensure_evidence_writable, evidence_dir
from database import ReportDatabase
from investigation_jobs import start_worker_threads
from scanner import ProxyManager

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("lupin.app")

# Writable absolute paths (validated at import so misconfigured volumes fail fast)
EVIDENCE_ROOT = ensure_evidence_writable(evidence_dir())
DASHBOARD_ROOT = dashboard_dir()

_data = data_dir()
_data.mkdir(parents=True, exist_ok=True)
DEFAULT_DB = _data / "lupin.db"

DEFAULT_TIMEOUT = int(os.environ.get("LUPIN_INVESTIGATE_TIMEOUT", "180"))
DEFAULT_WORKERS = int(os.environ.get("LUPIN_WORKERS", "2"))

db = ReportDatabase(Path(os.environ.get("LUPIN_DB", str(DEFAULT_DB))))
proxy_manager = ProxyManager()
job_queue: queue.Queue[str] = queue.Queue()
stop_workers = threading.Event()
_worker_threads: list[threading.Thread] = []
_services_lock = threading.Lock()
_services_started = False


def _public_base_url() -> str:
    for key in ("LUPIN_PUBLIC_URL", "PUBLIC_URL", "RAILWAY_PUBLIC_URL"):
        v = os.environ.get(key)
        if v and v.strip():
            return v.strip().rstrip("/")
    dom = os.environ.get("RAILWAY_PUBLIC_DOMAIN")
    if dom and dom.strip():
        return f"https://{dom.strip()}".rstrip("/")
    port = os.environ.get("PORT", os.environ.get("LUPIN_PORT", "8080"))
    return f"http://127.0.0.1:{port}".rstrip("/")


def ensure_background_services() -> None:
    """Initialize SQLite and worker threads exactly once (thread-safe)."""
    global _services_started, _worker_threads
    with _services_lock:
        if _services_started:
            return
        db.init()
        _worker_threads.extend(
            start_worker_threads(
                job_queue,
                db,
                proxy_manager,
                evidence_root=EVIDENCE_ROOT,
                public_evidence_base_url=_public_base_url(),
                timeout_s=DEFAULT_TIMEOUT,
                num_workers=DEFAULT_WORKERS,
                stop_event=stop_workers,
            )
        )
        logger.info(
            "Started %s investigation worker thread(s), %s proxy line(s) in config, evidence=%s",
            len(_worker_threads),
            proxy_manager.proxy_count,
            EVIDENCE_ROOT,
        )
        _services_started = True


def create_app() -> Flask:
    ensure_background_services()

    app = Flask(__name__)
    CORS(app)

    @app.route("/")
    def dashboard_index():
        if not DASHBOARD_ROOT.is_dir():
            return jsonify({"error": "Dashboard not installed"}), 503
        return send_from_directory(DASHBOARD_ROOT, "index.html")

    @app.route("/dashboard/<path:filename>")
    def dashboard_assets(filename: str):
        if not DASHBOARD_ROOT.is_dir():
            return jsonify({"error": "Dashboard not installed"}), 503
        return send_from_directory(DASHBOARD_ROOT, filename)

    @app.route("/health")
    def health():
        return jsonify({"status": "ok"})

    @app.route("/health/detail")
    def health_detail():
        return jsonify(
            {
                "status": "ok",
                "service": "lupin-forensic",
                "workers": len(_worker_threads),
                "proxies_configured": proxy_manager.proxy_count,
                "evidence_root": str(EVIDENCE_ROOT),
            }
        )

    @app.route("/evidence/<path:rel_path>")
    def serve_evidence(rel_path: str):
        return send_from_directory(EVIDENCE_ROOT, rel_path)

    def _enqueue_investigate(username: str, *, allow_html_redirect: bool) -> tuple:
        norm = db.normalize_username(username)
        if not norm:
            return jsonify({"error": "Username required", "status": "error"}), 400
        if allow_html_redirect and request.method == "GET":
            accept = request.headers.get("Accept") or ""
            if "text/html" in accept and "application/json" not in accept:
                return redirect(f"/?target={quote(norm, safe='')}"), 302
        try:
            job_id = str(uuid.uuid4())
            db.create_job(job_id, norm)
            job_queue.put(job_id)
        except Exception as exc:
            logger.exception("Failed to enqueue investigation for %s", norm)
            return (
                jsonify({"error": str(exc), "status": "error", "detail": "enqueue_failed"}),
                500,
            )
        poll = f"/api/status/{job_id}"
        return (
            jsonify(
                {
                    "job_id": job_id,
                    "status": "queued",
                    "poll_url": poll,
                    "poll_url_legacy": f"/status/{job_id}",
                    "note": "Poll poll_url until status is completed.",
                }
            ),
            202,
        )

    @app.route("/api/investigate/<username>", methods=["GET", "POST"])
    def api_investigate(username: str):
        return _enqueue_investigate(username, allow_html_redirect=False)

    @app.route("/investigate/<username>", methods=["GET", "POST"])
    def investigate(username: str):
        return _enqueue_investigate(username, allow_html_redirect=True)

    @app.route("/api/status/<job_id>", methods=["GET"])
    def api_job_status(job_id: str):
        return _job_status_payload(job_id)

    @app.route("/status/<job_id>", methods=["GET"])
    def job_status(job_id: str):
        return _job_status_payload(job_id)

    def _job_status_payload(job_id: str) -> tuple:
        row = db.get_job(job_id)
        if not row:
            return jsonify({"error": "Unknown job_id", "status": "not_found"}), 404

        body: dict = {
            "job_id": job_id,
            "status": row["status"],
            "username": row["username"],
        }
        st = row["status"]
        if st == "completed":
            raw = row.get("result_json")
            body["http_status"] = row.get("http_status")
            if raw:
                try:
                    body["result"] = json.loads(raw)
                except Exception:
                    body["result"] = None
                    body["parse_error"] = "Stored result_json is invalid"
        elif st == "failed":
            body["error"] = row.get("error")
        return jsonify(body), 200

    return app


app = create_app()


def main() -> None:
    host = os.environ.get("LUPIN_HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", os.environ.get("LUPIN_PORT", "8080")))
    debug = os.environ.get("LUPIN_DEBUG", "").lower() in ("1", "true", "yes")
    if debug:
        logger.warning("Flask debug mode is not recommended with background Playwright workers")
    app.run(host=host, port=port, debug=debug, threaded=True, use_reloader=False)


if __name__ == "__main__":
    main()
