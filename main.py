
import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

from forensic_report import format_report_text, run_full_investigation


async def run(username: str, verify: bool, truth_path: Optional[str]) -> int:
    report, http_status = await run_full_investigation(username)

    if http_status == 404:
        print(json.dumps(report, indent=2))
        return 1
    if http_status == 400:
        print(json.dumps(report, indent=2))
        return 1

    verify_msg: Optional[str] = None
    if verify:
        if truth_path:
            try:
                truth = json.loads(Path(truth_path).read_text(encoding="utf-8"))
                identity = report.get("identity") or {}
                truth_created = truth.get("account_created")
                truth_updated = truth.get("last_profile_update")
                last_profile_update = identity.get("last_profile_update_utc")
                ok = (truth_created == identity.get("profile_finalized_utc")) and (truth_updated == last_profile_update)
                verify_msg = "PASS" if ok else "FAIL"
            except Exception as exc:
                verify_msg = f"ERROR: {exc}"
        else:
            verify_msg = "truth file not provided"

    print(format_report_text(report, verify=verify, verify_message=verify_msg))
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "TikTok OSINT scanner using Playwright request interception and "
            "rehydration JSON extraction."
        )
    )
    parser.add_argument("username", help="TikTok username without the @ symbol.")
    parser.add_argument("--verify", action="store_true", help="Compare timestamps against a local truth file.")
    parser.add_argument(
        "--truth",
        default=None,
        help="Path to truth JSON: {\"account_created\":\"YYYY-MM-DD HH:MM:SS\",\"last_profile_update\":\"YYYY-MM-DD HH:MM:SS\"}",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        return asyncio.run(run(args.username, verify=args.verify, truth_path=args.truth))
    except KeyboardInterrupt:
        print("Interrupted by user.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"Scanner error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
