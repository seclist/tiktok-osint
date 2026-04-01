"""
Structured forensic report for Lupin (CLI + API).
"""

from __future__ import annotations

import base64
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote
from typing import Any, Dict, List, Optional, Set, Tuple

from config import evidence_dir as default_evidence_dir
from pivoter import LeadResult, download_high_res_avatar, sherlock_search
from scanner import ScanResult, TikTokScanner


def is_account_missing(result: ScanResult) -> bool:
    profile = (result.extracted_metadata or {}).get("profile") or {}
    uid = (profile.get("uniqueId") or "").strip()
    nid = profile.get("numeric_id")
    has_id = bool(uid) or (nid is not None and str(nid).strip() not in {"", "None"})
    return not has_id


def _lead_results_to_json(leads: Dict[str, List[LeadResult]]) -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = {}
    for k, lst in leads.items():
        out[k] = [asdict(r) for r in lst]
    return out


def scan_result_to_serializable(result: ScanResult) -> Dict[str, Any]:
    """Snapshot suitable for evidence/raw_scan.json (best-effort JSON-safe)."""
    return {
        "username": result.username,
        "page_url": result.page_url,
        "extracted_metadata": result.extracted_metadata,
        "rehydration_data": result.rehydration_data,
        "api_data": result.api_data,
    }


def build_forensic_report(
    scanner: TikTokScanner,
    result: ScanResult,
    leads: Dict[str, List[LeadResult]],
    *,
    unique_id: str,
    saved_avatar: Optional[Path],
    evidence_paths: Optional[Dict[str, Optional[str]]] = None,
    avatar_base64: Optional[str] = None,
    evidence_avatar_url: Optional[str] = None,
) -> Dict[str, Any]:
    profile = (result.extracted_metadata or {}).get("profile") or {}
    numeric_id = profile.get("numeric_id") or "(unknown)"
    created = profile.get("account_created") or "(unknown)"
    signature = profile.get("signature") or ""
    avatar = profile.get("avatarLarger") or ""
    registered_region = profile.get("registered_region") or "(unknown)"
    primary_language = profile.get("primary_language") or "(unknown)"
    id_forensics = profile.get("id_forensics") or {}
    geographic_anchor = profile.get("geographic_anchor") or "(unknown)"
    physical_dc = profile.get("physical_datacenter")
    region_flag = scanner.infer_region_spoofing_flag(
        registered_region if registered_region != "(unknown)" else None,
        avatar,
    )
    net_anomaly = scanner.infer_network_anomaly(
        registered_region if registered_region != "(unknown)" else None,
        geographic_anchor if geographic_anchor != "(unknown)" else None,
    )
    stats_v2 = profile.get("statsV2") or {}
    stats_v2_raw: Dict[str, Any] = profile.get("statsV2_raw") if isinstance(profile.get("statsV2_raw"), dict) else {}
    if not stats_v2_raw and isinstance(stats_v2, dict):
        stats_v2_raw = dict(stats_v2)
    account_details: Dict[str, Any] = profile.get("account_details") if isinstance(profile.get("account_details"), dict) else {}
    follower_count = stats_v2.get("followerCount") or stats_v2_raw.get("followerCount") or "(unknown)"
    heart_count = stats_v2.get("heartCount") or stats_v2_raw.get("heartCount") or "(unknown)"
    pol = (result.extracted_metadata or {}).get("pattern_of_life") or {}
    video_count_observed = int(pol.get("video_count_observed") or 0)

    found = scanner.parse_social_usernames(signature)
    ig_handles = found.get("instagram") or []
    x_handles = found.get("x") or []
    youtube_handles = found.get("youtube") or []
    github_handles = set(found.get("github") or [])
    alternate_ids = scanner.extract_alternate_identities(signature, unique_id)

    # Merge every username that was probed (including TikTok uniqueId). Previously only
    # ig/x/alternate handles were considered, so Instagram/X hits for the primary
    # @handle were dropped even though sherlock probed them.
    best_by_platform: Dict[str, LeadResult] = {}
    for _probe_user, res_list in (leads or {}).items():
        for res in res_list:
            if res.platform not in {"Instagram", "X", "YouTube", "Pinterest", "GitHub"}:
                continue
            prev = best_by_platform.get(res.platform)
            if prev is None:
                best_by_platform[res.platform] = res
            elif prev.status != "Found" and res.status == "Found":
                best_by_platform[res.platform] = res

    social_leads: List[Dict[str, Any]] = []
    seen_urls: Set[str] = set()
    for p in ["Instagram", "X", "YouTube", "Pinterest", "GitHub"]:
        if p not in best_by_platform:
            continue
        r = best_by_platform[p]
        if r.url in seen_urls:
            continue
        seen_urls.add(r.url)
        social_leads.append(
            {"platform": p, "url": r.url, "status": r.status, "http_status": r.http_status, "queried_username": r.username}
        )

    def _bio_fallback(platform: str, url: str, handle: str) -> None:
        if url in seen_urls:
            return
        if any(s.get("platform") == platform for s in social_leads):
            return
        seen_urls.add(url)
        social_leads.append(
            {
                "platform": platform,
                "url": url,
                "status": "From bio",
                "http_status": None,
                "queried_username": handle,
                "source": "bio_parse",
            }
        )

    for h in ig_handles:
        hn = (h or "").strip().lstrip("@")
        if hn:
            _bio_fallback("Instagram", f"https://www.instagram.com/{hn}/", hn)
    for h in x_handles:
        hn = (h or "").strip().lstrip("@")
        if hn:
            _bio_fallback("X", f"https://x.com/{hn}", hn)
    for h in youtube_handles:
        hn = (h or "").strip().lstrip("@")
        if hn:
            _bio_fallback("YouTube", f"https://www.youtube.com/@{hn}", hn)
    for h in github_handles:
        hn = (h or "").strip().lstrip("@")
        if hn:
            _bio_fallback("GitHub", f"https://github.com/{hn}", hn)

    if isinstance(id_forensics, dict) and id_forensics.get("decoded"):
        slot_reserved = id_forensics.get("timestamp_utc") or "(unknown)"
        slot_reserved_epoch = id_forensics.get("timestamp_seconds")
    else:
        slot_reserved = "(unknown)"
        slot_reserved_epoch = None

    integrity = "(unknown)"
    try:
        if isinstance(slot_reserved_epoch, int) and created not in {"(unknown)", ""}:
            created_dt = datetime.strptime(created, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            created_epoch = int(created_dt.timestamp())
            gap = created_epoch - int(slot_reserved_epoch)
            if gap < 20:
                integrity = "High Automation Probability"
            elif gap > 48 * 3600:
                integrity = "Possible Aged/Parked Account"
            else:
                integrity = "Human (typical provisioning)"
    except Exception:
        integrity = "(unknown)"

    ratio = pol.get("engagement_to_follower_ratio")
    engagement_ratio = ratio if ratio is not None else "(unknown)"
    follower_int = int(follower_count) if str(follower_count).isdigit() else None
    if video_count_observed > 0:
        content_status = "Public"
    else:
        content_status = "Ghost" if (follower_int or 0) >= 10_000 else "Private"

    shadow = (result.extracted_metadata or {}).get("shadow_tracker") or {}
    tagged = shadow.get("tagged_videos") or []
    interactions = shadow.get("interaction_leads") or []
    associates = shadow.get("potential_associates") or []
    associate_mesh = shadow.get("associate_mesh") or []
    secret = (result.extracted_metadata or {}).get("secret_stats") or {}

    discovered: List[str] = []
    for v in tagged:
        url = v.get("url")
        if not isinstance(url, str) or not url:
            continue
        ct = v.get("video_create_time")
        date_str = None
        if isinstance(ct, int):
            ts = ct // 1000 if ct > 10_000_000_000 else ct
            fmt = scanner._format_utc_timestamp(ts)
            date_str = fmt.split(" ")[0] if fmt else None
        elif isinstance(ct, str) and ct.isdigit():
            ts = int(ct)
            ts = ts // 1000 if ts > 10_000_000_000 else ts
            fmt = scanner._format_utc_timestamp(ts)
            date_str = fmt.split(" ")[0] if fmt else None
        discovered.append(f"{date_str or '(date?)'} - {url}")

    video_clock_ts: List[Any] = []
    for v in tagged:
        ct = v.get("video_create_time")
        if ct is not None:
            video_clock_ts.append(ct)

    slot_for_clock = slot_reserved if slot_reserved != "(unknown)" else None
    created_for_clock = created if created != "(unknown)" else None
    activity_clock = scanner.generate_activity_clock(slot_for_clock, created_for_clock, video_clock_ts)

    summary_bits: List[str] = []
    if integrity and integrity != "(unknown)":
        summary_bits.append(integrity)
    if region_flag:
        summary_bits.append(region_flag)
    if associates:
        summary_bits.append(
            "associated with "
            + ", ".join([f"@{a.get('uniqueId')}" for a in associates if a.get("uniqueId")][:3])
        )
    if not summary_bits:
        summary_bits.append("No high-confidence anomalies detected")

    stats_block: Dict[str, Any] = {
        "followers": follower_count,
        "following": stats_v2.get("followingCount") or stats_v2_raw.get("followingCount"),
        "likes": heart_count,
        "videos_on_profile": stats_v2.get("videoCount") or stats_v2_raw.get("videoCount"),
        "friends": stats_v2.get("friendCount") or stats_v2_raw.get("friendCount"),
        "diggs_total": stats_v2.get("diggCount") or stats_v2_raw.get("diggCount"),
        "content_status": content_status,
        "engagement_ratio": engagement_ratio if content_status == "Public" else None,
        "shadow_stats": (
            {"followers": follower_count, "likes": heart_count, "note": "non-public catalog; not an engagement ratio"}
            if content_status == "Private"
            else None
        ),
    }

    account: Dict[str, Any] = {
        "profile_url": f"https://www.tiktok.com/@{unique_id}",
        "verified": account_details.get("verified"),
        "private_account": account_details.get("private_account"),
        "bio_link_url": account_details.get("bio_link_url"),
        "following_visibility": account_details.get("following_visibility"),
        "ftc": account_details.get("ftc"),
        "is_organization": account_details.get("is_organization"),
        "show_favorite": account_details.get("show_favorite"),
        "open_favorite": account_details.get("open_favorite"),
        "user_level_privacy": {
            k: v
            for k, v in {
                "comment_setting": account_details.get("comment_setting_user"),
                "duet_setting": account_details.get("duet_setting_user"),
                "stitch_setting": account_details.get("stitch_setting_user"),
                "download_setting": account_details.get("download_setting_user"),
            }.items()
            if v is not None
        },
        "avatar_thumb_url": account_details.get("avatar_thumb"),
        "stats_v2_raw": stats_v2_raw,
    }

    identity = {
        "unique_id": unique_id,
        "numeric_id": numeric_id,
        "sec_uid": profile.get("secUid"),
        "nickname": profile.get("nickname"),
        "slot_reserved_utc": slot_reserved,
        "profile_finalized_utc": created,
        "last_profile_update_utc": profile.get("last_profile_update"),
        "registered_region": registered_region,
        "primary_language": primary_language,
        "integrity_assessment": integrity,
        "id_forensics": id_forensics,
    }

    infrastructure = {
        "server_anchor": geographic_anchor,
        "idc_code": profile.get("idc_code"),
        "physical_datacenter": physical_dc,
        "region_spoofing_flag": region_flag or None,
        "network_anomaly": net_anomaly or None,
    }

    intelligence = {
        "bio": signature,
        "bio_link_url": account_details.get("bio_link_url"),
        "avatar_url": avatar,
        "bio_parsed_handles": {
            "instagram": ig_handles,
            "x": x_handles,
            "youtube": youtube_handles,
            "github": list(github_handles),
            "snapchat": found.get("snapchat") or [],
        },
        "alternate_identities": alternate_ids,
        "social_leads": social_leads,
        "pivot_probe_results": _lead_results_to_json(leads),
        "potential_associates": associates[:3],
        "associate_mesh": associate_mesh[:8],
        "discovered_interactions": discovered[:15],
        "interaction_leads": interactions,
        "duetters": shadow.get("duetters") or [],
    }

    secret_stats_out = dict(secret) if isinstance(secret, dict) else {}

    pattern_of_life = {
        "video_count_observed": video_count_observed,
        "engagement_to_follower_ratio": pol.get("engagement_to_follower_ratio"),
        "content_status": content_status,
        "activity_clock": {
            "utc_hour_histogram": activity_clock.get("utc_hour_histogram"),
            "clock_face": activity_clock.get("clock_face"),
            "clock_ruler": activity_clock.get("clock_ruler"),
            "deduction": activity_clock.get("deduction"),
        },
        "shadow_tracker": {
            "tagged_videos": tagged,
            "interaction_events": shadow.get("interaction_events") or [],
            "interaction_leads": interactions,
            "potential_associates": associates,
            "associate_mesh": associate_mesh,
            "duetters": shadow.get("duetters") or [],
        },
    }

    evidence = {
        "avatar_local_path": evidence_paths.get("avatar") if evidence_paths else (saved_avatar.as_posix() if saved_avatar else None),
        "raw_json_path": evidence_paths.get("raw_json") if evidence_paths else None,
        "avatar_url": evidence_avatar_url,
        "avatar_base64": avatar_base64,
    }

    return {
        "status": "complete",
        "username_requested": result.username,
        "forensic_summary": summary_bits,
        "account": account,
        "identity": identity,
        "infrastructure": infrastructure,
        "intelligence": intelligence,
        "secret_stats": secret_stats_out,
        "pattern_of_life": pattern_of_life,
        "stats": stats_block,
        "evidence": evidence,
    }


def format_report_text(report: Dict[str, Any], *, verify: bool = False, verify_message: Optional[str] = None) -> str:
    """Render structured report as legacy multi-line text (CLI)."""
    uid = (report.get("identity") or {}).get("unique_id") or report.get("username_requested") or "?"
    identity = report.get("identity") or {}
    infra = report.get("infrastructure") or {}
    intel = report.get("intelligence") or {}
    pol = report.get("pattern_of_life") or {}
    stats = report.get("stats") or {}
    secret = report.get("secret_stats") or {}
    ev = report.get("evidence") or {}

    lines: List[str] = [
        f"{uid} Forensic Report",
        "Forensic Summary",
        "",
        "- " + "; ".join(report.get("forensic_summary") or []),
        "",
        "Account",
        "",
    ]
    acc = report.get("account") or {}
    lines.extend(
        [
            f"Profile URL: {acc.get('profile_url')}",
            f"Verified: {acc.get('verified')}  Private: {acc.get('private_account')}",
            f"Bio link: {acc.get('bio_link_url') or intel.get('bio_link_url') or ''}",
        ]
    )
    lines.extend(
        [
            "",
            "Identity Details",
            "",
            f"Numeric ID: {identity.get('numeric_id')}",
            "",
            f"Slot Reserved: {identity.get('slot_reserved_utc')} UTC",
            "",
            f"Profile Finalized: {identity.get('profile_finalized_utc')} UTC",
            "",
            f"Region/Lang: {identity.get('registered_region')} / {identity.get('primary_language')}",
            "",
            "Server Anchor: "
            + str(infra.get("server_anchor") or "(unknown)")
            + (f" ({infra.get('region_spoofing_flag')})" if infra.get("region_spoofing_flag") else ""),
        ]
    )
    pdc = infra.get("physical_datacenter")
    if isinstance(pdc, str) and pdc.strip():
        lines.extend(["", pdc.strip()])
    if infra.get("network_anomaly"):
        lines.extend(["", str(infra["network_anomaly"])])

    socials = intel.get("social_leads") or []
    socials_str = " | ".join(f"{s.get('platform')}: {s.get('url')} ({s.get('status')})" for s in socials)

    lines.extend(
        [
            "",
            "Intelligence Leads",
            "",
            f"Bio: {intel.get('bio') or ''}",
            "",
            f"High-Res Avatar: {intel.get('avatar_url') or ''}",
        ]
    )
    if socials_str:
        lines.extend(["", f"Socials: {socials_str}"])
    lines.extend(["", f"Integrity: {identity.get('integrity_assessment')}"])

    assoc = intel.get("potential_associates") or []
    if assoc:
        lines.extend(["", "Potential Associates"])
        for a in assoc[:3]:
            lines.append(f"- @{a.get('uniqueId')} ({a.get('count')})")

    mesh = intel.get("associate_mesh") or []
    if mesh:
        lines.extend(["", "Associate Mesh (shared social leads on comment-host bios)"])
        for row in mesh[:8]:
            au = row.get("video_author") or "?"
            ls = row.get("shared_social_leads") or []
            lines.append(f"- @{au}: " + ", ".join(ls))

    if any(
        secret.get(k) is not None
        for k in (
            "downloadSetting",
            "commentSetting",
            "duetSetting",
            "stitchSetting",
            "is_stem_verified",
            "video_label",
        )
    ):
        lines.extend(["", "Secret Stats"])
        if secret.get("downloadSetting") is not None:
            lines.append(
                f"- downloadSetting: {secret.get('downloadSetting')} ({secret.get('downloadSetting_decoded')})"
            )
        if secret.get("commentSetting") is not None:
            lines.append(
                f"- commentSetting: {secret.get('commentSetting')} ({secret.get('commentSetting_decoded')})"
            )
        if secret.get("duetSetting") is not None:
            lines.append(f"- duetSetting: {secret.get('duetSetting')} ({secret.get('duetSetting_decoded')})")
        if secret.get("stitchSetting") is not None:
            lines.append(
                f"- stitchSetting: {secret.get('stitchSetting')} ({secret.get('stitchSetting_decoded')})"
            )
        if secret.get("is_stem_verified") is not None:
            lines.append(f"- is_stem_verified: {secret.get('is_stem_verified')}")
        if secret.get("video_label") is not None:
            lines.append(f"- video_label: {secret.get('video_label')}")
        if secret.get("ai_tags_present"):
            lines.append("- ai_tags_present: true")

    ap = ev.get("avatar_local_path")
    if ap:
        lines.extend(["", f"Avatar Saved: {ap}"])
    host_av = ev.get("avatar_url")
    if host_av:
        lines.extend(["", f"Hosted Avatar URL: {host_av}"])

    ac = (pol.get("activity_clock") or {})
    if ac.get("clock_face"):
        lines.extend(
            [
                "",
                "Pattern of Life Clock (24h UTC)",
                "",
                ac.get("clock_ruler", ""),
                ac["clock_face"],
            ]
        )
        if ac.get("deduction"):
            lines.extend(["", f"Deduction: {ac['deduction']}"])

    disc = intel.get("discovered_interactions") or []
    ileads = intel.get("interaction_leads") or []
    if disc or ileads:
        lines.extend(["", "Discovered Interactions"])
        for row in disc[:15]:
            lines.append(row)
        if ileads:
            lines.append("")
            lines.append("Interaction Leads: " + ", ".join(ileads))

    lines.extend(
        [
            "",
            "Stats",
            "",
            f"Followers/Following/Likes: {stats.get('followers')} / {stats.get('following')} / {stats.get('likes')}",
            f"Videos on profile (counter): {stats.get('videos_on_profile')}",
        ]
    )
    if stats.get("content_status") == "Public":
        lines.extend(["", f"Engagement Ratio: {stats.get('engagement_ratio')}"])
    elif stats.get("content_status") == "Private" and stats.get("shadow_stats"):
        ss = stats["shadow_stats"]
        lines.extend(
            [
                "",
                f"Shadow Stats: {ss.get('followers')} / {ss.get('likes')} (Followers/Likes — non-public catalog; not an engagement ratio)",
            ]
        )
    lines.extend(["", f"Status: {stats.get('content_status')}"])

    if verify:
        lines.extend(["", f"(verify) Timestamp Verification: {verify_message or 'truth file not provided'}"])

    return "\n".join(lines)


async def run_full_investigation(
    username: str,
    *,
    evidence_root: Optional[Path] = None,
    include_avatar_base64: bool = True,
    base64_max_bytes: int = 2_000_000,
    proxy_server: Optional[str] = None,
    public_evidence_base_url: Optional[str] = None,
) -> Tuple[Dict[str, Any], Optional[int]]:
    """
    Run scanner + pivots + evidence write. Returns (json_body, http_status).
    http_status None means success for CLI; 404 for missing account.
    """
    eroot = (evidence_root if evidence_root is not None else default_evidence_dir()).resolve()
    username = (username or "").strip().lstrip("@")
    if not username:
        return {"error": "Username required", "status": "error"}, 400

    async with TikTokScanner(proxy_server=proxy_server) as scanner:
        result = await scanner.scan_username(username)

    if is_account_missing(result):
        audit = write_audit_evidence(result, username, eroot)
        return (
            {
                "error": "Account not found",
                "status": "missing",
                "username_requested": username,
                "evidence": {
                    "avatar_local_path": audit.get("avatar"),
                    "raw_json_path": audit.get("raw_json"),
                    "avatar_url": None,
                    "avatar_base64": None,
                },
            },
            404,
        )

    profile = (result.extracted_metadata or {}).get("profile") or {}
    unique_id = profile.get("uniqueId") or result.username
    signature = profile.get("signature") or ""

    found = scanner.parse_social_usernames(signature)
    ig_handles = found.get("instagram") or []
    x_handles = found.get("x") or []
    youtube_handles = found.get("youtube") or []
    github_handles = set(found.get("github") or [])
    alternate_ids = scanner.extract_alternate_identities(signature, unique_id)
    pivot_candidates = [unique_id, *ig_handles, *x_handles, *youtube_handles, *alternate_ids]
    prioritize_ig = (found.get("instagram") or [None])[0]
    deep_links = set(alternate_ids) | {h.strip().lstrip("@") for h in youtube_handles if h}
    leads = await sherlock_search(
        pivot_candidates,
        prioritize_instagram=prioritize_ig,
        github_usernames=github_handles,
        deep_link_usernames=deep_links,
    )

    evidence_dir = eroot / unique_id
    evidence_dir.mkdir(parents=True, exist_ok=True)
    avatar = profile.get("avatarLarger") or ""
    saved_avatar: Optional[Path] = None
    try:
        saved_avatar = await download_high_res_avatar(avatar, evidence_dir=evidence_dir, filename="avatar.jpg")
    except Exception:
        saved_avatar = None

    raw_json_path: Optional[str] = None
    try:
        rp = evidence_dir / "raw_scan.json"
        rp.write_text(
            json.dumps(scan_result_to_serializable(result), indent=2, default=str),
            encoding="utf-8",
        )
        raw_json_path = rp.as_posix()
    except Exception:
        pass

    evidence_paths = {
        "avatar": saved_avatar.as_posix() if saved_avatar else None,
        "raw_json": raw_json_path,
    }

    evidence_avatar_url: Optional[str] = None
    if public_evidence_base_url and saved_avatar and saved_avatar.is_file():
        evidence_avatar_url = (
            f"{public_evidence_base_url.rstrip('/')}/evidence/{quote(unique_id, safe='')}/avatar.jpg"
        )

    avatar_b64: Optional[str] = None
    if (
        include_avatar_base64
        and not evidence_avatar_url
        and saved_avatar
        and saved_avatar.is_file()
    ):
        try:
            data = saved_avatar.read_bytes()
            if len(data) <= base64_max_bytes:
                avatar_b64 = base64.standard_b64encode(data).decode("ascii")
        except Exception:
            pass

    report = build_forensic_report(
        scanner,
        result,
        leads,
        unique_id=unique_id,
        saved_avatar=saved_avatar,
        evidence_paths=evidence_paths,
        avatar_base64=avatar_b64,
        evidence_avatar_url=evidence_avatar_url,
    )
    return report, None


def write_audit_evidence(result: ScanResult, folder_name: str, evidence_root: Path) -> Dict[str, Optional[str]]:
    """Persist raw_scan.json under evidence/<folder_name>/ (e.g. missing-account audit)."""
    safe = (folder_name or "unknown").strip().lstrip("@") or "unknown"
    evidence_dir = evidence_root / safe
    evidence_dir.mkdir(parents=True, exist_ok=True)
    raw_path = evidence_dir / "raw_scan.json"
    try:
        raw_path.write_text(
            json.dumps(scan_result_to_serializable(result), indent=2, default=str),
            encoding="utf-8",
        )
        return {"raw_json": raw_path.as_posix(), "avatar": None}
    except Exception:
        return {"raw_json": None, "avatar": None}
