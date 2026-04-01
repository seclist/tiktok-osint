import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

import httpx


@dataclass(frozen=True)
class LeadResult:
    platform: str
    username: str
    url: str
    status: str  # Found | Not Found | Unknown
    http_status: Optional[int] = None


IG_X_PLATFORMS: Tuple[Tuple[str, str], ...] = (
    ("Instagram", "https://www.instagram.com/{u}/"),
    ("X", "https://x.com/{u}"),
)

GITHUB_PLATFORM: Tuple[str, str] = ("GitHub", "https://github.com/{u}")
DEEP_LINK_PLATFORMS: Tuple[Tuple[str, str], ...] = (
    ("YouTube", "https://www.youtube.com/@{u}"),
    ("Pinterest", "https://www.pinterest.com/{u}/"),
)


async def _probe_profile(client: httpx.AsyncClient, platform: str, username: str, url: str) -> LeadResult:
    headers = {
        "user-agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/122.0.0.0 Safari/537.36"
        )
    }

    # Some platforms respond poorly to HEAD; we try HEAD then a tiny GET fallback.
    try:
        r = await client.head(url, headers=headers)
        code = r.status_code
    except Exception:
        code = None

    if code is None or code in {403, 405, 429}:
        try:
            r = await client.get(url, headers={**headers, "range": "bytes=0-0"})
            code = r.status_code
        except Exception:
            code = None

    if code == 200:
        return LeadResult(platform=platform, username=username, url=url, status="Found", http_status=code)
    if code == 404:
        return LeadResult(platform=platform, username=username, url=url, status="Not Found", http_status=code)
    return LeadResult(platform=platform, username=username, url=url, status="Unknown", http_status=code)


async def sherlock_search(
    usernames: Iterable[str],
    prioritize_instagram: Optional[str] = None,
    github_usernames: Optional[Set[str]] = None,
    deep_link_usernames: Optional[Set[str]] = None,
) -> Dict[str, List[LeadResult]]:
    uniq: List[str] = []
    seen = set()
    for u in usernames:
        u = (u or "").strip().lstrip("@")
        if not u or u in seen:
            continue
        seen.add(u)
        uniq.append(u)

    if prioritize_instagram:
        ig = prioritize_instagram.strip().lstrip("@")
        if ig and ig in uniq:
            uniq.remove(ig)
            uniq.insert(0, ig)

    limits = httpx.Limits(max_keepalive_connections=10, max_connections=20)
    timeout = httpx.Timeout(6.0, connect=5.0)
    results: Dict[str, List[LeadResult]] = {u: [] for u in uniq}
    github_usernames = set(github_usernames or [])
    deep_link_usernames = set(deep_link_usernames or [])

    async with httpx.AsyncClient(follow_redirects=True, timeout=timeout, limits=limits) as client:
        tasks = []
        for u in uniq:
            for platform, template in IG_X_PLATFORMS:
                url = template.format(u=u)
                tasks.append((u, asyncio.create_task(_probe_profile(client, platform, u, url))))
            if u in github_usernames:
                platform, template = GITHUB_PLATFORM
                url = template.format(u=u)
                tasks.append((u, asyncio.create_task(_probe_profile(client, platform, u, url))))
            if u in deep_link_usernames:
                for platform, template in DEEP_LINK_PLATFORMS:
                    url = template.format(u=u)
                    tasks.append((u, asyncio.create_task(_probe_profile(client, platform, u, url))))

        for u, task in tasks:
            res = await task
            results[u].append(res)

    return results


async def download_high_res_avatar(avatar_url: str, evidence_dir: Path, filename: str = "avatar.jpg") -> Optional[Path]:
    if not avatar_url:
        return None

    evidence_dir.mkdir(parents=True, exist_ok=True)
    target = evidence_dir / filename

    headers = {
        "user-agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/122.0.0.0 Safari/537.36"
        )
    }

    timeout = httpx.Timeout(12.0, connect=6.0)
    async with httpx.AsyncClient(follow_redirects=True, timeout=timeout) as client:
        r = await client.get(avatar_url, headers=headers)
        r.raise_for_status()
        target.write_bytes(r.content)

    return target
