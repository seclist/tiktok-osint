import asyncio
import json
import random
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from playwright.async_api import Browser, BrowserContext, Page, Playwright, async_playwright


class ProxyManager:
    """
    Loads proxy endpoints from config/proxies.txt (one per line).
    Used to rotate egress per investigation job — each pick_random() is independent.
    """

    DEFAULT_FILE = Path(__file__).resolve().parent / "config" / "proxies.txt"

    def __init__(self, path: Optional[Union[str, Path]] = None) -> None:
        self._path = Path(path) if path is not None else self.DEFAULT_FILE
        self._lock = threading.Lock()
        self._proxies: List[str] = []
        self.reload()

    def reload(self) -> None:
        with self._lock:
            self._proxies = self._load_file()

    def _load_file(self) -> List[str]:
        if not self._path.is_file():
            return []
        try:
            text = self._path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return []
        out: List[str] = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            out.append(line)
        return out

    def pick_random(self) -> Optional[str]:
        """Return a random proxy server URL, or None if the list is empty."""
        with self._lock:
            if not self._proxies:
                return None
            return random.choice(self._proxies)

    @property
    def proxy_count(self) -> int:
        with self._lock:
            return len(self._proxies)


REHYDRATION_KEY = "__UNIVERSAL_DATA_FOR_REHYDRATION__"
POST_ITEM_LIST_PATH = "api/post/item_list"
COMMENT_LIST_PATH = "api/comment/list"
SEARCH_ITEM_FULL_PATH = "api/search/item/full"
VERIFY_HUMAN_MARKERS = (
    "verify you are human",
    "captcha",
    "/captcha/",
    "challenge",
)


@dataclass
class ScanResult:
    username: str
    page_url: str
    api_data: Dict[str, List[Dict[str, Any]]] = field(
        default_factory=lambda: {"post_item_list": [], "comment_list": [], "search_item_full": []}
    )
    rehydration_data: Optional[Dict[str, Any]] = None
    extracted_metadata: Dict[str, Any] = field(default_factory=dict)


class TikTokScanner:
    """
    Intercepts TikTok XHR/Fetch traffic and extracts rehydration JSON from HTML.

    Note: this implementation intentionally avoids anti-bot bypass/evasion behavior.
    """

    def __init__(self, timeout_ms: int = 26000, proxy_server: Optional[str] = None) -> None:
        self.timeout_ms = timeout_ms
        self._proxy_server = (proxy_server or "").strip() or None
        self._playwright: Optional[Playwright] = None
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None
        self._api_results: Dict[str, List[Dict[str, Any]]] = {
            "post_item_list": [],
            "comment_list": [],
            "search_item_full": [],
        }
        self._visited_urls: List[str] = []
        self._pending_capture_tasks: Set[asyncio.Task] = set()

    async def __aenter__(self) -> "TikTokScanner":
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    async def start(self) -> None:
        self._playwright = await async_playwright().start()
        # headless + sandbox flags for Docker / Railway (no display, restricted namespaces)
        chromium_args = [
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--disable-dev-shm-usage",
            "--disable-gpu",
        ]
        launch_opts: Dict[str, Any] = {
            "headless": True,
            "args": chromium_args,
        }
        if self._proxy_server:
            launch_opts["proxy"] = {"server": self._proxy_server}
        self._browser = await self._playwright.chromium.launch(**launch_opts)
        self._context = await self._browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/122.0.0.0 Safari/537.36"
            ),
            viewport={"width": 1366, "height": 768},
            locale="en-US",
            timezone_id="UTC",
        )

    async def close(self) -> None:
        if self._context:
            await self._context.close()
            self._context = None
        if self._browser:
            await self._browser.close()
            self._browser = None
        if self._playwright:
            await self._playwright.stop()
            self._playwright = None

    async def scan_username(self, username: str) -> ScanResult:
        if not self._context:
            raise RuntimeError("Scanner is not started. Use `async with TikTokScanner()`.")

        self._api_results = {"post_item_list": [], "comment_list": [], "search_item_full": []}

        page = await self._context.new_page()

        def _on_request_finished(request) -> None:
            task = asyncio.create_task(self._capture_api_json(request))
            self._pending_capture_tasks.add(task)
            task.add_done_callback(lambda t: self._pending_capture_tasks.discard(t))

        page.on("requestfinished", _on_request_finished)

        profile_url = f"https://www.tiktok.com/@{username}"
        await page.goto(profile_url, wait_until="domcontentloaded", timeout=self.timeout_ms)
        self._visited_urls = [profile_url]
        await page.wait_for_timeout(2000)

        # Trigger lazy-loading of videos and wait for item_list responses.
        await self._trigger_video_load(page)
        await page.wait_for_timeout(1200)

        html = await page.content()
        rehydration_data = self._extract_rehydration_json(html)
        metadata = self._extract_hidden_metadata(rehydration_data)

        # Shadow Tracker runs only for "empty" profiles and is bounded.
        # (run after PoL is computed)
        shadow_task: Optional[asyncio.Task] = None

        # Trigger comment XHRs by opening the first visible video link (best-effort).
        video_url = await self._discover_first_video_url(page, rehydration_data)
        if video_url:
            try:
                await page.goto(video_url, wait_until="domcontentloaded", timeout=self.timeout_ms)
                self._visited_urls.append(video_url)
                await page.wait_for_timeout(4500)
            except Exception:
                pass

        # Ensure we've processed any in-flight response handlers.
        if self._pending_capture_tasks:
            await asyncio.gather(*list(self._pending_capture_tasks), return_exceptions=True)

        await page.close()

        # Post-process PoL after network captures are done.
        try:
            metadata["pattern_of_life"] = self._build_pattern_of_life(metadata, self._api_results)
        except Exception:
            metadata["pattern_of_life"] = {}

        # Interaction Discovery (The Shadow): only when itemList is empty.
        try:
            pol = metadata.get("pattern_of_life") or {}
            if int(pol.get("video_count_observed") or 0) == 0:
                profile = metadata.get("profile") or {}
                uid = str(profile.get("uniqueId") or username)
                nickname = str(profile.get("nickname") or "")
                bio = str(profile.get("signature") or "")
                target_social = self.parse_social_usernames(bio or "")
                target_mesh_handles: Dict[str, Set[str]] = {
                    "instagram": {h.strip().lower() for h in (target_social.get("instagram") or []) if h},
                    "x": {h.strip().lower() for h in (target_social.get("x") or []) if h},
                    "snapchat": {h.strip().lower() for h in (target_social.get("snapchat") or []) if h},
                    "github": {h.strip().lower() for h in (target_social.get("github") or []) if h},
                }
                shadow_task = asyncio.create_task(
                    self._shadow_tracker(
                        unique_id=uid,
                        nickname=nickname,
                        bio=bio,
                        max_comment_videos=2,
                        target_mesh_handles=target_mesh_handles,
                    )
                )
                metadata["shadow_tracker"] = await asyncio.wait_for(shadow_task, timeout=26)
            else:
                metadata["shadow_tracker"] = {}
        except Exception:
            metadata["shadow_tracker"] = {}

        # Secret stats extraction (best-effort).
        try:
            metadata["secret_stats"] = self._extract_secret_stats(rehydration_data, self._api_results)
        except Exception:
            metadata["secret_stats"] = {}

        return ScanResult(
            username=username,
            page_url=profile_url,
            api_data=self._api_results,
            rehydration_data=rehydration_data,
            extracted_metadata=metadata,
        )

    async def _trigger_video_load(self, page: Page) -> None:
        """
        TikTok profiles often lazy-load video lists. We scroll a bit and wait for
        the post item_list XHR to land (best-effort, non-fatal).
        """
        try:
            # Scroll/wait loop until itemList becomes non-empty (best-effort).
            for delta in (1000, 1600, 2200):
                await page.mouse.wheel(0, delta)
                await self._wait_for_post_item_list(page, timeout_ms=5000)
                if self._has_nonempty_post_item_list():
                    return
                await page.wait_for_timeout(450)
        except Exception:
            return

    async def _wait_for_post_item_list(self, page: Page, timeout_ms: int = 8000) -> None:
        try:
            await page.wait_for_response(lambda r: POST_ITEM_LIST_PATH in r.url, timeout=timeout_ms)
        except Exception:
            return

    async def _capture_api_json(self, request) -> None:
        url = request.url
        target_key: Optional[str] = None

        if POST_ITEM_LIST_PATH in url:
            target_key = "post_item_list"
        elif COMMENT_LIST_PATH in url:
            target_key = "comment_list"
        elif SEARCH_ITEM_FULL_PATH in url:
            target_key = "search_item_full"
        if not target_key:
            return

        try:
            response = await request.response()
            if response is None:
                return

            status = response.status
            content_type = (response.headers or {}).get("content-type", "")

            try:
                payload = await response.json()
                entry: Dict[str, Any] = {
                    "url": url,
                    "status": status,
                    "content_type": content_type,
                    "json": payload,
                }
                if target_key in {"post_item_list"} and isinstance(payload, dict):
                    entry["item_count"] = len(self._get_item_list(payload))
                self._api_results[target_key].append(entry)
                return
            except Exception:
                # Fallback: capture raw text for anti-bot pages or non-JSON payloads.
                text = await response.text()
                parsed: Optional[Any] = self._try_parse_json_from_text(text)
                parse_error: Optional[str] = None
                if parsed is None and text:
                    try:
                        json.loads(text)
                    except Exception as exc:
                        parse_error = str(exc)

                entry: Dict[str, Any] = {
                    "url": url,
                    "status": status,
                    "content_type": content_type,
                    "raw_text_preview": text[:2000],
                    "looks_like_human_verification": self._looks_like_human_verification(text),
                }
                if parsed is not None:
                    entry["json"] = parsed
                    if target_key in {"post_item_list"} and isinstance(parsed, dict):
                        entry["item_count"] = len(self._get_item_list(parsed))
                if parse_error:
                    entry["parse_error"] = parse_error
                self._api_results[target_key].append(entry)
        except Exception as exc:  # best-effort capture
            self._api_results[target_key].append({"url": url, "error": str(exc)})

    async def _shadow_tracker(
        self,
        unique_id: str,
        nickname: str,
        bio: str,
        max_comment_videos: int = 10,
        target_mesh_handles: Optional[Dict[str, Set[str]]] = None,
    ) -> Dict[str, Any]:
        """
        Aggressive search:
        - query '@uniqueId', 'uniqueId', nickname, and any bio-derived handles (e.g. ig/x)
        - gather mention/tag hits and then visit top 10 hits to inspect comments for target activity
        """
        queries: List[str] = []
        if unique_id:
            queries.extend([f"@{unique_id}", unique_id, f"\"{unique_id}\""])
        if nickname:
            queries.append(nickname)

        # Bio-link pivot: search for any extracted handles (notably IG handle).
        try:
            social = self.parse_social_usernames(bio or "")
            for k in ("instagram", "x", "github", "snapchat", "youtube"):
                for h in (social.get(k) or []):
                    if h and h not in queries:
                        queries.append(h)
        except Exception:
            pass

        # De-dupe, keep order.
        seen_q = set()
        uniq_queries = []
        for q in queries:
            q0 = (q or "").strip()
            if not q0:
                continue
            if q0.lower() in seen_q:
                continue
            seen_q.add(q0.lower())
            uniq_queries.append(q0)

        # Run searches concurrently (separate pages) to reduce wall time.
        search_pages: List[Page] = []
        try:
            if not self._context:
                return {
                    "tagged_videos": [],
                    "interaction_events": [],
                    "interaction_leads": [],
                    "associate_mesh": [],
                }

            async def run_search(q: str) -> List[Dict[str, Any]]:
                p = await self._context.new_page()
                search_pages.append(p)
                p.on("requestfinished", lambda request: self._track_capture_task(request))
                url = "https://www.tiktok.com/search?q=" + q.replace("#", "%23").replace(" ", "%20")
                try:
                    await p.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
                    await p.wait_for_timeout(900)
                    try:
                        await p.wait_for_response(lambda r: SEARCH_ITEM_FULL_PATH in r.url, timeout=6000)
                    except Exception:
                        pass
                    await p.wait_for_timeout(600)
                except Exception:
                    return []
                return self._extract_search_videos(
                    self._api_results.get("search_item_full") or [], unique_id=unique_id, query=q
                )

            # Universal use: for shadow mode we only need handle + nickname + key bio handles.
            search_tasks = [asyncio.create_task(run_search(q)) for q in uniq_queries[:3]]
            search_results_lists = await asyncio.gather(*search_tasks, return_exceptions=True)
        finally:
            for p in search_pages:
                try:
                    await p.close()
                except Exception:
                    pass

        all_hits: List[Dict[str, Any]] = []
        for res in search_results_lists:
            if isinstance(res, list):
                all_hits.extend(res)

        # Rank: prioritize explicit @uniqueId mentions first, then plain, then bio handles.
        needle_at = f"@{unique_id}".lower()
        needle_plain = unique_id.lower()

        def score(hit: Dict[str, Any]) -> int:
            d = (hit.get("desc") or "").lower()
            s = 0
            if needle_at and needle_at in d:
                s += 10
            if needle_plain and needle_plain in d:
                s += 5
            if hit.get("query") and hit["query"].lower() in d:
                s += 2
            return s

        all_hits.sort(key=score, reverse=True)

        # De-dupe by url/video_id.
        seen = set()
        deduped: List[Dict[str, Any]] = []
        for h in all_hits:
            key = h.get("url") or h.get("video_id")
            if not key or key in seen:
                continue
            seen.add(key)
            deduped.append(h)

        tagged_videos = deduped[:6]

        # Interaction Leads (Search): quoted query yields duet/stitch ecosystem (best-effort)
        duetters: Set[str] = set()
        quoted_q = f"\"{unique_id}\""
        for h in deduped:
            if (h.get("query") or "").strip() == quoted_q:
                a = h.get("author")
                if isinstance(a, str) and a and a.lower() != unique_id.lower():
                    duetters.add(a)

        # Deep comment interception: visit top N results and look for target comments.
        interaction_events: List[Dict[str, Any]] = []
        interaction_leads: Set[str] = set()
        associate_counts: Dict[str, int] = {}
        associate_mesh: List[Dict[str, Any]] = []
        mesh_scanned_authors: Set[str] = set()
        mesh_handles = target_mesh_handles or {}

        def _mesh_has_targets() -> bool:
            return any(bool(mesh_handles.get(k)) for k in ("instagram", "x", "snapchat", "github"))

        async def visit_video(v: Dict[str, Any]) -> None:
            if not self._context:
                return
            url = v.get("url")
            if not isinstance(url, str) or not url:
                return
            p = await self._context.new_page()
            p.on("requestfinished", lambda request: self._track_capture_task(request))
            before = len(self._api_results.get("comment_list") or [])
            try:
                await p.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
                await p.wait_for_timeout(1000)
                try:
                    await p.wait_for_response(lambda r: COMMENT_LIST_PATH in r.url, timeout=7000)
                except Exception:
                    pass
                await p.wait_for_timeout(800)
            except Exception:
                return
            finally:
                try:
                    await p.close()
                except Exception:
                    pass

            found = self._find_target_interaction_events(unique_id=unique_id, start_index=before, video_url=url)
            for ev in found:
                interaction_events.append(ev)
                rt = ev.get("reply_to_uniqueId")
                if isinstance(rt, str) and rt:
                    interaction_leads.add(rt)
                    associate_counts[rt] = associate_counts.get(rt, 0) + 1

            # Associate Mesh: target commented on @author — scan author's bio for shared social leads.
            author_uid = v.get("author")
            if (
                found
                and _mesh_has_targets()
                and isinstance(author_uid, str)
                and author_uid.strip()
                and author_uid.strip().lower() != unique_id.lower()
            ):
                key = author_uid.strip().lower()
                if key not in mesh_scanned_authors:
                    mesh_scanned_authors.add(key)
                    hit = await self._associate_mesh_probe_author_bio(author_uid.strip(), mesh_handles)
                    if hit:
                        associate_mesh.append(hit)

        # Limit concurrency for stability.
        sem = asyncio.Semaphore(3)

        async def guarded(v: Dict[str, Any]) -> None:
            async with sem:
                await visit_video(v)

        await asyncio.gather(
            *[asyncio.create_task(guarded(v)) for v in deduped[: max_comment_videos or 0]],
            return_exceptions=True,
        )

        return {
            "tagged_videos": tagged_videos,
            "interaction_events": interaction_events,
            "interaction_leads": sorted(interaction_leads),
            "duetters": sorted(duetters),
            "potential_associates": [
                {"uniqueId": u, "count": c}
                for u, c in sorted(associate_counts.items(), key=lambda kv: kv[1], reverse=True)[:3]
            ],
            "associate_mesh": associate_mesh,
        }

    def _track_capture_task(self, request) -> None:
        task = asyncio.create_task(self._capture_api_json(request))
        self._pending_capture_tasks.add(task)
        task.add_done_callback(lambda t: self._pending_capture_tasks.discard(t))

    def _extract_search_videos(self, search_entries: List[Dict[str, Any]], unique_id: str, query: str) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        needle = f"@{unique_id}".lower()

        for entry in search_entries:
            payload = entry.get("json")
            if not isinstance(payload, dict):
                continue
            data = payload.get("data") or payload.get("item_list") or payload.get("itemList") or []
            if not isinstance(data, list):
                continue

            for hit in data:
                if not isinstance(hit, dict):
                    continue
                item = hit.get("item") or hit.get("aweme_info") or hit.get("awemeInfo") or hit.get("aweme") or hit
                if not isinstance(item, dict):
                    continue
                desc = item.get("desc") or ""
                if not isinstance(desc, str):
                    desc = str(desc)
                if needle not in desc.lower() and unique_id.lower() not in desc.lower() and query.lower() not in desc.lower():
                    continue

                author = item.get("author") or {}
                author_uid = None
                if isinstance(author, dict):
                    author_uid = author.get("uniqueId") or author.get("unique_id")

                vid = item.get("id") or item.get("aweme_id")
                url = None
                share = item.get("shareInfo") or item.get("share_info") or {}
                if isinstance(share, dict):
                    url = share.get("shareURL") or share.get("share_url") or share.get("url")
                if not url and vid and author_uid:
                    url = f"https://www.tiktok.com/@{author_uid}/video/{vid}"

                results.append(
                    {
                        "video_id": str(vid) if vid is not None else None,
                        "url": url,
                        "author": str(author_uid) if author_uid is not None else None,
                        "desc_preview": desc[:200],
                        "desc": desc,
                        "query": query,
                        "video_create_time": item.get("createTime") or item.get("create_time"),
                    }
                )

        seen = set()
        out: List[Dict[str, Any]] = []
        for r in results:
            key = r.get("url") or r.get("video_id")
            if not key or key in seen:
                continue
            seen.add(key)
            out.append(r)
        return out

    def _find_target_interaction_events(self, unique_id: str, start_index: int, video_url: str) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        entries = (self._api_results.get("comment_list") or [])[start_index:]
        for entry in entries:
            payload = entry.get("json")
            if not isinstance(payload, dict):
                continue
            comments = payload.get("comments") or payload.get("commentList") or payload.get("comment_list") or []
            if not isinstance(comments, list):
                continue
            for c in comments:
                if not isinstance(c, dict):
                    continue
                user = c.get("user") or c.get("author") or {}
                author_uid = None
                if isinstance(user, dict):
                    author_uid = user.get("uniqueId") or user.get("unique_id")
                if (author_uid or "").lower() != unique_id.lower():
                    continue

                reply_to = c.get("reply_to_user") or c.get("replyToUser") or c.get("reply_user") or {}
                if isinstance(reply_to, dict):
                    rt_uid = reply_to.get("uniqueId") or reply_to.get("unique_id")
                else:
                    rt_uid = None

                ct = c.get("create_time") or c.get("createTime")
                if isinstance(ct, str) and ct.isdigit():
                    ct = int(ct)
                if isinstance(ct, int) and ct > 10_000_000_000:
                    ct = ct // 1000

                events.append(
                    {
                        "video_url": video_url,
                        "comment_create_time": ct,
                        "comment_time_utc": self._format_utc_timestamp(ct) if isinstance(ct, int) else None,
                        "reply_to_uniqueId": rt_uid,
                    }
                )
        return events

    def _has_nonempty_post_item_list(self) -> bool:
        for entry in (self._api_results.get("post_item_list") or []):
            if isinstance(entry, dict) and (entry.get("item_count") or 0) > 0:
                return True
        return False

    def _get_item_list(self, payload: Dict[str, Any]) -> List[Any]:
        item_list = (
            payload.get("itemList")
            or payload.get("item_list")
            or (payload.get("data") or {}).get("itemList")
            or (payload.get("data") or {}).get("item_list")
            or (payload.get("aweme_list") or payload.get("awemeList") or [])
            or []
        )
        return item_list if isinstance(item_list, list) else []

    def _try_parse_json_from_text(self, text: str) -> Optional[Any]:
        if not text:
            return None
        s = text.strip()

        # Common anti-XSSI / JS prefixes.
        for prefix in ("for (;;);", "while(1);", ")]}',"):
            if s.startswith(prefix):
                s = s[len(prefix) :].lstrip()

        # Direct JSON.
        if (s.startswith("{") and s.endswith("}")) or (s.startswith("[") and s.endswith("]")):
            try:
                return json.loads(s)
            except Exception:
                pass

        # Heuristic: find the first '{' or '[' and attempt to parse the largest suffix.
        first_obj = s.find("{")
        first_arr = s.find("[")
        starts = [i for i in (first_obj, first_arr) if i != -1]
        if not starts:
            return None
        start = min(starts)
        candidate = s[start:]

        # Try full suffix first.
        try:
            return json.loads(candidate)
        except Exception:
            pass

        # Try trimming to the last matching closing brace/bracket.
        last_curly = candidate.rfind("}")
        last_square = candidate.rfind("]")
        end = max(last_curly, last_square)
        if end != -1:
            try:
                return json.loads(candidate[: end + 1])
            except Exception:
                return None
        return None

    async def _discover_first_video_url(
        self, page: Page, rehydration_data: Optional[Dict[str, Any]]
    ) -> Optional[str]:
        # Prefer DOM discovery because rehydration often omits itemList.
        try:
            locator = page.locator("a[href*='/video/']").first
            href = await locator.get_attribute("href")
            if href:
                return self._normalize_tiktok_url(href)
        except Exception:
            pass

        # Fallback: attempt rehydration paths that sometimes include video ids.
        if rehydration_data:
            video_id = self._find_first_video_id(rehydration_data)
            if video_id:
                return f"https://www.tiktok.com/@{self._safe_get_unique_id(rehydration_data)}/video/{video_id}"

        return None

    def _find_first_video_id(self, data: Any) -> Optional[str]:
        # Look for likely fields that store video IDs.
        candidates: List[str] = []

        def walk(node: Any) -> None:
            if isinstance(node, dict):
                for k, v in node.items():
                    if k in {"vid", "videoId", "video_id", "itemId", "item_id"}:
                        if isinstance(v, (str, int)) and str(v).isdigit() and len(str(v)) >= 8:
                            candidates.append(str(v))
                    walk(v)
            elif isinstance(node, list):
                for item in node:
                    walk(item)

        walk(data)
        return candidates[0] if candidates else None

    def _safe_get_unique_id(self, rehydration_data: Dict[str, Any]) -> str:
        try:
            user = (
                rehydration_data.get("__DEFAULT_SCOPE__", {})
                .get("webapp.user-detail", {})
                .get("userInfo", {})
                .get("user", {})
            )
            unique_id = user.get("uniqueId")
            if isinstance(unique_id, str) and unique_id:
                return unique_id
        except Exception:
            pass
        return "unknown"

    def _normalize_tiktok_url(self, href: str) -> str:
        if href.startswith("http://") or href.startswith("https://"):
            return href
        if href.startswith("//"):
            return "https:" + href
        if href.startswith("/"):
            return "https://www.tiktok.com" + href
        return "https://www.tiktok.com/" + href.lstrip("/")

    def _looks_like_human_verification(self, text: str) -> bool:
        lowered = (text or "").lower()
        return any(marker in lowered for marker in VERIFY_HUMAN_MARKERS)

    def _extract_rehydration_json(self, html: str) -> Optional[Dict[str, Any]]:
        # 1) Most reliable: dedicated JSON script by id.
        id_pattern = re.compile(
            rf'<script[^>]*id="{re.escape(REHYDRATION_KEY)}"[^>]*>(.*?)</script>',
            re.DOTALL,
        )
        id_match = id_pattern.search(html)
        if id_match:
            raw = (id_match.group(1) or "").strip()
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                pass

        # 2) Assignment-style embed: window.__UNIVERSAL_DATA_FOR_REHYDRATION__ = {...};
        assignment_pattern = re.compile(
            rf"{re.escape(REHYDRATION_KEY)}\s*=\s*(\{{.*?\}})\s*;",
            re.DOTALL,
        )
        assignment_match = assignment_pattern.search(html)
        if assignment_match:
            raw = assignment_match.group(1).strip()
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                pass

        # 3) Generic script blocks containing the key (for format variations).
        script_pattern = re.compile(r"<script[^>]*>(.*?)</script>", re.DOTALL)
        for script_match in script_pattern.finditer(html):
            body = script_match.group(1)
            if REHYDRATION_KEY not in body:
                continue

            # Attempt direct script-body parse first.
            candidate = body.strip()
            if candidate.startswith("{") and candidate.endswith("}"):
                try:
                    return json.loads(candidate)
                except json.JSONDecodeError:
                    pass

            # Attempt extraction from assignment inside script body.
            nested_assignment = re.search(
                rf"{re.escape(REHYDRATION_KEY)}\s*=\s*(\{{.*\}})\s*;",
                body,
                re.DOTALL,
            )
            if nested_assignment:
                try:
                    return json.loads(nested_assignment.group(1).strip())
                except json.JSONDecodeError:
                    continue

        return None

    def _extract_hidden_metadata(self, rehydration_data: Optional[Dict[str, Any]]) -> Dict[str, List[int]]:
        if not rehydration_data:
            return {}

        profile = self._extract_profile_snapshot(rehydration_data)
        settings = self._extract_region_language_settings(rehydration_data)
        profile.update(settings)

        # Keep a small, filtered list of likely TikTok snowflake IDs for pivoting.
        snowflakes = sorted(self._extract_snowflake_ids(rehydration_data))

        return {
            "profile": profile,
            "filtered_snowflake_ids": snowflakes,
        }

    def _build_pattern_of_life(
        self, extracted_metadata: Dict[str, Any], api_data: Dict[str, List[Dict[str, Any]]]
    ) -> Dict[str, Any]:
        profile = (extracted_metadata or {}).get("profile") or {}
        follower_count_raw = ((profile.get("statsV2") or {}).get("followerCount") or "")
        follower_count = int(follower_count_raw) if str(follower_count_raw).isdigit() else None

        total_likes_raw = ((profile.get("statsV2") or {}).get("heartCount") or "")
        total_likes_profile = int(total_likes_raw) if str(total_likes_raw).isdigit() else None

        videos, associates, audit = self._extract_videos_from_post_item_list(api_data)
        videos_sorted = sorted(
            [v for v in videos if isinstance(v.get("createTime"), int)],
            key=lambda v: v["createTime"],
            reverse=True,
        )

        last_10 = videos_sorted[:10]
        exact_post_times = [
            {
                "createTime": v["createTime"],
                "utc": self._format_utc_timestamp(v["createTime"]),
                "hour_utc": datetime.fromtimestamp(v["createTime"], tz=timezone.utc).hour,
            }
            for v in last_10
            if self._format_utc_timestamp(v["createTime"]) is not None
        ]

        hours = [
            datetime.fromtimestamp(v["createTime"], tz=timezone.utc).hour
            for v in videos_sorted
            if isinstance(v.get("createTime"), int)
        ]

        sleep_gap = self._estimate_sleep_gap(hours)
        active_window = self._estimate_active_window(hours)
        inferred_region = None
        if sleep_gap and isinstance(sleep_gap, dict):
            inferred_region = self._infer_region_from_sleep_gap_utc(sleep_gap["start_hour"], sleep_gap["end_hour"])

        engagement_to_follower_ratio = None
        engagement_rating = None
        if follower_count and follower_count > 0 and total_likes_profile is not None:
            engagement_to_follower_ratio = total_likes_profile / follower_count
            if engagement_to_follower_ratio >= 100:
                engagement_rating = "Suspicious Engagement Ratio"
            elif engagement_to_follower_ratio >= 20:
                engagement_rating = "Potential Viral Content"
            else:
                engagement_rating = "Normal"

        return {
            "video_count_observed": len(videos_sorted),
            "exact_post_times_last_10": exact_post_times,
            "active_window": active_window,
            "sleep_gap": sleep_gap,
            "estimated_region": inferred_region,
            "engagement_to_follower_ratio": round(engagement_to_follower_ratio, 2)
            if engagement_to_follower_ratio is not None
            else None,
            "influencer_level": engagement_rating,
            "known_associates": associates,
            "metadata_audit": audit,
        }

    def _extract_videos_from_post_item_list(
        self, api_data: Dict[str, List[Dict[str, Any]]]
    ) -> Tuple[List[Dict[str, Any]], Dict[str, int], Dict[str, Any]]:
        videos: List[Dict[str, Any]] = []
        known_associates: Dict[str, int] = {}
        audit: Dict[str, Any] = {
            "per_video_hardware": [],
        }

        entries = (api_data or {}).get("post_item_list") or []
        for entry in entries:
            payload = entry.get("json")

            if not isinstance(payload, dict):
                continue
            item_list = self._get_item_list(payload)
            if not item_list:
                continue

            for item in item_list:
                if not isinstance(item, dict):
                    continue
                ct = item.get("createTime") or item.get("create_time")
                if isinstance(ct, str) and ct.isdigit():
                    ct = int(ct)
                if not isinstance(ct, int):
                    continue

                stats = item.get("stats") or {}
                desc = item.get("desc") or item.get("description") or ""
                if not isinstance(desc, str):
                    desc = str(desc)

                mentions = self._extract_mentions(desc)
                for m in mentions:
                    known_associates[m] = known_associates.get(m, 0) + 1

                # Deep item scan for hardware signatures.
                deep = self._scan_item_for_keys(item, keys=("device_platform", "app_name", "build_number", "region"))
                vid = item.get("id")
                # Two decoders:
                # - decode_tiktok_id: top-32-bit timestamp heuristic (seconds)
                # - decode_snowflake_id: millisecond-level snowflake heuristic (may be false if epoch differs)
                decoded_sec = self.decode_tiktok_id(vid)
                decoded_ms = self.decode_snowflake_id(vid)
                ghost = self._ghost_link(deep, decoded_ms, set())
                if len(audit["per_video_hardware"]) < 10:
                    audit["per_video_hardware"].append(
                        {
                            "video_id": str(vid) if vid is not None else None,
                            "device_platform": deep.get("device_platform"),
                            "app_name": deep.get("app_name"),
                            "build_number": deep.get("build_number"),
                            "region": deep.get("region"),
                            "id_decode_seconds": decoded_sec,
                            "id_decode_millis": decoded_ms,
                            "ghost_link": ghost,
                        }
                    )

                videos.append(
                    {
                        "createTime": ct,
                        "id": item.get("id"),
                        "diggCount": stats.get("diggCount") or stats.get("digg_count"),
                        "shareCount": stats.get("shareCount") or stats.get("share_count"),
                        "commentCount": stats.get("commentCount") or stats.get("comment_count"),
                        "desc": desc,
                        "mentions": mentions,
                    }
                )

        return videos, known_associates, audit

    def _scan_item_for_keys(self, item: Dict[str, Any], keys: Tuple[str, ...]) -> Dict[str, Optional[str]]:
        found: Dict[str, Optional[str]] = {k: None for k in keys}

        def walk(node: Any) -> None:
            if all(found[k] is not None for k in keys):
                return
            if isinstance(node, dict):
                for k, v in node.items():
                    if isinstance(k, str) and k in found and found[k] is None:
                        if isinstance(v, (str, int, float)) and str(v):
                            found[k] = str(v)
                    walk(v)
            elif isinstance(node, list):
                for it in node:
                    walk(it)

        walk(item)
        return found

    def decode_snowflake_id(self, video_id: Any) -> Dict[str, Any]:
        """
        Best-effort Snowflake-style decoder.
        Many platforms use: (timestamp_ms << 22) | (machine_id << 12) | sequence.
        This uses the Twitter epoch (1288834974657) as a common default.
        """
        raw = None
        if isinstance(video_id, int):
            raw = video_id
        elif isinstance(video_id, str) and video_id.isdigit():
            raw = int(video_id)
        if raw is None:
            return {"raw": video_id, "decoded": False}

        epoch_ms = 1288834974657
        ts_part = raw >> 22
        machine_id = (raw >> 12) & 0x3FF
        sequence = raw & 0xFFF
        ts_ms = ts_part + epoch_ms

        # Plausibility guard (2014..2035)
        try:
            dt = datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc)
            if dt.year < 2014 or dt.year > 2035:
                return {
                    "raw": str(raw),
                    "decoded": False,
                    "note": "timestamp out of plausible range for default epoch",
                    "machine_id": machine_id,
                    "sequence": sequence,
                }
            return {
                "raw": str(raw),
                "decoded": True,
                "timestamp_utc": dt.strftime("%Y-%m-%d %H:%M:%S"),
                "machine_id": machine_id,
                "sequence": sequence,
                "epoch_ms_assumed": epoch_ms,
            }
        except Exception:
            return {"raw": str(raw), "decoded": False, "machine_id": machine_id, "sequence": sequence}

    def decode_tiktok_id(self, id_val: Any) -> Dict[str, Any]:
        """
        Universal TikTok ID decoder (best-effort).

        Observed for many TikTok 64-bit IDs:
        - Top 32 bits (bits 63..32) resemble a Unix timestamp in seconds.
        - Next 10 bits (bits 31..22) can be treated as an internal shard/machine id.

        This is an observational heuristic; treat as forensic hint, not ground truth.
        """
        raw_int: Optional[int] = None
        if isinstance(id_val, int):
            raw_int = id_val
        elif isinstance(id_val, str) and id_val.isdigit():
            raw_int = int(id_val)

        if raw_int is None:
            return {"raw": id_val, "decoded": False}

        # Force to 64-bit unsigned representation for binary display.
        raw_64 = raw_int & ((1 << 64) - 1)
        b64 = format(raw_64, "064b")

        ts_seconds = (raw_64 >> 32) & 0xFFFFFFFF
        machine_id = (raw_64 >> 22) & 0x3FF  # bits 31..22

        ts_str = None
        try:
            dt = datetime.fromtimestamp(ts_seconds, tz=timezone.utc)
            ts_str = dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            ts_str = None

        return {
            "raw": str(raw_int),
            "decoded": True,
            "binary_64": b64,
            "timestamp_seconds": ts_seconds,
            "timestamp_utc": ts_str,
            "machine_id": machine_id,
        }

    def _ghost_link(self, deep: Dict[str, Optional[str]], decoded: Dict[str, Any], profile_device_ids: Set[str]) -> Dict[str, Any]:
        """
        Compare any device_id-ish values/machine_id against profile-level device_id.
        """
        match_device_id = None
        device_id_in_item = deep.get("device_id") if isinstance(deep, dict) else None
        if device_id_in_item and profile_device_ids:
            match_device_id = device_id_in_item in profile_device_ids

        return {
            "profile_device_ids_observed": sorted(profile_device_ids),
            "device_id_in_item": device_id_in_item,
            "device_id_matches_profile": match_device_id,
            "machine_id": decoded.get("machine_id") if isinstance(decoded, dict) else None,
        }

    def _extract_region_language_settings(self, rehydration_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract region / address_book_region and language settings from rehydration JSON.
        """
        keys = {"region", "address_book_region", "language", "content_language", "app_language"}
        found: Dict[str, str] = {}

        def walk(node: Any) -> None:
            if len(found) == len(keys):
                return
            if isinstance(node, dict):
                for k, v in node.items():
                    if isinstance(k, str) and k in keys and isinstance(v, str) and v:
                        found.setdefault(k, v)
                    walk(v)
            elif isinstance(node, list):
                for it in node:
                    walk(it)

        walk(rehydration_data)

        # Normalize into report-friendly names.
        return {
            "registered_region": found.get("address_book_region") or found.get("region"),
            "primary_language": found.get("language") or found.get("app_language"),
            "content_language": found.get("content_language"),
        }

    def _extract_mentions(self, text: str) -> List[str]:
        if not text:
            return []
        handles = []
        seen = set()
        for m in re.finditer(r"@([A-Za-z0-9._]{2,24})", text):
            h = m.group(1)
            if not h:
                continue
            key = h.lower()
            if key in seen:
                continue
            seen.add(key)
            handles.append(h)
        return handles

    def _extract_system_strings(self, item: Dict[str, Any]) -> Set[str]:
        """
        Best-effort audit: scan item metadata for OS/device hints.
        """
        needles = ("iphone", "ipad", "ios", "android", "samsung", "pixel", "huawei", "xiaomi", "windows", "mac")
        found: Set[str] = set()

        def walk(node: Any) -> None:
            if isinstance(node, dict):
                for k, v in node.items():
                    walk(k)
                    walk(v)
            elif isinstance(node, list):
                for it in node:
                    walk(it)
            elif isinstance(node, str):
                low = node.lower()
                for n in needles:
                    if n in low:
                        found.add(n)

        # Only scan a subset of likely metadata fields if present.
        for key in ("source", "shareInfo", "video", "music", "textExtra", "challenges", "poi"):
            if key in item:
                walk(item.get(key))
        return found

    def _classify_hardware(self, dp: Optional[str], os_name: Optional[str]) -> str:
        dp_l = (dp or "").lower()
        os_l = (os_name or "").lower()
        if "android" in dp_l or "android" in os_l:
            return "Android"
        if "ios" in dp_l or "iphone" in dp_l or "ios" in os_l:
            return "iOS"
        if "web" in dp_l or "windows" in os_l or "mac" in os_l:
            return "Web"
        return "Unknown"

    def _estimate_sleep_gap(self, hours_utc: List[int]) -> Optional[Dict[str, int]]:
        if not hours_utc:
            return None
        present = [False] * 24
        for h in hours_utc:
            if isinstance(h, int) and 0 <= h <= 23:
                present[h] = True

        # Find longest consecutive gap in circular 24h.
        best_len = 0
        best_start = None
        cur_len = 0
        cur_start = None

        for i in range(48):
            h = i % 24
            if not present[h]:
                if cur_len == 0:
                    cur_start = h
                cur_len += 1
                if cur_len > best_len:
                    best_len = cur_len
                    best_start = cur_start
            else:
                cur_len = 0
                cur_start = None

        if best_len < 6 or best_start is None:
            return None

        end = (best_start + best_len) % 24
        return {"start_hour": best_start, "end_hour": end, "length_hours": best_len}

    def _estimate_active_window(self, hours_utc: List[int], window_hours: int = 4) -> Optional[Dict[str, int]]:
        if not hours_utc:
            return None
        counts = [0] * 24
        for h in hours_utc:
            if isinstance(h, int) and 0 <= h <= 23:
                counts[h] += 1

        best_sum = -1
        best_start = 0
        for start in range(24):
            s = 0
            for i in range(window_hours):
                s += counts[(start + i) % 24]
            if s > best_sum:
                best_sum = s
                best_start = start

        end = (best_start + window_hours) % 24
        return {"start_hour": best_start, "end_hour": end, "window_hours": window_hours, "samples": best_sum}

    def _infer_region_from_sleep_gap_utc(self, start_hour_utc: int, end_hour_utc: int) -> str:
        """
        Heuristic:
        - Assume typical local sleep ~00:00–08:00.
        - If sleep gap starts at H_utc, then local midnight likely aligns to H_utc.
          Offset ≈ -H_utc hours (UTC -> local).
        """
        try:
            h = int(start_hour_utc) % 24
        except Exception:
            return "Unknown"

        # Offset in hours (local = UTC + offset)
        offset = (-h) % 24
        # Convert to signed offset in [-12, +14] like real timezones.
        if offset > 14:
            offset -= 24

        # Map common offsets to regions.
        common = {
            0: "GMT/UK (UTC+0)",
            1: "Central Europe (UTC+1)",
            2: "Eastern Europe (UTC+2)",
            3: "Turkey/Moscow-ish (UTC+3)",
            5.5: "India (UTC+5:30)",
            8: "China/Singapore (UTC+8)",
            9: "Japan/Korea (UTC+9)",
            10: "Australia East (UTC+10)",
            -5: "US Eastern (UTC-5)",
            -6: "US Central (UTC-6)",
            -7: "US Mountain (UTC-7)",
            -8: "US Pacific (UTC-8)",
        }

        if offset in common:
            return common[offset]
        if offset == 5:
            return "Pakistan (UTC+5)"
        if offset == 4:
            return "Gulf/Armenia-ish (UTC+4)"
        if offset == -4:
            return "US Eastern (DST) / Atlantic (UTC-4)"
        if offset == 11:
            return "Australia East (DST) / Pacific (UTC+11)"

        sign = "+" if offset >= 0 else "-"
        return f"Approx. UTC{sign}{abs(offset)}"

    def _extract_profile_snapshot(self, rehydration_data: Dict[str, Any]) -> Dict[str, Any]:
        user: Dict[str, Any] = (
            rehydration_data.get("__DEFAULT_SCOPE__", {})
            .get("webapp.user-detail", {})
            .get("userInfo", {})
            .get("user", {})
        )
        stats_v2: Dict[str, Any] = (
            rehydration_data.get("__DEFAULT_SCOPE__", {})
            .get("webapp.user-detail", {})
            .get("userInfo", {})
            .get("statsV2", {})
        )

        create_time = user.get("createTime")
        modify_time = user.get("nickNameModifyTime")

        bio_link_url: Optional[str] = None
        bl = user.get("bioLink") or user.get("bio_link")
        if isinstance(bl, dict):
            bio_link_url = bl.get("link") or bl.get("url") or bl.get("riskUrl")

        stats_flat: Dict[str, Any] = dict(stats_v2) if isinstance(stats_v2, dict) else {}

        profile: Dict[str, Any] = {
            "nickname": user.get("nickname"),
            "uniqueId": user.get("uniqueId"),
            "numeric_id": user.get("id"),
            "secUid": user.get("secUid"),
            "signature": user.get("signature"),
            "avatarLarger": user.get("avatarLarger"),
            "account_created": self._format_utc_timestamp(create_time),
            "last_profile_update": self._format_utc_timestamp(modify_time),
            "statsV2": {
                "followerCount": stats_flat.get("followerCount"),
                "followingCount": stats_flat.get("followingCount"),
                "heartCount": stats_flat.get("heartCount"),
                "videoCount": stats_flat.get("videoCount"),
                "friendCount": stats_flat.get("friendCount"),
                "diggCount": stats_flat.get("diggCount"),
            },
            "statsV2_raw": stats_flat,
            "account_details": {
                "verified": user.get("verified"),
                "private_account": user.get("secret"),
                "following_visibility": user.get("followingVisibility"),
                "show_favorite": user.get("showFavorite"),
                "open_favorite": user.get("openFavorite"),
                "ftc": user.get("ftc"),
                "is_organization": user.get("isOrganization"),
                "bio_link_url": bio_link_url,
                "avatar_thumb": user.get("avatarThumb") or user.get("avatarMedium"),
                "comment_setting_user": user.get("commentSetting"),
                "duet_setting_user": user.get("duetSetting"),
                "stitch_setting_user": user.get("stitchSetting"),
                "download_setting_user": user.get("downloadSetting"),
            },
        }
        # ID forensics: decode the numeric user id into timestamp + internal shard.
        profile["id_forensics"] = self.decode_tiktok_id(profile.get("numeric_id"))
        avatar_url = profile.get("avatarLarger")
        shard_anchor = self._decode_avatar_storage_shard(avatar_url)
        idc_anchor = self._decode_idc_region(avatar_url)
        profile["geographic_anchor"] = shard_anchor or idc_anchor
        profile["idc_code"] = self._extract_avatar_idc(avatar_url)
        profile["physical_datacenter"] = self._physical_datacenter_note(avatar_url)
        return profile

    def _extract_avatar_idc(self, avatar_url: Any) -> Optional[str]:
        if not isinstance(avatar_url, str) or not avatar_url:
            return None
        try:
            qs = parse_qs(urlparse(avatar_url).query)
            idc = (qs.get("idc") or [None])[0]
            if isinstance(idc, str) and idc:
                return idc.lower()
        except Exception:
            pass
        return None

    def _physical_datacenter_note(self, avatar_url: Any) -> Optional[str]:
        """
        Known TikTok CDN idc → public-ish datacenter labels (heuristic).
        """
        if isinstance(avatar_url, str) and "tos-maliva" in avatar_url.lower():
            return "Global Shard (Multi-Region)"
        idc_l = self._extract_avatar_idc(avatar_url)
        if idc_l == "no1a":
            return "Physical Data Center: Dublin, Ireland (TikTok Europe Core)"
        if idc_l in {"useast2a", "useast5"}:
            return "Physical Data Center: Virginia, USA"
        if isinstance(avatar_url, str) and "tos-useast2a" in avatar_url.lower():
            return "Physical Data Center: Virginia, USA"
        if isinstance(avatar_url, str) and "tos-useast5" in avatar_url.lower():
            return "Physical Data Center: Virginia, USA"
        return None

    def _decode_idc_region(self, avatar_url: Any) -> Optional[str]:
        """
        Parse `idc=` from TikTok CDN URLs and map to a likely geographic anchor.
        Heuristic only.
        """
        idc_l = self._extract_avatar_idc(avatar_url)
        if not idc_l:
            return None

        mapping = {
            # Observational sharding hints; not authoritative.
            "no1a": "Europe (EU shard)",
            "no1": "Europe (EU shard)",
            "alisg": "Asia (SG shard)",
            "sg": "Asia (SG shard)",
            "useast1": "North America (US-East shard)",
            "useast2a": "North America (US-East shard)",
            "useast2": "North America (US-East shard)",
            "useast5": "Virginia, USA",
            "usw2": "North America (US-West shard)",
            "maliva": "Middle East/Africa (MENA shard)",
        }
        return mapping.get(idc_l, f"Unknown shard ({idc_l})")

    async def _associate_mesh_probe_author_bio(
        self, author_unique_id: str, target_handles: Dict[str, Set[str]]
    ) -> Optional[Dict[str, Any]]:
        """
        When the target commented on this author's video, load the author's profile HTML and
        compare parsed bio handles to the target's social leads (co-managed / associate signal).
        """
        if not self._context:
            return None
        page: Optional[Page] = None
        try:
            page = await self._context.new_page()
            await page.goto(
                f"https://www.tiktok.com/@{author_unique_id}",
                wait_until="domcontentloaded",
                timeout=self.timeout_ms,
            )
            await page.wait_for_timeout(700)
            html = await page.content()
        except Exception:
            return None
        finally:
            if page:
                try:
                    await page.close()
                except Exception:
                    pass

        red = self._extract_rehydration_json(html)
        if not red:
            return None
        prof = self._extract_profile_snapshot(red)
        sig = prof.get("signature") or ""
        if not isinstance(sig, str):
            sig = str(sig)
        theirs = self.parse_social_usernames(sig)
        shared: List[str] = []
        for plat in ("instagram", "x", "snapchat", "github"):
            tset = target_handles.get(plat) or set()
            if not tset:
                continue
            for h in theirs.get(plat) or []:
                hn = (h or "").strip().lower()
                if hn and hn in tset:
                    shared.append(f"{plat}:{(h or '').strip()}")
        if not shared:
            return None
        return {"video_author": author_unique_id, "shared_social_leads": shared}

    def _extract_secret_stats(self, rehydration_data: Optional[Dict[str, Any]], api_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Best-effort extraction of internal flags:
        - downloadSetting
        - is_stem_verified
        - video_label / AI tags
        """
        out: Dict[str, Any] = {}
        keys = {
            "downloadSetting",
            "commentSetting",
            "duetSetting",
            "stitchSetting",
            "is_stem_verified",
            "video_label",
            "aigc",
            "ai",
            "aiGenerated",
            "is_ai_generated",
        }

        def walk(node: Any) -> None:
            if isinstance(node, dict):
                for k, v in node.items():
                    if isinstance(k, str) and k in keys:
                        out.setdefault(k, v)
                    walk(v)
            elif isinstance(node, list):
                for it in node:
                    walk(it)

        if rehydration_data:
            walk(rehydration_data)
        # Also scan captured search payloads (often include content labels).
        for entry in (api_data or {}).get("search_item_full") or []:
            payload = entry.get("json")
            if isinstance(payload, dict):
                walk(payload)

        def decode_setting(key: str, val: Any) -> Optional[str]:
            if val is None:
                return None
            try:
                v = int(val)
            except Exception:
                return str(val)
            if key == "downloadSetting":
                return "Enabled" if v == 0 else "Disabled" if v == 1 else str(v)
            if key == "commentSetting":
                return "Everyone" if v == 0 else "Friends" if v == 1 else "Off" if v == 3 else str(v)
            if key in {"duetSetting", "stitchSetting"}:
                return "Everyone" if v == 0 else "Off" if v == 3 else str(v)
            return str(v)

        return {
            "downloadSetting": out.get("downloadSetting"),
            "downloadSetting_decoded": decode_setting("downloadSetting", out.get("downloadSetting")),
            "commentSetting": out.get("commentSetting"),
            "commentSetting_decoded": decode_setting("commentSetting", out.get("commentSetting")),
            "duetSetting": out.get("duetSetting"),
            "duetSetting_decoded": decode_setting("duetSetting", out.get("duetSetting")),
            "stitchSetting": out.get("stitchSetting"),
            "stitchSetting_decoded": decode_setting("stitchSetting", out.get("stitchSetting")),
            "is_stem_verified": out.get("is_stem_verified"),
            "video_label": out.get("video_label"),
            "ai_tags_present": any(k in out for k in ("aigc", "ai", "aiGenerated", "is_ai_generated")),
        }

    def _decode_avatar_storage_shard(self, avatar_url: Any) -> Optional[str]:
        """
        Some TikTok CDN URLs embed a storage shard like 'tos-useast2a'.
        """
        if not isinstance(avatar_url, str) or not avatar_url:
            return None
        lower = avatar_url.lower()
        m = re.search(r"tos-([a-z0-9]+)", lower)
        if not m:
            return None
        code = m.group(1)
        mapping = {
            "useast2a": "US East (useast2a shard)",
            "useast2": "US East",
            "useast5": "Virginia, USA",
            "maliva": "Global Shard (Multi-Region)",
            "usw2": "US West",
            "sg": "Asia (SG)",
            "alisg": "Asia (SG)",
            "no1a": "Europe (EU shard)",
        }
        return mapping.get(code, f"Unknown shard (tos-{code})")

    def infer_region_spoofing_flag(self, registered_region: Optional[str], avatar_url: str) -> Optional[str]:
        reg = (registered_region or "").upper()
        shard = (self._decode_avatar_storage_shard(avatar_url) or "").lower()
        if reg == "GB" and "us east" in shard:
            return "Potential Region Spoofing / US-Managed Account"
        return None

    def infer_network_anomaly(self, registered_region: Optional[str], server_anchor: Optional[str]) -> Optional[str]:
        """
        Infrastructure Audit: compare registered region to server anchor (heuristic).
        """
        reg = (registered_region or "").upper()
        anchor = (server_anchor or "").lower()
        if not reg or not anchor:
            return None

        region_to_group = {
            "GB": "europe",
            "FR": "europe",
            "DE": "europe",
            "ES": "europe",
            "IT": "europe",
            "US": "us",
            "CA": "us",
            "MX": "us",
            "JP": "asia",
            "KR": "asia",
            "SG": "asia",
            "CN": "asia",
            "IN": "asia",
            "AU": "oceania",
        }
        reg_group = region_to_group.get(reg)
        if not reg_group:
            return None

        anchor_group = None
        if "us " in anchor or "us-" in anchor or "useast" in anchor or "us west" in anchor:
            anchor_group = "us"
        elif "europe" in anchor or "eu shard" in anchor:
            anchor_group = "europe"
        elif "asia" in anchor or "sg" in anchor:
            anchor_group = "asia"
        elif "oceania" in anchor or "australia" in anchor:
            anchor_group = "oceania"

        if anchor_group and anchor_group != reg_group:
            return "Network Anomaly: Cross-Regional Management Detected"
        return None

    def extract_alternate_identities(self, signature: str, unique_id: str) -> List[str]:
        """
        Pull alternate handles from bio text that differ from the TikTok uniqueId.
        Includes labeled handles (ig/x/github/snap) and generic @mentions.
        """
        base = (unique_id or "").strip().lstrip("@").lower()
        found = self.parse_social_usernames(signature or "")
        candidates: List[str] = []
        for k in ("instagram", "x", "github", "snapchat", "youtube"):
            candidates.extend(found.get(k) or [])
        candidates.extend(self._extract_mentions(signature or ""))

        out: List[str] = []
        seen = set()
        for c in candidates:
            c0 = (c or "").strip().lstrip("@")
            if not c0:
                continue
            if c0.lower() == base:
                continue
            if c0.lower() in seen:
                continue
            seen.add(c0.lower())
            out.append(c0)
        return out

    def parse_social_usernames(self, signature: str) -> Dict[str, List[str]]:
        """
        Extract cross-platform handles from the bio/signature.
        Returns keys: instagram, snapchat (also includes sc/snap prefixes), github, x.
        """
        text = (signature or "").strip()
        if not text:
            return {"instagram": [], "snapchat": [], "github": [], "x": [], "youtube": []}

        # Instagram profile URLs (exclude /p/, /reel/, etc.)
        _ig_url = r"(?:https?://)?(?:www\.)?instagram\.com/(?!p/|reel/|reels/|stories/|explore/|accounts/)([A-Za-z0-9._]{1,30})/?"
        _x_url = r"(?:https?://)?(?:www\.)?(?:x\.com|twitter\.com)/([A-Za-z0-9_]{1,30})/?"
        _yt_url = r"(?:https?://)?(?:www\.)?youtube\.com/(?:@|c/|channel/|user/)([A-Za-z0-9._-]{1,100})/?"

        patterns = {
            "instagram": [
                r"\big\s*[-:]\s*@?([A-Za-z0-9._]{1,30})\b",
                r"\binsta\s*[-:]\s*@?([A-Za-z0-9._]{1,30})\b",
                r"\binstagram\s*[-:]\s*@?([A-Za-z0-9._]{1,30})\b",
                _ig_url,
            ],
            "snapchat": [
                r"\bsc\s*[-:]\s*@?([A-Za-z0-9._-]{1,30})\b",
                r"\bsnap\s*[-:]\s*@?([A-Za-z0-9._-]{1,30})\b",
                r"\bsnapchat\s*[-:]\s*@?([A-Za-z0-9._-]{1,30})\b",
            ],
            "github": [
                r"\bgh\s*[-:]\s*@?([A-Za-z0-9-]{1,39})\b",
                r"\bgithub\s*[-:]\s*@?([A-Za-z0-9-]{1,39})\b",
                r"(?:https?://)?(?:www\.)?github\.com/([A-Za-z0-9-]{1,39})/?",
            ],
            "x": [
                r"\bx\s*[-:]\s*@?([A-Za-z0-9_]{1,30})\b",
                r"\btwitter\s*[-:]\s*@?([A-Za-z0-9_]{1,30})\b",
                _x_url,
            ],
            "youtube": [
                r"\byt\s*[-:]\s*@?([A-Za-z0-9._-]{1,100})\b",
                r"\byoutube\s*[-:]\s*@?([A-Za-z0-9._-]{1,100})\b",
                _yt_url,
            ],
        }

        out: Dict[str, List[str]] = {"instagram": [], "snapchat": [], "github": [], "x": [], "youtube": []}
        for platform, pats in patterns.items():
            seen = set()
            for pat in pats:
                for m in re.finditer(pat, text, flags=re.IGNORECASE):
                    handle = (m.group(1) or "").strip().lstrip("@")
                    if handle and handle.lower() not in seen:
                        seen.add(handle.lower())
                        out[platform].append(handle)
        return out

    def _format_utc_timestamp(self, ts: Any) -> Optional[str]:
        # Accept seconds (int/str). Return 'YYYY-MM-DD HH:MM:SS' in UTC.
        if ts is None:
            return None
        if isinstance(ts, str):
            if not ts.isdigit():
                return None
            ts_int = int(ts)
        elif isinstance(ts, int):
            ts_int = ts
        else:
            return None

        # Convert ms -> seconds if needed.
        if ts_int >= 10_000_000_000:
            ts_int = ts_int // 1000

        if not (1_000_000_000 <= ts_int <= 9_999_999_999):
            return None

        dt = datetime.fromtimestamp(ts_int, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S")

    def _extract_snowflake_ids(self, data: Any) -> Set[int]:
        # TikTok IDs are commonly 19-digit snowflakes starting with '7'.
        ids: Set[int] = set()

        def walk(node: Any) -> None:
            if isinstance(node, dict):
                for v in node.values():
                    walk(v)
            elif isinstance(node, list):
                for item in node:
                    walk(item)
            elif isinstance(node, int):
                s = str(node)
                if len(s) == 19 and s.startswith("7"):
                    ids.add(node)
            elif isinstance(node, str) and node.isdigit():
                if len(node) == 19 and node.startswith("7"):
                    ids.add(int(node))

        walk(data)
        return ids
