/**
 * Minimal B&W dashboard — POST /api/investigate → GET /api/status
 */
(function () {
  function resolveApiBase() {
    if (typeof window.LUPIN_API_BASE === "string" && window.LUPIN_API_BASE.trim()) {
      return window.LUPIN_API_BASE.trim().replace(/\/$/, "");
    }
    const staticPorts = ["5500", "5501", "3000", "4173", "5173"];
    const port = window.location.port;
    if (window.location.protocol === "file:") {
      const m = document.querySelector('meta[name="lupin-api-origin"]');
      return ((m && m.content.trim()) || "http://127.0.0.1:8080").replace(/\/$/, "");
    }
    if (port && staticPorts.includes(port)) {
      const m = document.querySelector('meta[name="lupin-api-origin"]');
      if (m && m.content.trim()) return m.content.trim().replace(/\/$/, "");
      return `http://${window.location.hostname}:8080`.replace(/\/$/, "");
    }
    return window.location.origin.replace(/\/$/, "");
  }

  const API_BASE = resolveApiBase();
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  async function readJsonResponse(res, label) {
    const text = await res.text();
    const t = text.trim();
    if (!t) throw new Error(`Empty response (${label}) HTTP ${res.status}`);
    if (t[0] === "<")
      throw new Error(
        `HTML from ${label} — API may be wrong host. Using ${API_BASE}. Try: curl -X POST ${API_BASE}/api/investigate/test -H "Accept: application/json" -d "{}"`
      );
    try {
      return JSON.parse(text);
    } catch (e) {
      throw new Error(`Bad JSON (${label}): ${e.message}`);
    }
  }

  const $ = (id) => document.getElementById(id);
  const form = $("form");
  const q = $("q");
  const btn = $("btn");
  const loading = $("loading");
  const err = $("err");
  const results = $("results");
  const rawbox = $("rawbox");
  const raw = $("raw");

  function esc(s) {
    if (s == null || s === "") return "—";
    const d = document.createElement("div");
    d.textContent = String(s);
    return d.innerHTML;
  }

  function section(title, inner) {
    return `<section>
      <h2 class="text-[10px] uppercase tracking-[0.25em] text-neutral-500 mb-4">${esc(title)}</h2>
      ${inner}
    </section>`;
  }

  function dl(rows) {
    return `<dl class="space-y-3 text-sm">
      ${rows
        .map(
          ([k, v]) =>
            `<div class="flex flex-col sm:flex-row sm:gap-4 border-b border-neutral-900 pb-3">
            <dt class="text-neutral-500 font-mono text-xs w-40 shrink-0">${esc(k)}</dt>
            <dd class="text-neutral-200 font-mono text-xs break-all">${v}</dd>
          </div>`
        )
        .join("")}
    </dl>`;
  }

  function renderReport(data, httpStatus) {
    const missing = data.status === "missing" || httpStatus === 404;
    if (missing) {
      results.innerHTML = section("Result", `<p class="text-neutral-400 text-sm">${esc(data.error || "Not found")}</p>`);
      raw.textContent = JSON.stringify(data, null, 2);
      rawbox.classList.remove("hidden");
      return;
    }

    const id = data.identity || {};
    const acc = data.account || {};
    const st = data.stats || {};
    const inf = data.infrastructure || {};
    const intel = data.intelligence || {};
    const pol = data.pattern_of_life || {};
    const sec = data.secret_stats || {};
    const ev = data.evidence || {};

    const avatarSrc = ev.avatar_url || intel.avatar_url || "";
    const avatarBlock = avatarSrc
      ? `<img src="${esc(avatarSrc)}" alt="" class="w-16 h-16 rounded-full object-cover border border-neutral-700 grayscale" />`
      : `<div class="w-16 h-16 rounded-full border border-neutral-700 bg-neutral-900"></div>`;

    const integ = id.integrity_assessment || "—";
    const summary = (data.forensic_summary || []).join(" · ") || "—";

    const statGrid = [
      ["Followers", st.followers],
      ["Following", st.following],
      ["Likes", st.likes],
      ["Videos (profile)", st.videos_on_profile],
      ["Friends", st.friends],
      ["Diggs (total)", st.diggs_total],
      ["Catalog", st.content_status],
      ...(st.content_status === "Public" && st.engagement_ratio != null
        ? [["Engagement", st.engagement_ratio]]
        : []),
    ];

    const hero = `<div class="flex gap-6 items-start">
      ${avatarBlock}
      <div class="min-w-0 flex-1">
        <p class="font-mono text-lg text-white">@${esc(id.unique_id || data.username_requested)}</p>
        <p class="text-neutral-300 mt-1">${esc(id.nickname)}</p>
        <p class="text-xs text-neutral-500 mt-3 leading-relaxed">${esc(summary)}</p>
        <p class="text-xs text-neutral-600 mt-2 font-mono">Integrity: ${esc(integ)}</p>
      </div>
    </div>`;

    const statsHtml = `<div class="grid grid-cols-2 sm:grid-cols-3 gap-4">
      ${statGrid
        .map(
          ([k, v]) =>
            `<div><p class="text-[10px] uppercase tracking-wider text-neutral-600">${esc(k)}</p>
            <p class="font-mono text-sm mt-1 text-white">${esc(v)}</p></div>`
        )
        .join("")}
    </div>`;

    const link = (u, label) =>
      u
        ? `<a class="underline text-neutral-300 hover:text-white" href="${esc(u)}" target="_blank" rel="noopener">${esc(
            label || u
          )}</a>`
        : "—";
    const accBlock = `<dl class="space-y-3 text-sm">
      <div class="flex flex-col sm:flex-row sm:gap-4 border-b border-neutral-900 pb-3">
        <dt class="text-neutral-500 font-mono text-xs w-40 shrink-0">Profile URL</dt>
        <dd class="text-xs">${link(acc.profile_url, acc.profile_url)}</dd>
      </div>
      <div class="flex flex-col sm:flex-row sm:gap-4 border-b border-neutral-900 pb-3">
        <dt class="text-neutral-500 font-mono text-xs w-40 shrink-0">Verified</dt>
        <dd class="font-mono text-xs text-neutral-200">${esc(acc.verified)}</dd>
      </div>
      <div class="flex flex-col sm:flex-row sm:gap-4 border-b border-neutral-900 pb-3">
        <dt class="text-neutral-500 font-mono text-xs w-40 shrink-0">Private</dt>
        <dd class="font-mono text-xs text-neutral-200">${esc(acc.private_account)}</dd>
      </div>
      <div class="flex flex-col sm:flex-row sm:gap-4 border-b border-neutral-900 pb-3">
        <dt class="text-neutral-500 font-mono text-xs w-40 shrink-0">Bio link</dt>
        <dd class="text-xs">${link(intel.bio_link_url || acc.bio_link_url, intel.bio_link_url || acc.bio_link_url)}</dd>
      </div>
      <div class="flex flex-col sm:flex-row sm:gap-4 border-b border-neutral-900 pb-3">
        <dt class="text-neutral-500 font-mono text-xs w-40 shrink-0">Following visibility</dt>
        <dd class="font-mono text-xs text-neutral-200">${esc(acc.following_visibility)}</dd>
      </div>
      <div class="flex flex-col sm:flex-row sm:gap-4 border-b border-neutral-900 pb-3">
        <dt class="text-neutral-500 font-mono text-xs w-40 shrink-0">FTC / Org</dt>
        <dd class="font-mono text-xs text-neutral-200">${esc(acc.ftc)} / ${esc(acc.is_organization)}</dd>
      </div>
    </dl>`;

    const idRows = [
      ["Numeric ID", id.numeric_id],
      ["SecUid", id.sec_uid],
      ["Slot reserved (UTC)", id.slot_reserved_utc],
      ["Profile created (UTC)", id.profile_finalized_utc],
      ["Last profile update", id.last_profile_update_utc],
      ["Region", id.registered_region],
      ["Language", id.primary_language],
    ];

    const infraRows = [
      ["Physical DC", inf.physical_datacenter],
      ["Server anchor", inf.server_anchor],
      ["IDC", inf.idc_code],
      ["Flags", [inf.region_spoofing_flag, inf.network_anomaly].filter(Boolean).join(" · ") || "—"],
    ];

    let secretRows = [];
    for (const k of Object.keys(sec)) {
      if (k.endsWith("_decoded")) continue;
      const dec = sec[k + "_decoded"];
      const val = sec[k];
      if (val === undefined || val === null) continue;
      const d = dec != null ? `${val} — ${dec}` : String(val);
      secretRows.push([k, d]);
    }
    if (sec.ai_tags_present) secretRows.push(["ai_tags_present", "true"]);

    const ac = pol.activity_clock || {};
    const hist = ac.utc_hour_histogram;
    let clockHtml = "";
    if (Array.isArray(hist) && hist.length === 24) {
      const mx = Math.max(1, ...hist);
      clockHtml = `<div class="flex items-end gap-0.5 h-16 mt-2">
        ${hist
          .map((n) => {
            const h = Math.max(2, (n / mx) * 100);
            const bg = n > 0 ? "background:#fff" : "background:#404040";
            const op = n > 0 ? 1 : 0.35;
            return `<div class="flex-1 rounded-sm" style="height:${h}%;${bg};opacity:${op}"></div>`;
          })
          .join("")}
      </div><p class="text-[10px] text-neutral-600 mt-2 font-mono">UTC 0–23 · ${esc(ac.deduction || "")}</p>`;
    } else {
      clockHtml = `<p class="text-xs text-neutral-600 font-mono">${esc(ac.clock_face || "No histogram")}</p>`;
    }

    const leads = intel.social_leads || [];
    const leadHtml = leads.length
      ? `<ul class="space-y-2">
        ${leads
          .map(
            (L) =>
              `<li><a class="text-sm font-mono underline text-neutral-300 hover:text-white" href="${esc(L.url)}" target="_blank" rel="noopener">${esc(L.platform)}</a> <span class="text-neutral-600 text-xs">${esc(L.status)}</span></li>`
          )
          .join("")}
      </ul>`
      : `<p class="text-xs text-neutral-600">No pivot hits.</p>`;

    const bio = intel.bio ? `<p class="text-sm text-neutral-400 leading-relaxed whitespace-pre-wrap">${esc(intel.bio)}</p>` : "";

    let extra = "";
    const disc = intel.discovered_interactions || [];
    if (disc.length)
      extra += section(
        "Discovered interactions",
        `<ul class="text-xs font-mono text-neutral-500 space-y-1">${disc.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>`
      );
    const mesh = intel.associate_mesh || [];
    if (mesh.length)
      extra += section(
        "Associate mesh",
        `<ul class="text-xs text-neutral-400 space-y-2">${mesh.map((m) => `<li>@${esc(m.video_author)}: ${esc((m.shared_social_leads || []).join(", "))}</li>`).join("")}</ul>`
      );

    results.innerHTML = [
      section("Overview", hero),
      section("Counts", statsHtml),
      section("Account flags", accBlock),
      section("Identity", dl(idRows)),
      section("Infrastructure", dl(infraRows)),
      section("Bio", bio || `<p class="text-neutral-600 text-sm">—</p>`),
      section("Social leads", leadHtml),
      section("Pattern of life", clockHtml),
      secretRows.length ? section("Secret stats", dl(secretRows.map(([k, v]) => [k, v]))) : "",
      extra,
    ]
      .filter(Boolean)
      .join("");

    raw.textContent = JSON.stringify(data, null, 2);
    rawbox.classList.remove("hidden");
  }

  async function pollJob(jobId, pollPath) {
    const url = pollPath
      ? (pollPath.startsWith("http") ? pollPath : `${API_BASE}${pollPath.startsWith("/") ? "" : "/"}${pollPath}`)
      : `${API_BASE}/api/status/${encodeURIComponent(jobId)}`;
    for (let i = 0; i < 200; i++) {
      const r = await fetch(url, { headers: { Accept: "application/json" } });
      const body = await readJsonResponse(r, "status");
      if (body.status === "completed") return body;
      if (body.status === "failed") throw new Error(body.error || "Failed");
      await sleep(1000);
    }
    throw new Error("Timed out waiting for results.");
  }

  async function runScan(username) {
    const u = username.trim().replace(/^@+/g, "");
    if (!u) return;
    err.classList.add("hidden");
    results.classList.add("hidden");
    rawbox.classList.add("hidden");
    loading.classList.remove("hidden");
    btn.disabled = true;
    q.disabled = true;

    try {
      const res = await fetch(`${API_BASE}/api/investigate/${encodeURIComponent(u)}`, {
        method: "POST",
        headers: { Accept: "application/json", "Content-Type": "application/json" },
        body: "{}",
      });
      const start = await readJsonResponse(res, "investigate");
      if (!res.ok) throw new Error(start.error || `HTTP ${res.status}`);
      const jobId = start.job_id;
      if (!jobId) throw new Error("No job_id");
      const body = await pollJob(jobId, start.poll_url);
      const result = body.result;
      if (!result) throw new Error(body.parse_error || "Empty result");
      results.classList.remove("hidden");
      renderReport(result, body.http_status);
    } catch (e) {
      err.textContent = e.message || String(e);
      err.classList.remove("hidden");
    } finally {
      loading.classList.add("hidden");
      btn.disabled = false;
      q.disabled = false;
    }
  }

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    runScan(q.value);
  });

  const qs = new URLSearchParams(window.location.search);
  const preset = qs.get("target") || qs.get("user");
  if (preset) {
    q.value = preset;
    if (window.history.replaceState) window.history.replaceState({}, "", window.location.pathname || "/");
    runScan(preset);
  }
})();
