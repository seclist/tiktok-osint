/**
 * Lupin Logic OSINT Dashboard
 * API: POST /api/investigate/<user> → poll GET /api/status/<job_id>
 *
 * If you use Live Server (e.g. :5500), set meta lupin-api-origin or LUPIN_API_BASE to your API (default :8080).
 * Override anytime: <script>window.LUPIN_API_BASE='http://127.0.0.1:8000'</script> before main.js
 */
(function () {
  function resolveApiBase() {
    if (typeof window.LUPIN_API_BASE === "string" && window.LUPIN_API_BASE.trim()) {
      return window.LUPIN_API_BASE.trim().replace(/\/$/, "");
    }
    const staticPorts = ["5500", "5501", "3000", "4173", "5173"];
    const port = window.location.port;
    if (window.location.protocol === "file:") {
      const meta = document.querySelector('meta[name="lupin-api-origin"]');
      const m = meta && meta.content && meta.content.trim();
      return (m || "http://127.0.0.1:8080").replace(/\/$/, "");
    }
    if (port && staticPorts.includes(port)) {
      const meta = document.querySelector('meta[name="lupin-api-origin"]');
      const m = meta && meta.content && meta.content.trim();
      if (m) return m.replace(/\/$/, "");
      return `http://${window.location.hostname}:8080`.replace(/\/$/, "");
    }
    return window.location.origin.replace(/\/$/, "");
  }

  const API_BASE = resolveApiBase();

  const JSON_POST_HEADERS = {
    Accept: "application/json",
    "Content-Type": "application/json",
  };

  /**
   * Parse API JSON; if the server returned HTML (SPA fallback, 404 page, wrong port), fail clearly.
   */
  async function readJsonResponse(res, urlLabel) {
    const text = await res.text();
    const trimmed = text.trim();
    if (!trimmed) {
      throw new Error(`Empty response from ${urlLabel} (HTTP ${res.status})`);
    }
    if (trimmed[0] === "<") {
      throw new Error(
        `Got HTML instead of JSON from ${urlLabel}. Either Flask is not running on this port, or another app ` +
          `(e.g. Live Server) is bound to the same port and is returning index.html. ` +
          `API base: ${API_BASE}. Confirm with: curl -s -H "Accept: application/json" -X POST ${API_BASE}/api/investigate/test ` +
          `(expect JSON with job_id). The dashboard uses /api/investigate and /api/status only.`
      );
    }
    try {
      return JSON.parse(text);
    } catch (e) {
      throw new Error(
        `Invalid JSON from ${urlLabel} (HTTP ${res.status}): ${(e && e.message) || e}`
      );
    }
  }

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

  const els = {
    form: $("#scan-form"),
    input: $("#username-input"),
    scanBtn: $("#scan-btn"),
    loading: $("#loading-overlay"),
    loadingStatus: $("#loading-status"),
    empty: $("#empty-state"),
    results: $("#results"),
    errorBanner: $("#error-banner"),
    avatarImg: $("#avatar-img"),
    avatarPh: $("#avatar-placeholder"),
    nickname: $("#profile-nickname"),
    handle: $("#profile-handle"),
    numeric: $("#profile-numeric"),
    integrity: $("#integrity-badge"),
    region: $("#profile-region"),
    lang: $("#profile-lang"),
    catalog: $("#profile-status"),
    infraDc: $("#infra-dc"),
    infraAnchor: $("#infra-anchor"),
    infraMeta: $("#infra-meta"),
    intelBio: $("#intel-bio"),
    socialLeads: $("#social-leads"),
    polDeduction: $("#pol-deduction"),
    clockContainer: $("#clock-container"),
    clockRuler: $("#clock-ruler"),
    secretDrawer: $("#secret-drawer"),
    secretToggle: $("#secret-toggle"),
    secretChevron: $("#secret-chevron"),
    rawToggle: $("#raw-toggle"),
    rawPanel: $("#raw-panel"),
    rawJson: $("#raw-json"),
    rawChevron: $("#raw-chevron"),
  };

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  function refreshIcons() {
    if (window.lucide && typeof lucide.createIcons === "function") {
      lucide.createIcons();
    }
  }

  function showLoading(show, statusText) {
    els.loading.classList.toggle("hidden", !show);
    if (statusText) els.loadingStatus.textContent = statusText;
    els.scanBtn.disabled = show;
    els.input.disabled = show;
  }

  function integrityClass(text) {
    const t = (text || "").toLowerCase();
    if (t.includes("automation") || t.includes("bot")) {
      return {
        cls: "bg-red-500/15 text-red-300 border border-red-500/30",
        label: "Automation risk",
        icon: "bot",
      };
    }
    if (t.includes("human") || t.includes("typical provisioning")) {
      return {
        cls: "bg-emerald-500/15 text-emerald-300 border border-emerald-500/30",
        label: "Human (typical)",
        icon: "user-check",
      };
    }
    if (t.includes("parked") || t.includes("aged")) {
      return {
        cls: "bg-amber-500/15 text-amber-200 border border-amber-500/30",
        label: "Aged / parked",
        icon: "archive",
      };
    }
    return {
      cls: "bg-zinc-500/15 text-zinc-300 border border-zinc-500/25",
      label: text || "Unknown",
      icon: "help-circle",
    };
  }

  function platformIcon(platform) {
    const p = (platform || "").toLowerCase();
    if (p.includes("instagram")) return "camera";
    if (p === "x" || p.includes("twitter")) return "at-sign";
    if (p.includes("youtube")) return "play-circle";
    if (p.includes("pinterest")) return "pin";
    if (p.includes("github")) return "github";
    return "link";
  }

  function statusTone(status) {
    const s = (status || "").toLowerCase();
    if (s === "found")
      return "border-emerald-500/40 bg-emerald-500/10 text-emerald-300 hover:bg-emerald-500/20";
    if (s === "not found") return "border-red-500/30 bg-red-950/30 text-red-300/90 hover:bg-red-950/50";
    return "border-slate-600 bg-slate-800/60 text-zinc-300 hover:bg-slate-800";
  }

  function renderClock(pol) {
    const ac = (pol && pol.activity_clock) || {};
    const hist = ac.utc_hour_histogram;
    const face = ac.clock_face || "";

    els.polDeduction.textContent = ac.deduction || "—";
    els.clockRuler.textContent = ac.clock_ruler || "";

    let html = "";

    if (Array.isArray(hist) && hist.length === 24) {
      const max = Math.max(1, ...hist);
      html += `<div class="flex items-end justify-between gap-0.5 h-24 px-1">`;
      hist.forEach((n, h) => {
        const pct = Math.max(4, (n / max) * 100);
        const active = n > 0;
        html += `<div class="flex-1 flex flex-col items-center gap-1 min-w-0">
          <div class="w-full rounded-t bg-slate-800 relative h-20 flex items-end overflow-hidden">
            <div class="w-full rounded-t transition-all ${
              active ? "bg-gradient-to-t from-emerald-600 to-emerald-400" : "bg-slate-700/40"
            }" style="height:${pct}%"></div>
          </div>
          <span class="text-[9px] font-mono text-zinc-600">${h % 6 === 0 ? h : ""}</span>
        </div>`;
      });
      html += `</div>`;
    }

    if (face && face.length >= 24) {
      html += `<div class="rounded-lg border border-slate-700 bg-slate-950/80 p-3 font-mono text-xs tracking-wider text-emerald-500/90 break-all">${escapeHtml(
        face
      )}</div>`;
      html += `<p class="text-[10px] text-zinc-500">Digits 0–9 = events in that UTC hour (capped at 9). <code class="text-zinc-600">.</code> = none.</p>`;
    }

    if (!html) {
      html = `<p class="text-xs text-zinc-500">No UTC activity histogram for this target.</p>`;
    }

    els.clockContainer.innerHTML = html;
  }

  function renderSecretStats(secret) {
    const keys = [
      ["downloadSetting", "downloadSetting_decoded"],
      ["commentSetting", "commentSetting_decoded"],
      ["duetSetting", "duetSetting_decoded"],
      ["stitchSetting", "stitchSetting_decoded"],
      ["is_stem_verified", null],
      ["video_label", null],
    ];
    const rows = [];
    for (const [k, decKey] of keys) {
      if (secret[k] === undefined || secret[k] === null) continue;
      const decoded = decKey ? secret[decKey] : null;
      const label = k.replace(/_/g, " ");
      const valStr = String(secret[k]);
      const decStr = decoded != null ? String(decoded) : "";
      const restrictive =
        /off|disabled|nobody|none|0|false/i.test(decStr) || /off|disabled/i.test(valStr);
      const permissive =
        /everyone|all|on|enabled|1|true/i.test(decStr) || /everyone|all/i.test(valStr);
      let tone = "text-zinc-300 border-slate-600 bg-slate-800/50";
      let icon = "toggle-left";
      if (permissive && !restrictive) {
        tone = "text-emerald-300 border-emerald-500/30 bg-emerald-500/10";
        icon = "unlock";
      } else if (restrictive) {
        tone = "text-amber-200 border-amber-500/25 bg-amber-500/10";
        icon = "lock";
      }
      rows.push(`<div class="rounded-lg border px-3 py-2.5 flex items-start gap-3 ${tone}">
        <i data-lucide="${icon}" class="h-4 w-4 shrink-0 mt-0.5 opacity-80"></i>
        <div class="min-w-0">
          <p class="text-[10px] uppercase tracking-wider text-zinc-500 font-semibold">${escapeHtml(label)}</p>
          <p class="text-sm font-mono text-white/90">${escapeHtml(valStr)}</p>
          ${
            decStr
              ? `<p class="text-xs text-zinc-400 mt-1">${escapeHtml(decStr)}</p>`
              : ""
          }
        </div>
      </div>`);
    }
    if (secret.ai_tags_present) {
      rows.push(`<div class="rounded-lg border border-violet-500/30 bg-violet-500/10 px-3 py-2.5 flex items-center gap-2">
        <i data-lucide="sparkles" class="h-4 w-4 text-violet-300"></i>
        <span class="text-sm text-violet-200">AI / content tags detected</span>
      </div>`);
    }
    els.secretDrawer.innerHTML =
      rows.length > 0
        ? rows.join("")
        : `<p class="text-xs text-zinc-500 col-span-full">No secret stats captured for this profile.</p>`;
    refreshIcons();
  }

  function escapeHtml(s) {
    const d = document.createElement("div");
    d.textContent = s;
    return d.innerHTML;
  }

  function renderReport(data, httpStatus) {
    els.errorBanner.classList.add("hidden");
    els.results.classList.remove("hidden");
    els.empty.classList.add("hidden");

    const missing = data.status === "missing" || httpStatus === 404;
    if (missing) {
      els.errorBanner.textContent =
        data.error || "Account not found or could not be resolved.";
      els.errorBanner.classList.remove("hidden");
    }

    const id = data.identity || {};
    const infra = data.infrastructure || {};
    const intel = data.intelligence || {};
    const pol = data.pattern_of_life || {};
    const stats = data.stats || {};
    const secret = data.secret_stats || {};
    const ev = data.evidence || {};

    const avatarUrl = ev.avatar_url || intel.avatar_url || "";
    if (avatarUrl) {
      els.avatarImg.src = avatarUrl;
      els.avatarImg.classList.remove("hidden");
      els.avatarPh.classList.add("hidden");
      els.avatarImg.onerror = () => {
        els.avatarImg.classList.add("hidden");
        els.avatarPh.classList.remove("hidden");
      };
    } else {
      els.avatarImg.classList.add("hidden");
      els.avatarPh.classList.remove("hidden");
    }

    els.nickname.textContent = id.nickname || "—";
    els.handle.textContent = "@" + (id.unique_id || data.username_requested || "—");
    els.numeric.textContent = "Numeric ID " + (id.numeric_id ?? "—");

    const integ = integrityClass(id.integrity_assessment);
    els.integrity.className =
      "mt-4 inline-flex items-center gap-2 rounded-full px-3 py-1 text-xs font-semibold " + integ.cls;
    els.integrity.innerHTML = `<i data-lucide="${integ.icon}" class="h-3.5 w-3.5"></i><span>${escapeHtml(
      integ.label
    )}</span>`;

    els.region.textContent = id.registered_region || "—";
    els.lang.textContent = id.primary_language || "—";
    els.catalog.textContent = stats.content_status || pol.content_status || "—";

    els.infraDc.textContent = infra.physical_datacenter || "—";
    els.infraAnchor.textContent = infra.server_anchor || "—";
    const metaBits = [];
    if (infra.idc_code) metaBits.push("IDC: " + infra.idc_code);
    if (infra.region_spoofing_flag) metaBits.push(infra.region_spoofing_flag);
    if (infra.network_anomaly) metaBits.push(infra.network_anomaly);
    els.infraMeta.textContent = metaBits.length ? metaBits.join(" • ") : "—";

    els.intelBio.textContent = intel.bio || "—";

    const leads = intel.social_leads || [];
    els.socialLeads.innerHTML = leads.length
      ? leads
          .map((L) => {
            const ic = platformIcon(L.platform);
            const tone = statusTone(L.status);
            const href = L.url || "#";
            const safe = escapeHtml(href);
            return `<a href="${safe}" target="_blank" rel="noopener noreferrer"
            class="inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-medium transition-colors ${tone}">
            <i data-lucide="${ic}" class="h-3.5 w-3.5 shrink-0"></i>
            <span>${escapeHtml(L.platform || "Link")}</span>
            <span class="text-zinc-500 font-mono">${escapeHtml(L.status || "")}</span>
          </a>`;
          })
          .join("")
      : `<p class="text-xs text-zinc-500">No social leads from pivot probes.</p>`;

    renderClock(pol);
    renderSecretStats(secret);

    els.rawJson.textContent = JSON.stringify(data, null, 2);
    refreshIcons();
  }

  function absoluteApiUrl(path) {
    if (path.startsWith("http://") || path.startsWith("https://")) return path;
    return `${API_BASE}${path.startsWith("/") ? path : "/" + path}`;
  }

  async function pollJob(jobId, pollPath) {
    const url = pollPath
      ? absoluteApiUrl(pollPath)
      : `${API_BASE}/api/status/${encodeURIComponent(jobId)}`;
    const maxAttempts = 200;
    for (let n = 0; n < maxAttempts; n++) {
      const r = await fetch(url, { headers: { Accept: "application/json" } });
      const body = await readJsonResponse(r, `/api/status/${jobId.slice(0, 8)}…`);
      if (body.status === "queued") {
        els.loadingStatus.textContent = "Queued…";
      } else if (body.status === "processing") {
        els.loadingStatus.textContent = "Decrypting metadata • Playwright + pivots";
      } else if (body.status === "completed") {
        return { body };
      } else if (body.status === "failed") {
        throw new Error(body.error || "Job failed");
      }
      await sleep(1200);
    }
    throw new Error("Polling timed out — increase LUPIN_INVESTIGATE_TIMEOUT or retry.");
  }

  async function runScan(username) {
    const u = username.trim().replace(/^@+/, "");
    if (!u) return;

    showLoading(true, "Submitting target…");
    els.empty.classList.add("hidden");
    els.results.classList.add("hidden");

    try {
      const res = await fetch(`${API_BASE}/api/investigate/${encodeURIComponent(u)}`, {
        method: "POST",
        headers: JSON_POST_HEADERS,
        body: "{}",
      });
      const start = await readJsonResponse(res, `POST /api/investigate/${u}`);
      if (!res.ok) {
        throw new Error(start.error || `HTTP ${res.status}`);
      }
      const jobId = start.job_id;
      if (!jobId) throw new Error("No job_id returned");

      els.loadingStatus.textContent = "Job " + jobId.slice(0, 8) + "…";

      const { body } = await pollJob(jobId, start.poll_url);
      showLoading(false);

      const result = body.result;
      if (!result) {
        throw new Error(body.parse_error || "Empty result");
      }
      renderReport(result, body.http_status);
    } catch (err) {
      showLoading(false);
      els.empty.classList.add("hidden");
      els.results.classList.remove("hidden");
      els.errorBanner.textContent = err.message || String(err);
      els.errorBanner.classList.remove("hidden");
      refreshIcons();
    }
  }

  els.form.addEventListener("submit", (e) => {
    e.preventDefault();
    runScan(els.input.value);
  });

  let secretOpen = false;
  els.secretToggle.addEventListener("click", () => {
    secretOpen = !secretOpen;
    els.secretDrawer.classList.toggle("hidden", !secretOpen);
    els.secretChevron.setAttribute("data-lucide", secretOpen ? "chevron-up" : "chevron-down");
    els.secretToggle.querySelector("span").textContent = secretOpen ? "Collapse" : "Expand";
    refreshIcons();
  });

  let rawOpen = false;
  els.rawToggle.addEventListener("click", () => {
    rawOpen = !rawOpen;
    els.rawPanel.classList.toggle("hidden", !rawOpen);
    els.rawChevron.setAttribute("data-lucide", rawOpen ? "chevron-up" : "chevron-down");
    refreshIcons();
  });

  refreshIcons();

  // Opened from GET /investigate/<user> → redirect to /?target=<user>
  const qs = new URLSearchParams(window.location.search);
  const preset = qs.get("target") || qs.get("user");
  if (preset) {
    els.input.value = preset;
    if (window.history.replaceState) {
      window.history.replaceState({}, "", window.location.pathname || "/");
    }
    runScan(preset);
  }
})();
