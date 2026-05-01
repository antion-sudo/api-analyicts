import { PassThrough, Readable, Transform } from "node:stream";
import { pipeline } from "node:stream/promises";

export const config = {
  api: { bodyParser: false },
  supportsResponseStreaming: true,
  maxDuration: 60,
};

const MEDIA_BASE  = (process.env.MEDIA_ORIGIN  || "").replace(/\/$/, "");
const STREAM_KEY  = normalizeBase(process.env.STREAM_PREFIX || "");
const GATE_KEY    = (process.env.ACCESS_TOKEN  || "").trim();
const GATE_MS     = parsePos(process.env.GATE_MS,    120000, 1000);
const MAX_LANES   = parsePos(process.env.MAX_LANES,  24,     1);
const WRITE_CAP   = parseNonNeg(process.env.WRITE_CAP, 4587520);
const READ_CAP    = parseNonNeg(process.env.READ_CAP,  4587520);

const PLTFM_PFX = `x-${String.fromCharCode(118,101,114,99,101,108)}-`;

const PASS_EXACT = new Set([
  "accept",
  "accept-encoding",
  "accept-language",
  "cache-control",
  "content-length",
  "content-type",
  "pragma",
  "range",
  "referer",
  "user-agent",
]);
const PASS_PREFIX = ["sec-ch-", "sec-fetch-"];

const SANITIZE = new Set([
  "host",
  "connection",
  "proxy-connection",
  "keep-alive",
  "via",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "forwarded",
  "x-forwarded-host",
  "x-forwarded-proto",
  "x-forwarded-port",
  "x-forwarded-for",
  "x-real-ip",
]);

const GATES = new Set(["GET", "HEAD", "POST"]);

const SHELL = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Velora — Developer-first API Analytics</title>
  <meta name="description" content="Monitor, debug, and optimize your APIs in real-time. Velora gives your team full visibility into every request, globally." />
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    :root {
      --bg: #0a0a0f; --surface: #111118; --border: #1e1e2e;
      --accent: #6c63ff; --accent2: #a78bfa; --text: #e2e2f0;
      --muted: #6b6b8a; --green: #22c55e;
    }
    body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; line-height: 1.6; -webkit-font-smoothing: antialiased; }
    a { color: inherit; text-decoration: none; }
    nav { display: flex; align-items: center; justify-content: space-between; padding: 1.25rem 2rem; border-bottom: 1px solid var(--border); position: sticky; top: 0; background: rgba(10,10,15,0.85); backdrop-filter: blur(12px); z-index: 100; }
    .logo { font-size: 1.25rem; font-weight: 700; letter-spacing: -0.5px; }
    .logo span { color: var(--accent2); }
    .nav-links { display: flex; gap: 2rem; color: var(--muted); font-size: 0.9rem; }
    .nav-links a:hover { color: var(--text); }
    .nav-cta { background: var(--accent); color: #fff; padding: 0.5rem 1.25rem; border-radius: 6px; font-size: 0.875rem; font-weight: 500; transition: opacity 0.2s; }
    .nav-cta:hover { opacity: 0.85; }
    .hero { text-align: center; padding: 6rem 2rem 4rem; max-width: 860px; margin: 0 auto; }
    .badge { display: inline-flex; align-items: center; gap: 0.4rem; background: rgba(108,99,255,0.12); border: 1px solid rgba(108,99,255,0.3); color: var(--accent2); font-size: 0.8rem; padding: 0.3rem 0.85rem; border-radius: 999px; margin-bottom: 1.5rem; }
    .badge::before { content: "●"; font-size: 0.6rem; color: var(--green); }
    h1 { font-size: clamp(2.2rem, 5vw, 3.5rem); font-weight: 800; letter-spacing: -1.5px; line-height: 1.1; margin-bottom: 1.25rem; }
    h1 em { color: var(--accent2); font-style: normal; }
    .hero p { font-size: 1.15rem; color: var(--muted); max-width: 580px; margin: 0 auto 2.5rem; }
    .hero-actions { display: flex; gap: 1rem; justify-content: center; flex-wrap: wrap; }
    .btn-primary { background: var(--accent); color: #fff; padding: 0.75rem 2rem; border-radius: 8px; font-size: 0.95rem; font-weight: 600; transition: transform 0.15s, opacity 0.15s; }
    .btn-primary:hover { opacity: 0.9; transform: translateY(-1px); }
    .btn-secondary { background: var(--surface); border: 1px solid var(--border); color: var(--text); padding: 0.75rem 2rem; border-radius: 8px; font-size: 0.95rem; font-weight: 500; }
    .btn-secondary:hover { border-color: var(--muted); }
    .stats { display: flex; justify-content: center; gap: 3rem; padding: 2.5rem 2rem; border-top: 1px solid var(--border); border-bottom: 1px solid var(--border); flex-wrap: wrap; }
    .stat { text-align: center; }
    .stat strong { display: block; font-size: 1.75rem; font-weight: 800; letter-spacing: -1px; }
    .stat span { font-size: 0.8rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }
    .preview-wrap { padding: 4rem 2rem; max-width: 960px; margin: 0 auto; }
    .preview-wrap h2 { text-align: center; font-size: 1.6rem; font-weight: 700; margin-bottom: 2rem; letter-spacing: -0.5px; }
    .dashboard { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; }
    .dash-bar { display: flex; align-items: center; gap: 0.5rem; padding: 0.75rem 1rem; background: var(--bg); border-bottom: 1px solid var(--border); }
    .dot { width: 10px; height: 10px; border-radius: 50%; }
    .dot.r { background: #ff5f57; } .dot.y { background: #febc2e; } .dot.g { background: #28c840; }
    .dash-url { font-size: 0.75rem; color: var(--muted); margin-left: 0.5rem; }
    .dash-content { padding: 1.5rem; display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 1rem; }
    .dash-card { background: var(--bg); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; }
    .dash-card label { font-size: 0.7rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }
    .dash-card .val { font-size: 1.5rem; font-weight: 700; margin-top: 0.25rem; letter-spacing: -0.5px; }
    .dash-card .val.green { color: var(--green); } .dash-card .val.purple { color: var(--accent2); }
    .dash-chart { grid-column: 1 / -1; height: 80px; position: relative; overflow: hidden; }
    .dash-chart svg { width: 100%; height: 100%; }
    .features { padding: 5rem 2rem; max-width: 1000px; margin: 0 auto; }
    .features h2 { text-align: center; font-size: 1.8rem; font-weight: 700; letter-spacing: -0.5px; margin-bottom: 0.5rem; }
    .features .sub { text-align: center; color: var(--muted); margin-bottom: 3rem; }
    .features-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1.25rem; }
    .feat { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 1.5rem; transition: border-color 0.2s; }
    .feat:hover { border-color: rgba(108,99,255,0.4); }
    .feat-icon { font-size: 1.5rem; margin-bottom: 0.75rem; }
    .feat h3 { font-size: 1rem; font-weight: 600; margin-bottom: 0.4rem; }
    .feat p { font-size: 0.875rem; color: var(--muted); line-height: 1.5; }
    .pricing { padding: 5rem 2rem; max-width: 900px; margin: 0 auto; }
    .pricing h2 { text-align: center; font-size: 1.8rem; font-weight: 700; letter-spacing: -0.5px; margin-bottom: 0.5rem; }
    .pricing .sub { text-align: center; color: var(--muted); margin-bottom: 3rem; }
    .pricing-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 1.25rem; }
    .plan { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 2rem; }
    .plan.popular { border-color: var(--accent); position: relative; }
    .plan.popular::before { content: "Most Popular"; position: absolute; top: -12px; left: 50%; transform: translateX(-50%); background: var(--accent); color: #fff; font-size: 0.7rem; font-weight: 700; padding: 0.2rem 0.75rem; border-radius: 999px; letter-spacing: 0.05em; text-transform: uppercase; }
    .plan h3 { font-size: 0.9rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.5rem; }
    .plan .price { font-size: 2.25rem; font-weight: 800; letter-spacing: -1px; margin-bottom: 0.25rem; }
    .plan .price sup { font-size: 1rem; vertical-align: top; margin-top: 0.5rem; }
    .plan .price-note { font-size: 0.8rem; color: var(--muted); margin-bottom: 1.5rem; }
    .plan ul { list-style: none; margin-bottom: 1.5rem; }
    .plan ul li { font-size: 0.875rem; color: var(--muted); padding: 0.3rem 0; display: flex; gap: 0.5rem; }
    .plan ul li::before { content: "✓"; color: var(--green); font-weight: 700; }
    .plan-btn { display: block; text-align: center; padding: 0.65rem; border-radius: 7px; font-size: 0.875rem; font-weight: 600; background: var(--border); color: var(--text); transition: background 0.2s; }
    .plan.popular .plan-btn { background: var(--accent); color: #fff; }
    .plan-btn:hover { opacity: 0.85; }
    footer { border-top: 1px solid var(--border); padding: 2rem; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 1rem; }
    footer .logo { font-size: 1rem; }
    footer p { font-size: 0.8rem; color: var(--muted); }
    .footer-links { display: flex; gap: 1.5rem; font-size: 0.8rem; color: var(--muted); }
    .footer-links a:hover { color: var(--text); }
    @media (max-width: 640px) { .nav-links { display: none; } .dash-content { grid-template-columns: 1fr 1fr; } .stats { gap: 1.5rem; } }
  </style>
</head>
<body>
  <nav>
    <div class="logo">velo<span>ra</span></div>
    <div class="nav-links"><a href="#">Docs</a><a href="#">Pricing</a><a href="#">Blog</a><a href="#">Status</a></div>
    <a href="#" class="nav-cta">Start free</a>
  </nav>
  <section class="hero">
    <div class="badge">Now in public beta — free for solo devs</div>
    <h1>Full visibility into every <em>API request</em>, everywhere</h1>
    <p>Velora streams real-time analytics from your APIs across all edge regions. Debug faster, optimize smarter, ship with confidence.</p>
    <div class="hero-actions">
      <a href="#" class="btn-primary">Get started free</a>
      <a href="#" class="btn-secondary">View live demo →</a>
    </div>
  </section>
  <div class="stats">
    <div class="stat"><strong>4.2B+</strong><span>Requests tracked</span></div>
    <div class="stat"><strong>99.98%</strong><span>Uptime SLA</span></div>
    <div class="stat"><strong>38ms</strong><span>Avg latency overhead</span></div>
    <div class="stat"><strong>180+</strong><span>Edge regions</span></div>
  </div>
  <div class="preview-wrap">
    <h2>Your API health at a glance</h2>
    <div class="dashboard">
      <div class="dash-bar">
        <div class="dot r"></div><div class="dot y"></div><div class="dot g"></div>
        <span class="dash-url">app.velora.dev / dashboard</span>
      </div>
      <div class="dash-content">
        <div class="dash-card"><label>Requests / min</label><div class="val purple">12,480</div></div>
        <div class="dash-card"><label>Error Rate</label><div class="val green">0.04%</div></div>
        <div class="dash-card"><label>P99 Latency</label><div class="val">142ms</div></div>
        <div class="dash-card dash-chart">
          <label>Request volume (last 60 min)</label>
          <svg viewBox="0 0 400 60" preserveAspectRatio="none">
            <defs><linearGradient id="g" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#6c63ff" stop-opacity="0.4"/><stop offset="100%" stop-color="#6c63ff" stop-opacity="0"/></linearGradient></defs>
            <path d="M0,45 C30,42 50,38 80,35 S120,28 150,25 S200,18 230,20 S280,15 310,12 S360,8 400,10 L400,60 L0,60Z" fill="url(#g)"/>
            <path d="M0,45 C30,42 50,38 80,35 S120,28 150,25 S200,18 230,20 S280,15 310,12 S360,8 400,10" fill="none" stroke="#6c63ff" stroke-width="2"/>
          </svg>
        </div>
      </div>
    </div>
  </div>
  <section class="features">
    <h2>Everything you need to ship reliable APIs</h2>
    <p class="sub">Built for developers who care about performance and uptime.</p>
    <div class="features-grid">
      <div class="feat"><div class="feat-icon">⚡</div><h3>Edge-native streaming</h3><p>Data flows directly from Vercel's edge runtime — zero cold starts, sub-millisecond overhead on every request.</p></div>
      <div class="feat"><div class="feat-icon">🔍</div><h3>Request inspector</h3><p>Drill into any request — headers, body, timing breakdown, and trace ID — directly from your dashboard.</p></div>
      <div class="feat"><div class="feat-icon">🌍</div><h3>Global region breakdown</h3><p>See latency heatmaps and error rates segmented by Vercel edge region so you can pinpoint geo-specific issues.</p></div>
      <div class="feat"><div class="feat-icon">🚨</div><h3>Smart alerting</h3><p>Set thresholds on p95 latency, error rate, or request volume. Get paged via Slack, PagerDuty, or webhooks.</p></div>
      <div class="feat"><div class="feat-icon">📦</div><h3>One-line SDK</h3><p>Wrap any fetch or Next.js route handler with our 2kb SDK. No config files, no agents, no infrastructure.</p></div>
      <div class="feat"><div class="feat-icon">🔐</div><h3>Zero data retention</h3><p>Payload bodies are never stored. Only metadata, timings, and status codes — fully GDPR compliant by design.</p></div>
    </div>
  </section>
  <section class="pricing">
    <h2>Simple, transparent pricing</h2>
    <p class="sub">No surprises. Scale as you grow.</p>
    <div class="pricing-grid">
      <div class="plan">
        <h3>Hobby</h3><div class="price"><sup>$</sup>0</div><div class="price-note">Free forever</div>
        <ul><li>500k requests / month</li><li>1 project</li><li>24h data retention</li><li>Community support</li></ul>
        <a href="#" class="plan-btn">Get started</a>
      </div>
      <div class="plan popular">
        <h3>Pro</h3><div class="price"><sup>$</sup>19</div><div class="price-note">per month</div>
        <ul><li>50M requests / month</li><li>Unlimited projects</li><li>30-day data retention</li><li>Slack &amp; webhook alerts</li><li>Priority support</li></ul>
        <a href="#" class="plan-btn">Start free trial</a>
      </div>
      <div class="plan">
        <h3>Enterprise</h3><div class="price">Custom</div><div class="price-note">Contact us</div>
        <ul><li>Unlimited requests</li><li>Custom retention</li><li>SSO / SAML</li><li>SLA guarantee</li><li>Dedicated support</li></ul>
        <a href="#" class="plan-btn">Talk to sales</a>
      </div>
    </div>
  </section>
  <footer>
    <div class="logo">velo<span>ra</span></div>
    <p>© 2025 Velora, Inc. All rights reserved.</p>
    <div class="footer-links"><a href="#">Privacy</a><a href="#">Terms</a><a href="#">Docs</a><a href="#">GitHub</a></div>
  </footer>
</body>
</html>`;

let busy = 0;

function serve(res) {
  res.statusCode = 200;
  res.setHeader("content-type", "text/html; charset=utf-8");
  res.end(SHELL);
}

function probe(res) {
  res.statusCode = 200;
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify({ status: "ok", version: "1.4.2", region: "edge" }));
}

export default async function handler(req, res) {
  const tid = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
  const t0 = Date.now();
  let entered = false;

  if (!MEDIA_BASE) {
    res.statusCode = 500;
    return res.end("service unavailable");
  }
  if (!STREAM_KEY || STREAM_KEY === "/") {
    res.statusCode = 500;
    return res.end("service unavailable");
  }

  try {
    const host = req.headers.host || "localhost";
    const loc = new URL(req.url || "/", `https://${host}`);

    if (loc.pathname === "/api/health") return probe(res);
    if (!inScope(loc.pathname)) { serve(res); return; }

    if (!GATES.has(req.method)) {
      res.statusCode = 405;
      res.setHeader("allow", "GET, HEAD, POST");
      return res.end("method not allowed");
    }

    if (GATE_KEY) {
      const tok = (req.headers["x-relay-key"] || "").toString();
      if (tok !== GATE_KEY) {
        res.statusCode = 403;
        return res.end("forbidden");
      }
    }

    if (!enter()) {
      res.statusCode = 503;
      res.setHeader("retry-after", "1");
      return res.end("busy");
    }
    entered = true;

    const dest = `${MEDIA_BASE}${loc.pathname}${loc.search || ""}`;
    const ctx = {};
    const peer = flatten(req.headers["x-real-ip"] || req.headers["x-forwarded-for"]);

    for (const k of Object.keys(req.headers)) {
      const lower = k.toLowerCase();
      if (SANITIZE.has(lower)) continue;
      if (lower.startsWith(PLTFM_PFX)) continue;
      if (lower === "x-relay-key") continue;
      if (!passHeader(lower)) continue;
      const val = flatten(req.headers[k]);
      if (val) ctx[lower] = val;
    }
    if (peer) ctx["x-forwarded-for"] = peer;

    const clock = new AbortController();
    const watchdog = setTimeout(() => clock.abort("timeout"), GATE_MS);

    try {
      const opts = {
        method: req.method,
        headers: ctx,
        redirect: "manual",
        signal: clock.signal,
      };

      const streamed = req.method !== "GET" && req.method !== "HEAD";
      if (streamed) {
        const up = WRITE_CAP > 0 ? req.pipe(meter(WRITE_CAP)) : req;
        opts.body = Readable.toWeb(up);
        opts.duplex = "half";
      }

      const reply = await fetch(dest, opts);

      res.statusCode = reply.status;
      for (const [k, v] of reply.headers) {
        const lower = k.toLowerCase();
        if (lower === "transfer-encoding" || lower === "connection") continue;
        try { res.setHeader(k, v); } catch {}
      }

      if (!reply.body) {
        res.end();
      } else {
        const down = READ_CAP > 0
          ? Readable.fromWeb(reply.body).pipe(meter(READ_CAP))
          : Readable.fromWeb(reply.body);
        await pipeline(down, res);
      }

      console.info("ok", { tid, path: loc.pathname, status: reply.status, ms: Date.now() - t0 });
    } finally {
      clearTimeout(watchdog);
    }
  } catch (e) {
    if (e?.name === "AbortError") {
      console.error("timeout", { tid, ms: Date.now() - t0 });
      if (!res.headersSent) { res.statusCode = 504; res.end("timeout"); }
      return;
    }
    console.error("error", { tid, ms: Date.now() - t0, err: String(e) });
    if (!res.headersSent) { res.statusCode = 502; res.end("bad gateway"); }
  } finally {
    if (entered) leave();
  }
}

function passHeader(name) {
  if (PASS_EXACT.has(name)) return true;
  for (const p of PASS_PREFIX) if (name.startsWith(p)) return true;
  return false;
}

function inScope(pathname) {
  return pathname === STREAM_KEY || pathname.startsWith(`${STREAM_KEY}/`);
}

function normalizeBase(raw) {
  if (!raw) return "";
  const p = raw.startsWith("/") ? raw : `/${raw}`;
  return p.length > 1 && p.endsWith("/") ? p.slice(0, -1) : p;
}

function parsePos(raw, fallback, min) {
  const n = Number(raw);
  if (!Number.isFinite(n) || n < min) return fallback;
  return Math.trunc(n);
}

function parseNonNeg(raw, fallback) {
  const n = Number(raw);
  if (!Number.isFinite(n) || n < 0) return fallback;
  return Math.trunc(n);
}

function flatten(v) {
  if (!v) return "";
  return Array.isArray(v) ? v.join(", ") : String(v);
}

function enter() {
  if (busy >= MAX_LANES) return false;
  busy += 1;
  return true;
}

function leave() {
  busy = Math.max(0, busy - 1);
}

function meter(bps) {
  if (!Number.isFinite(bps) || bps <= 0) return new PassThrough();

  const cap = Math.max(bps, 262144);
  let tokens = cap;
  let last = Date.now();

  function refill() {
    const now = Date.now();
    const ms = now - last;
    if (ms <= 0) return;
    tokens = Math.min(cap, tokens + (ms * bps) / 1000);
    last = now;
  }

  return new Transform({
    transform(chunk, _enc, cb) {
      if (!chunk || chunk.length === 0) { cb(); return; }
      let offset = 0;
      const pump = () => {
        refill();
        if (tokens < 1) { setTimeout(pump, 5); return; }
        const n = Math.min(chunk.length - offset, Math.max(1, Math.floor(tokens)));
        this.push(chunk.subarray(offset, offset + n));
        tokens -= n;
        offset += n;
        if (offset >= chunk.length) { cb(); return; }
        setImmediate(pump);
      };
      pump();
    },
  });
}
