import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

// Event plumbing — blue teams should NOT need to touch this file.
//
// Two responsibilities:
//  1. Gate the entire app behind a start time. Before the gate opens,
//     return a plain HTML splash page (for browsers) or a JSON error
//     (for /api/* requests). After the gate opens, pass through.
//  2. Stamp x-request-id and x-request-start on every passed-through
//     request so lib/telemetry.ts can correlate and time requests.
//
// Gate time is configurable via EVENT_START_ISO. Default is
// 2026-04-09 17:55:00 PDT (5 minutes of safety margin before the
// nominal 18:00 kickoff). Set EVENT_START_ISO to a past timestamp to
// bypass the gate for local testing.

const DEFAULT_EVENT_START_ISO = "2026-04-09T17:55:00-07:00";

function getGateOpenMs(): number {
  const raw = process.env.EVENT_START_ISO?.trim();
  const iso = raw || DEFAULT_EVENT_START_ISO;
  const parsed = Date.parse(iso);
  if (Number.isNaN(parsed)) {
    // If someone sets EVENT_START_ISO to garbage, fall back to the
    // default rather than leaving the app wide open or permanently
    // locked. Treat it as a misconfiguration but keep the gate active.
    return Date.parse(DEFAULT_EVENT_START_ISO);
  }
  return parsed;
}

function splashHtml(gateOpenMs: number): string {
  const tenantId = process.env.TENANT_ID?.trim() || "(tenant id not set)";
  // Inline everything — the splash must render without any Next.js
  // assets, API calls, or external resources.
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>the infrastructure strikes back — gate closed</title>
<meta name="description" content="Synthetic adversarial training event. Gate closed until the event starts.">
<style>
  :root { color-scheme: dark; }
  body {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    background: #0b0b0b; color: #eaeaea;
    margin: 0; padding: 2rem; line-height: 1.4;
  }
  main { max-width: 640px; }
  h1 { font-size: 1.4rem; margin: 0 0 0.5rem; }
  p { opacity: 0.85; }
  .panel { border: 1px solid #333; padding: 0.85rem 1rem; margin: 1rem 0; }
  .label { opacity: 0.6; font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.05em; }
  .value { font-size: 1rem; margin-top: 0.25rem; word-break: break-all; }
  #countdown { font-size: 1.6rem; font-variant-numeric: tabular-nums; }
  .tenant { opacity: 0.55; font-size: 0.78rem; margin-top: 2rem; }
  a { color: #eaeaea; }
</style>
</head>
<body>
<main>
  <h1>the infrastructure strikes back</h1>
  <p>
    synthetic adversarial training event. not production. not a real system.
    all names and flows are synthetic — do not assume resemblance to any
    real company, product, or internal system.
  </p>

  <div class="panel">
    <div class="label">gate opens</div>
    <div class="value" id="open-at">—</div>
  </div>

  <div class="panel">
    <div class="label">time remaining</div>
    <div class="value" id="countdown">—</div>
  </div>

  <p>
    The event infrastructure is locked until the gate opens. The real
    app — signup, login, sessions, action objects, profile, reset, and
    the judge dashboard — will appear here at that time. This page will
    reload itself automatically when the gate opens.
  </p>

  <div class="tenant">deployment: ${tenantId}</div>
</main>

<script>
  (function () {
    var opensAt = ${gateOpenMs};
    var openEl = document.getElementById('open-at');
    var cdEl = document.getElementById('countdown');
    try {
      openEl.textContent = new Date(opensAt).toLocaleString(undefined, {
        dateStyle: 'medium', timeStyle: 'long'
      });
    } catch (e) {
      openEl.textContent = new Date(opensAt).toString();
    }
    function pad(n) { return n < 10 ? '0' + n : '' + n; }
    function tick() {
      var ms = opensAt - Date.now();
      if (ms <= 0) {
        cdEl.textContent = 'gate open — reloading…';
        setTimeout(function () { location.reload(); }, 1200);
        return;
      }
      var s = Math.floor(ms / 1000) % 60;
      var m = Math.floor(ms / 60000) % 60;
      var h = Math.floor(ms / 3600000);
      cdEl.textContent = pad(h) + ':' + pad(m) + ':' + pad(s);
    }
    tick();
    setInterval(tick, 1000);
  })();
</script>
</body>
</html>`;
}

function splashJson(gateOpenMs: number): string {
  return JSON.stringify({
    error: "gate_closed",
    message: "The event infrastructure is locked until the gate opens.",
    gate_opens_at: new Date(gateOpenMs).toISOString(),
    gate_opens_at_ms: gateOpenMs,
    now_ms: Date.now(),
  });
}

export function middleware(req: NextRequest) {
  const gateOpenMs = getGateOpenMs();
  const now = Date.now();

  if (now < gateOpenMs) {
    const isApi = req.nextUrl.pathname.startsWith("/api/");
    if (isApi) {
      return new NextResponse(splashJson(gateOpenMs), {
        status: 503,
        headers: {
          "content-type": "application/json; charset=utf-8",
          "cache-control": "no-store",
          "x-gate": "closed",
          "retry-after": String(Math.max(1, Math.ceil((gateOpenMs - now) / 1000))),
        },
      });
    }
    return new NextResponse(splashHtml(gateOpenMs), {
      status: 200,
      headers: {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
        "x-gate": "closed",
      },
    });
  }

  // Gate open — pass through with request-id plumbing.
  const requestId =
    (globalThis.crypto as Crypto | undefined)?.randomUUID?.() ??
    `req_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`;

  const res = NextResponse.next({
    request: { headers: new Headers(req.headers) },
  });

  res.headers.set("x-request-id", requestId);
  res.headers.set("x-gate", "open");
  req.headers.set("x-request-id", requestId);
  req.headers.set("x-request-start", String(Date.now()));
  return res;
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
