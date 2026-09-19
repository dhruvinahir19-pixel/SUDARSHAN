#!/usr/bin/env python3
"""
SUDARSHAN — Render free-tier probe  (Docker web service, read-only)

WHAT THIS IS
  A deliberately dumb stand-in for the real engine. It does exactly what the real bot would
  do to Binance -- public calls, an authenticated call, and a fetch-klines-then-compute step
  that mirrors our actual 15m indicator work -- and records what happens. It also measures
  how often Render's free tier actually keeps the container alive.

WHAT IT ANSWERS (the only questions that matter before building anything)
  Q1  Can a Render Singapore free container reach fapi.binance.com at all?  (451 / 403 / 418?)
  Q2  Do signed/authenticated calls work from a shared datacenter IP with no whitelist?
  Q3  Is the free tier actually stably alive (spin-downs, restarts, suspensions), and how
      much CPU does our real workload need on a 0.1-CPU instance?
  Q4  What is our egress IP, and does it ever change?  (decides whether whitelisting is
      ever possible, and proves we really landed in Singapore)

WHAT IT NEVER DOES
  It never places, modifies or cancels an order. No /order path exists in this file.
  Safe to run with a live API key.

ENDPOINTS (open in a browser, phone-friendly)
  /         tiny dashboard
  /status   JSON summary + last 25 results
  /log      full raw log JSON

ENVIRONMENT VARIABLES (all optional -> it runs with none)
  BINANCE_API_KEY     your Ed25519 (or HMAC) key. Omit to test public paths only.
  BINANCE_SECRET      your secret (hex private key for ed25519, or HMAC secret)
  KEY_TYPE            "ed25519" (default) or "hmac"
  PROBE_INTERVAL_SEC  seconds between probe rounds (default 300; see README on Render's
                      outbound-traffic suspension clause -- do not go crazy here)
  PROBE_SYMBOLS       comma list, default "BTCUSDT,ETHUSDT,SOLUSDT"
  HEARTBEAT_URL       optional healthchecks.io ping URL, hit once per round
"""

from __future__ import annotations
import json, os, threading, time, traceback, urllib.request, urllib.parse, urllib.error
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# --------------------------------------------------------------------------- config
PORT         = int(os.environ.get("PORT", "8080"))
INTERVAL     = int(os.environ.get("PROBE_INTERVAL_SEC", "300"))
API_KEY      = os.environ.get("BINANCE_API_KEY", "").strip()
SECRET       = os.environ.get("BINANCE_SECRET", "").strip()
KEY_TYPE     = os.environ.get("KEY_TYPE", "ed25519").strip().lower()
SYMBOLS      = [s.strip().upper() for s in os.environ.get(
                  "PROBE_SYMBOLS", "BTCUSDT,ETHUSDT,SOLUSDT").split(",") if s.strip()]
HEARTBEAT    = os.environ.get("HEARTBEAT_URL", "").strip()
START_TS     = time.time()
MAX_LOG      = 4000

FAPI = "https://fapi.binance.com"     # USDⓈ-M futures -- the venue the strategy runs on
SPOT = "https://api.binance.com"      # spot -- control group
UA   = "sudarshan-probe/1.0"

log: list[dict] = []
log_lock = threading.Lock()
state = {"round": 0, "region": None, "region_checked_at": None, "egress_ips": []}


# --------------------------------------------------------------------------- signing
def _sign(query: str) -> str:
    if KEY_TYPE == "hmac":
        import hmac, hashlib
        return hmac.new(SECRET.encode(), query.encode(), hashlib.sha256).hexdigest()
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SECRET))
    return sk.sign(query.encode()).hex()


def _http(url: str, timeout: float = 15.0):
    """Returns (status_code, body_text, latency_ms, error_str)."""
    t0 = time.perf_counter()
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    if API_KEY and ("fapi" in url or "api.binance" in url):
        req.add_header("X-MBX-APIKEY", API_KEY)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(4000).decode("utf-8", "replace")
            return r.status, body, (time.perf_counter() - t0) * 1000, None
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read(1000).decode("utf-8", "replace")
        except Exception:
            pass
        return e.code, body, (time.perf_counter() - t0) * 1000, None
    except Exception as e:
        return None, "", (time.perf_counter() - t0) * 1000, f"{type(e).__name__}: {e}"


def signed_get(path: str, params: dict | None = None):
    p = dict(params or {})
    p["timestamp"] = int(time.time() * 1000)
    p["recvWindow"] = 5000
    q = urllib.parse.urlencode(p)
    q += "&signature=" + _sign(q)
    return _http(f"{FAPI}{path}?{q}")


# --------------------------------------------------------------------------- one probe round
def one_round() -> dict:
    r = {"ts": datetime.now(timezone.utc).isoformat(), "epoch": time.time(), "results": {}}

    # --- Q1 public connectivity, both surfaces -------------------------------
    for name, url in (("futures_ping", f"{FAPI}/fapi/v1/ping"),
                      ("spot_ping",    f"{SPOT}/api/v3/ping")):
        code, body, ms, err = _http(url)
        r["results"][name] = {"http": code, "ms": round(ms), "err": err,
                              "body": body[:200] if code and code != 200 else None}

    # --- Q2 authenticated path ----------------------------------------------
    if API_KEY and SECRET:
        code, body, ms, err = signed_get("/fapi/v2/account")
        entry = {"http": code, "ms": round(ms), "err": err}
        if code == 200:
            try:
                a = json.loads(body)
                entry["ok"] = True
                entry["canTrade"] = a.get("canTrade")
                entry["totalWalletBalance"] = a.get("totalWalletBalance")
                entry["note"] = "signed call accepted from this IP, no whitelist involved"
            except Exception:
                entry["body"] = body[:200]
        else:
            entry["body"] = body[:300]
        r["results"]["signed_account"] = entry

    # --- Q3 mimic the real workload: fetch 15m klines + compute --------------
    compute_ms, payload_bytes, ok_syms = 0.0, 0, []
    for sym in SYMBOLS:
        code, body, ms, err = _http(
            f"{FAPI}/fapi/v1/klines?symbol={sym}&interval=15m&limit=200")
        if code == 200:
            try:
                t0 = time.perf_counter()
                c = json.loads(body)
                # what the real engine does: ATR(14) + swing structure on 15m bars
                highs = [float(k[2]) for k in c]
                lows  = [float(k[3]) for k in c]
                closes= [float(k[4]) for k in c]
                tr = [max(highs[i] - lows[i],
                          abs(highs[i] - closes[i-1]),
                          abs(lows[i] - closes[i-1])) for i in range(1, len(c))]
                atr14 = sum(tr[-14:]) / 14
                swing_hi = max(highs[-49:-1]); swing_lo = min(lows[-49:-1])
                compute_ms += (time.perf_counter() - t0) * 1000
                payload_bytes += len(body)
                ok_syms.append({"sym": sym, "bars": len(c),
                                "atr14_pct": round(atr14 / closes[-1] * 100, 3),
                                "last": closes[-1]})
            except Exception as e:
                ok_syms.append({"sym": sym, "parse_error": str(e)[:80]})
        else:
            ok_syms.append({"sym": sym, "http": code, "err": err,
                            "body": (body or "")[:150]})
    r["results"]["klines_compute"] = {"symbols": ok_syms,
                                      "compute_ms_total": round(compute_ms, 1),
                                      "payload_kb": round(payload_bytes / 1024, 1)}

    # --- Q4 egress identity, every round (cheap and it is the whole point) ---
    code, body, ms, err = _http("https://ipinfo.io/json")
    if code == 200:
        try:
            j = json.loads(body)
            r["results"]["egress"] = {"ip": j.get("ip"), "city": j.get("city"),
                                      "region": j.get("region"), "country": j.get("country"),
                                      "org": j.get("org")}
            ip = j.get("ip")
            if ip and ip not in state["egress_ips"]:
                state["egress_ips"].append(ip)
                state["region"] = f'{j.get("city")}, {j.get("region")}, {j.get("country")} | {j.get("org")}'
                state["region_checked_at"] = r["ts"]
        except Exception as e:
            r["results"]["egress"] = {"parse_error": str(e)[:80]}
    else:
        r["results"]["egress"] = {"http": code, "err": err}

    # --- optional heartbeat (free dead-man's switch) --------------------------
    if HEARTBEAT:
        try:
            _http(HEARTBEAT, timeout=8)
            r["results"]["heartbeat"] = "sent"
        except Exception:
            r["results"]["heartbeat"] = "failed"

    state["round"] += 1
    r["round"] = state["round"]
    return r


# --------------------------------------------------------------------------- loop
def probe_loop():
    while True:
        t0 = time.time()
        try:
            rec = one_round()
        except Exception:
            rec = {"ts": datetime.now(timezone.utc).isoformat(), "epoch": t0,
                   "crash": traceback.format_exc()[-800:]}
        with log_lock:
            log.append(rec)
            if len(log) > MAX_LOG:
                del log[:len(log) - MAX_LOG]
        time.sleep(max(5, INTERVAL - (time.time() - t0)))


def summarise() -> dict:
    with log_lock:
        snapshot = list(log)
    if not snapshot:
        return {"state": "no rounds yet", "seconds_since_start": round(time.time() - START_TS)}

    codes: dict[str, int] = {}
    for rec in snapshot:
        for name, res in rec.get("results", {}).items():
            if isinstance(res, dict) and "http" in res:
                key = f"{name}: HTTP {res['http']}" if res["http"] else f"{name}: {res.get('err','?')[:40]}"
                codes[key] = codes.get(key, 0) + 1

    epochs = [r["epoch"] for r in snapshot if "epoch" in r]
    gaps, downtime = [], 0.0
    for a, b in zip(epochs, epochs[1:]):
        d = b - a
        if d > INTERVAL * 1.8:
            gaps.append({"from": datetime.fromtimestamp(a, timezone.utc).isoformat(),
                         "gap_sec": round(d)}) 
            downtime += d - INTERVAL
    wall = max(time.time() - START_TS, 1)
    last = snapshot[-1]

    # freshness of the most important single signal
    def st(name):
        return last.get("results", {}).get(name, {})

    return {
        "region_proven": state["region"],
        "distinct_egress_ips": state["egress_ips"],
        "rounds_completed": len(snapshot),
        "round_interval_sec": INTERVAL,
        "wall_clock_sec": round(wall),
        "uptime_pct_estimate": round(100 * (wall - downtime) / wall, 2),
        "interruption_count": len(gaps),
        "interruptions": gaps[-10:],
        "response_code_tally": dict(sorted(codes.items(), key=lambda kv: -kv[1])),
        "latest": {
            "futures_ping": st("futures_ping").get("http"),
            "spot_ping": st("spot_ping").get("http"),
            "signed_account": st("signed_account").get("http"),
            "egress": st("egress"),
            "klines_compute": st("klines_compute"),
        },
        "keys_configured": bool(API_KEY and SECRET),
    }


# --------------------------------------------------------------------------- http
class H(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        try:
            if self.path.startswith("/status"):
                self._send(200, json.dumps(summarise(), indent=2))
            elif self.path.startswith("/log"):
                with log_lock:
                    self._send(200, json.dumps(log[-500:], indent=1))
            elif self.path.startswith("/health"):
                self._send(200, json.dumps({"ok": True}))
            else:
                s = summarise()
                up = s.get("uptime_pct_estimate", "—")
                lp = s.get("latest", {})
                fp = lp.get("futures_ping"); sp = lp.get("spot_ping"); sa = lp.get("signed_account")
                eg = lp.get("egress") or {}
                kc = lp.get("klines_compute") or {}
                def mark(v):
                    return "✅ 200" if v == 200 else ("—" if v is None else f"❌ {v}")
                html = f"""<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{{font:15px/1.5 system-ui;margin:16px;background:#0f1115;color:#e6e6e6}}
h1{{font-size:19px}}table{{border-collapse:collapse;width:100%;max-width:640px}}
td{{border-bottom:1px solid #2a2f3a;padding:7px 4px}}td:last-child{{text-align:right;font-weight:600}}
.s{{color:#8b93a7;font-size:13px}}</style>
<h1>SUDARSHAN · Render free-tier probe</h1>
<table>
<tr><td>Region actually running in</td><td>{s.get('region_proven') or '—'}</td></tr>
<tr><td>Egress IPs seen</td><td>{len(s.get('distinct_egress_ips') or [])}</td></tr>
<tr><td>Futures API reachable</td><td>{mark(fp)}</td></tr>
<tr><td>Spot API reachable</td><td>{mark(sp)}</td></tr>
<tr><td>Authenticated (signed) call</td><td>{mark(sa)}</td></tr>
<tr><td>Klines + compute</td><td>{kc.get('payload_kb','—')} KB in {kc.get('compute_ms_total','—')} ms</td></tr>
<tr><td>Rounds completed</td><td>{s.get('rounds_completed','—')}</td></tr>
<tr><td>Uptime estimate</td><td>{up}%</td></tr>
<tr><td>Interruptions (spin-downs/restarts)</td><td>{s.get('interruption_count','—')}</td></tr>
<tr><td>Keys configured</td><td>{'yes' if s.get('keys_configured') else 'no (public only)'}</td></tr>
</table>
<p class="s">Auto-refreshes every 30s. Raw: <a style="color:#6cf" href="/status">/status</a> ·
<a style="color:#6cf" href="/log">/log</a></p>
<script>setTimeout(()=>location.reload(),30000)</script>"""
                self._send(200, html, "text/html; charset=utf-8")
        except Exception as e:
            self._send(500, json.dumps({"error": str(e), "tb": traceback.format_exc()[-500:]}))

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    threading.Thread(target=probe_loop, daemon=True).start()
    print(f"probe up on 0.0.0.0:{PORT} | interval={INTERVAL}s | symbols={SYMBOLS} | "
          f"keys={'yes' if API_KEY else 'no'}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
