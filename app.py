#!/usr/bin/env python3
"""
SUDARSHAN — Render free-tier probe  (Docker web service, read-only)

WHAT THIS IS
  A deliberately dumb stand-in for the real engine. It does exactly what the real bot would
  do to Binance -- public calls, an authenticated call, and a fetch-klines-then-compute step
  that mirrors our actual 15m indicator work -- and records what happens. It also measures
  how often Render's free tier actually keeps the container alive.

WHAT IT ANSWERS (the only questions that matter before building anything)
  Q1  Can a Render <region> free container reach fapi.binance.com at all?  (451 / 403 / 418?)
  Q2  Do signed/authenticated calls work from a shared datacenter IP with no whitelist?
  Q3  Is the free tier actually stably alive (spin-downs, restarts, suspensions), and how
      much CPU does our real workload need on a 0.1-CPU instance?
  Q4  What is our egress IP, and does it ever change?  (decides whether whitelisting is
      ever possible, and proves we really landed in the intended region)

WHAT IT NEVER DOES
  It never places, modifies or cancels an order. No /order path exists in this file.
  Safe to run with a live API key.

DESIGN RULE (v2, learned the hard way)
  EVERY step is independently guarded. A bad API key, a network error, or a parse failure in
  one step can NEVER blank the whole round. The public ping is recorded first and recorded
  always -- it needs no credentials and it is the most important datapoint we collect.

ENDPOINTS (open in a browser, phone-friendly)
  /         tiny dashboard
  /status   JSON summary + last 25 results
  /log      full raw log JSON

ENVIRONMENT VARIABLES (all optional -> it runs with none)
  BINANCE_API_KEY     your key. Omit to test public paths only.
  BINANCE_SECRET      your secret (hex private key for ed25519, or the alphanumeric one).
  KEY_TYPE            "auto" (default) | "ed25519" | "hmac"
                      "auto" inspects your secret: 32-byte hex -> ed25519, otherwise HMAC.
  PROBE_INTERVAL_SEC  seconds between probe rounds (default 300; keep it modest -- Render may
                      suspend free services that make high outbound API volume)
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
KEY_TYPE     = os.environ.get("KEY_TYPE", "auto").strip().lower()
SYMBOLS      = [s.strip().upper() for s in os.environ.get(
                  "PROBE_SYMBOLS", "BTCUSDT,ETHUSDT,SOLUSDT").split(",") if s.strip()]
HEARTBEAT    = os.environ.get("HEARTBEAT_URL", "").strip()

# --- WebSocket soak (the piece R1/R2 actually depend on) --------------------
WS_ENABLED   = os.environ.get("WS_ENABLED", "1").strip().lower() not in ("0", "false", "no")
WS_SOAK_SEC  = int(os.environ.get("WS_SOAK_SEC", "600"))    # hold each connection this long
WS_STALL_SEC = int(os.environ.get("WS_STALL_SEC", "90"))     # silent connection => dead
WS_STREAMS   = [x.strip() for x in os.environ.get(
                 "WS_STREAMS", "btcusdt@aggTrade,ethusdt@aggTrade,btcusdt@kline_15m"
               ).split(",") if x.strip()]
WS_BASE      = "wss://fapi.binance.com/stream?streams="
WS_USER_BASE = "wss://fapi.binance.com/ws/"
START_TS     = time.time()
MAX_LOG      = 4000

FAPI = "https://fapi.binance.com"     # USDⓈ-M futures -- the venue the strategy runs on
SPOT = "https://api.binance.com"      # spot -- control group
UA   = "sudarshan-probe/2.0"

log: list[dict] = []
log_lock = threading.Lock()
state = {"round": 0, "region": None, "region_checked_at": None, "egress_ips": []}


# --------------------------------------------------------------------------- signing
class KeyConfigError(Exception):
    """Raised when the supplied credentials cannot be used at all."""


def resolve_key_type() -> tuple[str, str]:
    """Decide ed25519 vs hmac. Returns (effective_type, note). Never raises."""
    if not SECRET:
        return "none", "no secret set -- authenticated steps will be skipped"
    if KEY_TYPE in ("ed25519", "hmac"):
        note = f"forced by KEY_TYPE={KEY_TYPE}"
        if KEY_TYPE == "ed25519":
            try:
                raw = bytes.fromhex(SECRET)
                if len(raw) != 32:
                    return "hmac", (f"KEY_TYPE=ed25519 but the secret decodes to {len(raw)} bytes "
                                    f"(Ed25519 needs 32) -- falling back to HMAC")
            except ValueError:
                return "hmac", ("KEY_TYPE=ed25519 but the secret is not hexadecimal -- this is a "
                                "CLASSIC Binance key. Auto-switched to HMAC.")
        return KEY_TYPE, note
    # auto
    try:
        raw = bytes.fromhex(SECRET)
        if len(raw) == 32:
            return "ed25519", f"auto-detected: {len(raw)}-byte hex secret"
        return "hmac", f"auto-detected: secret decodes to {len(raw)} bytes, not 32 -- HMAC"
    except ValueError:
        return "hmac", "auto-detected: secret is not hexadecimal (classic Binance key) -- HMAC"


def _sign(query: str, ktype: str) -> str:
    if ktype == "hmac":
        import hmac, hashlib
        return hmac.new(SECRET.encode(), query.encode(), hashlib.sha256).hexdigest()
    if ktype == "ed25519":
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SECRET))
        return sk.sign(query.encode()).hex()
    raise KeyConfigError(f"unsupported key type {ktype!r}")


def _http(url: str, timeout: float = 15.0, extra_headers: dict | None = None,
          max_bytes: int = 8_000_000):
    """Returns (status_code, body_text, latency_ms, error_str). Never raises.

    NOTE: max_bytes exists because v2 read only 4000 bytes and silently truncated
    Binance payloads (the account object and 200-bar kline arrays are far larger),
    which produced JSONDecodeError and disguised two working endpoints as failures.
    Read the whole thing; truncate only when STORING it.
    """
    t0 = time.perf_counter()
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    for k, v in (extra_headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(max_bytes).decode("utf-8", "replace")
            _note_weight(r.headers)
            return r.status, body, (time.perf_counter() - t0) * 1000, None
    except urllib.error.HTTPError as e:
        _note_weight(getattr(e, "headers", None))
        body = ""
        try:
            body = e.read(4000).decode("utf-8", "replace")
        except Exception:
            pass
        return e.code, body, (time.perf_counter() - t0) * 1000, None
    except Exception as e:
        return None, "", (time.perf_counter() - t0) * 1000, f"{type(e).__name__}: {e}"


def signed_get(path: str, params: dict | None = None, timeout: float = 15.0):
    """Signed Binance GET. Raises KeyConfigError only if credentials are unusable."""
    ktype, _ = resolve_key_type()
    if ktype == "none":
        raise KeyConfigError("no API key/secret configured")
    p = dict(params or {})
    p["timestamp"] = int(time.time() * 1000)
    p["recvWindow"] = 5000
    q = urllib.parse.urlencode(p)
    q += "&signature=" + _sign(q, ktype)
    return _http(f"{FAPI}{path}?{q}", timeout=timeout,
                 extra_headers={"X-MBX-APIKEY": API_KEY})


def _safe(results: dict, name: str, fn):
    """Run one diagnostic step. A failure is RECORDED, never allowed to kill the round."""
    try:
        results[name] = fn()
    except KeyConfigError as e:
        results[name] = {"skipped": str(e)}
    except Exception as e:
        results[name] = {"error": f"{type(e).__name__}: {e}", "tb": traceback.format_exc()[-400:]}


# --------------------------------------------------------------- rate-limit weight
def _note_weight(headers):
    """Binance reports per-IP used weight. On a SHARED Render egress this reveals the
    neighbours' load, not just ours -- a direct measurement of the shared-IP hazard."""
    if not headers:
        return
    try:
        w = headers.get("X-MBX-USED-WEIGHT-1M") or headers.get("x-mbx-used-weight-1m")
        if w is not None:
            state["used_weight_1m"] = int(w)
            state["weight_seen_at"] = datetime.now(timezone.utc).isoformat()
        ra = headers.get("Retry-After") or headers.get("retry-after")
        if ra is not None:
            state["last_retry_after"] = ra
    except Exception:
        pass


# --------------------------------------------------------------- WebSocket soak
ws_lock = threading.Lock()
ws_state = {
    "enabled": WS_ENABLED, "streams": WS_STREAMS, "soak_sec": WS_SOAK_SEC,
    "connects": 0, "reconnects": 0, "messages": 0,
    "connected_sec_total": 0.0, "attempt_sec_total": 0.0,
    "max_gap_sec": 0.0, "last_hold_sec": None, "msgs_last_hold": None,
    "last_connect_ms": None, "last_error": None, "last_msg_age_sec": None,
    "listen_key": None, "listen_key_result": None, "user_stream": None,
    "events": [],
}


def _ws_event(kind, detail=""):
    with ws_lock:
        ws_state["events"].append({"ts": datetime.now(timezone.utc).isoformat(),
                                   "kind": kind, "detail": str(detail)[:220]})
        del ws_state["events"][:-40]


def _post(url, extra_headers=None, timeout=15.0, data=b""):
    """Tiny POST helper. Used ONLY for /fapi/v1/listenKey -- never for orders."""
    t0 = time.perf_counter()
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"User-Agent": UA, **(extra_headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            _note_weight(r.headers)
            return r.status, r.read(4000).decode("utf-8", "replace"), (time.perf_counter() - t0) * 1000, None
    except urllib.error.HTTPError as e:
        try:
            b = e.read(4000).decode("utf-8", "replace")
        except Exception:
            b = ""
        return e.code, b, (time.perf_counter() - t0) * 1000, None
    except Exception as e:
        return None, "", (time.perf_counter() - t0) * 1000, f"{type(e).__name__}: {e}"


def listenkey_test():
    """Create a user-data listenKey and connect to it briefly.

    This is the transport behind every 'order filled / stop triggered' notification the
    Telegram bot depends on. POST /fapi/v1/listenKey needs only the API-key header, not a
    signature -- and it is NOT an order path: it creates a stream token, nothing more.
    """
    if not API_KEY:
        return {"skipped": "no BINANCE_API_KEY set"}
    code, body, ms, err = _post(f"{FAPI}/fapi/v1/listenKey",
                                extra_headers={"X-MBX-APIKEY": API_KEY})
    out = {"create_http": code, "create_ms": round(ms), "err": err}
    if code != 200:
        out["body"] = (body or "")[:200]
        return out
    key = json.loads(body).get("listenKey")
    out["listen_key_len"] = len(key or "")
    with ws_lock:
        ws_state["listen_key_result"] = {"created": True, "http": code}
    try:
        import websocket
        t0 = time.perf_counter()
        w = websocket.create_connection(WS_USER_BASE + key, timeout=12)
        w.settimeout(2.0)
        out["user_stream_connect_ms"] = round((time.perf_counter() - t0) * 1000)
        held, n = 0, 0
        t_start = time.time()
        while time.time() - t_start < 20:
            try:
                if w.recv():
                    n += 1
            except websocket.WebSocketTimeoutException:
                continue
        out["user_stream_held_sec"] = round(time.time() - t_start)
        out["user_stream_msgs"] = n
        try:
            w.close()
        except Exception:
            pass
        out["note"] = ("user-data stream connected. Zero messages is EXPECTED: it only "
                       "emits events when an order/position on this account changes.")
    except Exception as e:
        out["user_stream_error"] = f"{type(e).__name__}: {e}"
    with ws_lock:
        ws_state["user_stream"] = out
    return out


def ws_soak_loop():
    """Hold a Binance market-data WebSocket open continuously and record how it behaves.

    This is the load-bearing test. If WS survives on Render's Singapore free tier, the real
    engine can be event-driven (low REST volume => stays clear of the suspension clause) and
    notifications work. If WS is reset by the proxy, the whole hybrid design changes.
    """
    if not WS_ENABLED:
        _ws_event("disabled", "WS_ENABLED=0")
        return
    try:
        import websocket
    except ImportError:
        _ws_event("fatal", "websocket-client not installed")
        return
    url = WS_BASE + ",".join(WS_STREAMS)
    _ws_event("start", f"{len(WS_STREAMS)} streams, soak {WS_SOAK_SEC}s")
    first = True
    while True:
        t_attempt = time.time()
        _ws_event("connecting", url[:140])
        try:
            t0 = time.perf_counter()
            ws = websocket.create_connection(url, timeout=12)
            connect_ms = (time.perf_counter() - t0) * 1000
            ws.settimeout(2.0)
            with ws_lock:
                ws_state["connects"] += 1
                if not first:
                    ws_state["reconnects"] += 1
                ws_state["last_connect_ms"] = round(connect_ms)
            _ws_event("connected", f"{connect_ms:.0f} ms")
            first = False

            t_start = t_last = time.time()
            n = 0
            while time.time() - t_start < WS_SOAK_SEC:
                try:
                    msg = ws.recv()
                    now = time.time()
                    if msg:
                        n += 1
                        gap = now - t_last
                        with ws_lock:
                            ws_state["messages"] += 1
                            if gap > ws_state["max_gap_sec"]:
                                ws_state["max_gap_sec"] = round(gap, 2)
                            ws_state["last_msg_age_sec"] = 0.0
                        t_last = now
                except websocket.WebSocketTimeoutException:
                    idle = time.time() - t_last
                    with ws_lock:
                        ws_state["last_msg_age_sec"] = round(idle, 1)
                    if idle > WS_STALL_SEC:
                        _ws_event("stall", f"no data for {idle:.0f}s")
                        break
                except Exception as e:
                    _ws_event("recv_error", f"{type(e).__name__}: {e}")
                    break
            held = time.time() - t_start
            with ws_lock:
                ws_state["connected_sec_total"] += held
                ws_state["last_hold_sec"] = round(held)
                ws_state["msgs_last_hold"] = n
            try:
                ws.close()
            except Exception:
                pass
            _ws_event("closed", f"held {held:.0f}s, {n} msgs")
        except Exception as e:
            with ws_lock:
                ws_state["last_error"] = f"{type(e).__name__}: {e}"
            _ws_event("connect_failed", ws_state["last_error"])
            time.sleep(15)
        with ws_lock:
            ws_state["attempt_sec_total"] += time.time() - t_attempt
        time.sleep(2)


def ws_summary():
    with ws_lock:
        d = dict(ws_state)
        d["events"] = ws_state["events"][-15:]
    held = d["connected_sec_total"]
    att = d["attempt_sec_total"]
    d["ws_availability_pct"] = round(100 * held / att, 2) if att > 0 else None
    d["streams"] = len(d["streams"])
    return d


# --------------------------------------------------------------------------- one probe round
def one_round() -> dict:
    r = {"ts": datetime.now(timezone.utc).isoformat(), "epoch": time.time(), "results": {}}
    res = r["results"]

    # --- Q1 FIRST AND ALWAYS: public connectivity ----------------------------
    # No credentials, no dependencies. This is the datapoint that decides everything.
    for name, url in (("futures_ping", f"{FAPI}/fapi/v1/ping"),
                      ("spot_ping",    f"{SPOT}/api/v3/ping")):
        _safe(res, name, lambda u=url: _fmt_ping(u))

    # --- Q4 egress identity (early: it is the context for everything else) ----
    _safe(res, "egress", _egress)

    # --- credential sanity, reported before we use them ----------------------
    ktype, note = resolve_key_type()
    res["key_diagnostics"] = {"key_type_effective": ktype, "note": note,
                              "api_key_present": bool(API_KEY), "secret_present": bool(SECRET)}

    # --- Q2 authenticated path ----------------------------------------------
    if API_KEY and SECRET:
        _safe(res, "signed_account", _signed_account)
    else:
        res["signed_account"] = {"skipped": "no BINANCE_API_KEY / BINANCE_SECRET set"}

    # --- Q3 mimic the real workload: fetch 15m klines + compute --------------
    _safe(res, "klines_compute", _klines_compute)

    # --- optional heartbeat (free dead-man's switch) --------------------------
    if HEARTBEAT:
        _safe(res, "heartbeat", lambda: _ok(_http(HEARTBEAT, timeout=8)[0]))

    r["weight_1m"] = state.get("used_weight_1m")
    r["ws_connects"] = ws_state.get("connects")
    r["ws_messages"] = ws_state.get("messages")
    r["ws_reconnects"] = ws_state.get("reconnects")

    state["round"] += 1
    r["round"] = state["round"]
    if state["round"] % max(1, int(3600 / max(INTERVAL, 1))) == 1:
        _safe(res, "listenkey", listenkey_test)
    return r


def _ok(code) -> str:
    return "sent" if code == 200 else f"http {code}"


def _fmt_ping(url: str) -> dict:
    code, body, ms, err = _http(url)
    out = {"http": code, "ms": round(ms), "err": err}
    if code is not None and code != 200:
        out["body"] = (body or "")[:300]
        if code == 451:
            out["diagnosis"] = "GEO-BLOCK: this egress region is restricted by Binance"
        elif code == 403:
            out["diagnosis"] = "IP-level block (shared/datacenter range)"
        elif code == 418:
            out["diagnosis"] = "IP banned for repeated limit violations"
        elif code == 429:
            out["diagnosis"] = "rate limited (informational; our volume is low)"
    return out


def _egress() -> dict:
    code, body, ms, err = _http("https://ipinfo.io/json")
    if code != 200:
        return {"http": code, "err": err}
    j = json.loads(body)
    ip = j.get("ip")
    if ip and ip not in state["egress_ips"]:
        state["egress_ips"].append(ip)
        state["region"] = f'{j.get("city")}, {j.get("region")}, {j.get("country")} | {j.get("org")}'
        state["region_checked_at"] = datetime.now(timezone.utc).isoformat()
    return {"ip": ip, "city": j.get("city"), "region": j.get("region"),
            "country": j.get("country"), "org": j.get("org"), "ms": round(ms)}


def _signed_account() -> dict:
    code, body, ms, err = signed_get("/fapi/v2/account")
    entry = {"http": code, "ms": round(ms), "err": err}
    if code == 200:
        a = json.loads(body)
        entry.update({"ok": True, "canTrade": a.get("canTrade"),
                      "totalWalletBalance": a.get("totalWalletBalance"),
                      "note": "signed call accepted from this IP; no whitelist involved"})
    else:
        entry["body"] = (body or "")[:300]
        if code == 401 or "-2015" in (body or ""):
            entry["diagnosis"] = ("key rejected -- check that the key has Futures/Reading "
                                  "permission and that key_type matches the key style")
    return entry


def _klines_compute() -> dict:
    compute_ms, payload_bytes, rows = 0.0, 0, []
    for sym in SYMBOLS:
        code, body, ms, err = _http(f"{FAPI}/fapi/v1/klines?symbol={sym}&interval=15m&limit=200")
        if code != 200:
            rows.append({"sym": sym, "http": code, "err": err, "body": (body or "")[:150]})
            continue
        try:
            t0 = time.perf_counter()
            c = json.loads(body)
            highs  = [float(k[2]) for k in c]
            lows   = [float(k[3]) for k in c]
            closes = [float(k[4]) for k in c]
            tr = [max(highs[i] - lows[i], abs(highs[i] - closes[i-1]),
                      abs(lows[i] - closes[i-1])) for i in range(1, len(c))]
            atr14 = sum(tr[-14:]) / 14
            rows.append({"sym": sym, "bars": len(c),
                         "atr14_pct": round(atr14 / closes[-1] * 100, 3),
                         "last": closes[-1],
                         "swing_hi": max(highs[-49:-1]), "swing_lo": min(lows[-49:-1])})
            compute_ms += (time.perf_counter() - t0) * 1000
            payload_bytes += len(body)
        except Exception as e:
            rows.append({"sym": sym, "parse_error": f"{type(e).__name__}: {e}"[:120]})
    return {"symbols": rows, "compute_ms_total": round(compute_ms, 1),
            "payload_kb": round(payload_bytes / 1024, 1)}


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


def _timeline(snapshot, every=None, cap=120):
    """Compact per-round history so a 1-2 hour soak is readable at a glance."""
    def code(rec, name):
        v = rec.get("results", {}).get(name, {})
        return v.get("http") if isinstance(v, dict) else None
    rows = [{"t": rec["ts"][11:19], "fut": code(rec, "futures_ping"),
             "spot": code(rec, "spot_ping"), "signed": code(rec, "signed_account"),
             "w": rec.get("weight_1m"), "ws_msgs": rec.get("ws_messages"),
             "ws_rc": rec.get("ws_reconnects")}
            for rec in snapshot[-cap:]]
    return rows


def summarise() -> dict:
    with log_lock:
        snapshot = list(log)
    if not snapshot:
        return {"state": "no rounds yet", "seconds_since_start": round(time.time() - START_TS)}

    codes: dict[str, int] = {}
    crashes = 0
    for rec in snapshot:
        if "crash" in rec:
            crashes += 1
        for name, r0 in rec.get("results", {}).items():
            if isinstance(r0, dict) and "http" in r0:
                key = (f"{name}: HTTP {r0['http']}" if r0["http"]
                       else f"{name}: {str(r0.get('err'))[:40]}")
                codes[key] = codes.get(key, 0) + 1

    epochs = [rec["epoch"] for rec in snapshot if "epoch" in rec]
    gaps, downtime = [], 0.0
    for a, b in zip(epochs, epochs[1:]):
        d = b - a
        if d > INTERVAL * 1.8:
            gaps.append({"from": datetime.fromtimestamp(a, timezone.utc).isoformat(),
                         "gap_sec": round(d)})
            downtime += d - INTERVAL
    wall = max(time.time() - START_TS, 1)
    last = snapshot[-1]
    lr = last.get("results", {})

    def g(name, field="http"):
        v = lr.get(name, {})
        return v.get(field) if isinstance(v, dict) else None

    return {
        "region_proven": state["region"],
        "distinct_egress_ips": state["egress_ips"],
        "rounds_completed": len(snapshot),
        "round_interval_sec": INTERVAL,
        "wall_clock_sec": round(wall),
        "uptime_pct_estimate": round(100 * (wall - downtime) / wall, 2),
        "interruption_count": len(gaps),
        "interruptions": gaps[-10:],
        "round_crashes": crashes,
        "response_code_tally": dict(sorted(codes.items(), key=lambda kv: -kv[1])),
        "key_diagnostics": lr.get("key_diagnostics"),
        "used_weight_1m": state.get("used_weight_1m"),
        "timeline": _timeline(snapshot),
        "websocket": ws_summary(),
        "latest": {
            "futures_ping": g("futures_ping"),
            "futures_ping_body": g("futures_ping", "body"),
            "spot_ping": g("spot_ping"),
            "signed_account": g("signed_account"),
            "signed_account_diagnosis": g("signed_account", "diagnosis"),
            "signed_account_error": g("signed_account", "error"),
            "signed_account_skipped": g("signed_account", "skipped"),
            "signed_account_balance": g("signed_account", "totalWalletBalance"),
            "egress": lr.get("egress"),
            "klines_compute": lr.get("klines_compute"),
            "klines_error": (kc0.get("error") if isinstance(kc0 := lr.get("klines_compute"), dict) else None),
        },
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
                lp = s.get("latest", {}) or {}
                kd = s.get("key_diagnostics") or {}
                kc = lp.get("klines_compute") or {}
                ws = s.get("websocket") or {}
                def mark(v):
                    return "✅ 200" if v == 200 else ("—" if v is None else f"❌ {v}")
                fp = lp.get("futures_ping")
                verdict = {200: "reachable", 451: "GEO-BLOCKED", 403: "IP-blocked",
                           418: "IP banned", 429: "rate limited"}.get(fp, "no data yet")
                html = f"""<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{{font:15px/1.5 system-ui;margin:16px;background:#0f1115;color:#e6e6e6}}
h1{{font-size:19px}}table{{border-collapse:collapse;width:100%;max-width:660px}}
td{{border-bottom:1px solid #2a2f3a;padding:7px 4px}}td:last-child{{text-align:right;font-weight:600}}
.s{{color:#8b93a7;font-size:13px}}.warn{{color:#ffb454}}</style>
<h1>SUDARSHAN · Render probe</h1>
<table>
<tr><td>Region actually running in</td><td>{s.get('region_proven') or '—'}</td></tr>
<tr><td>Egress IPs seen</td><td>{len(s.get('distinct_egress_ips') or [])}</td></tr>
<tr><td>Binance futures verdict</td><td class="{'warn' if fp!=200 else ''}">{verdict}</td></tr>
<tr><td>Futures API {'' if fp else ''}</td><td>{mark(fp)}</td></tr>
<tr><td>Spot API</td><td>{mark(lp.get('spot_ping'))}</td></tr>
<tr><td>Authenticated (signed) call</td><td>{mark(lp.get('signed_account'))}</td></tr>
<tr><td>Key type in use</td><td>{kd.get('key_type_effective','—')}</td></tr>
<tr><td>Klines + compute</td><td>{kc.get('payload_kb','—')} KB in {kc.get('compute_ms_total','—')} ms</td></tr>
<tr><td>WebSocket (market streams)</td><td>{ws.get('messages','—')} msgs · {ws.get('reconnects','—')} reconnects</td></tr>
<tr><td>WS availability</td><td>{ws.get('ws_availability_pct','—')}%</td></tr>
<tr><td>WS last hold / connect</td><td>{ws.get('last_hold_sec','—')}s / {ws.get('last_connect_ms','—')} ms</td></tr>
<tr><td>REST weight used (1m, per IP)</td><td>{s.get('used_weight_1m','—')} / 2400</td></tr>
<tr><td>Rounds completed</td><td>{s.get('rounds_completed','—')}</td></tr>
<tr><td>Uptime estimate</td><td>{s.get('uptime_pct_estimate','—')}%</td></tr>
<tr><td>Interruptions</td><td>{s.get('interruption_count','—')}</td></tr>
</table>
<p class="s">{kd.get('note','')}<br>Auto-refreshes every 30s. Raw:
<a style="color:#6cf" href="/status">/status</a> · <a style="color:#6cf" href="/log">/log</a></p>
<script>setTimeout(()=>location.reload(),30000)</script>"""
                self._send(200, html, "text/html; charset=utf-8")
        except Exception as e:
            self._send(500, json.dumps({"error": str(e), "tb": traceback.format_exc()[-500:]}))

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    ktype, note = resolve_key_type()
    threading.Thread(target=probe_loop, daemon=True).start()
    threading.Thread(target=ws_soak_loop, daemon=True).start()
    print(f"probe up on 0.0.0.0:{PORT} | interval={INTERVAL}s | symbols={SYMBOLS} | "
          f"key_type={ktype} ({note})", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
