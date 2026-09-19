#!/usr/bin/env python3
"""
ws_check.py — "Does Binance's WebSocket work from THIS connection?"

WHY THIS EXISTS
  From Render (Singapore free tier) we measured:
      REST  api  -> HTTP 200   (works)
      WS    fapi -> HTTP 403   (CloudFront WAF, x-amz-cf-pop SIN2-P5)
      WS    fstream -> TCP timeout
  Same IP, same region, same instant: REST passes and WS is refused. That means it is NOT a
  geographic block (which would kill both) -- Binance's WebSocket front-end appears to apply a
  stricter rule to CLOUD/DATACENTER network ranges. Render's Singapore egress is AS16509 Amazon,
  so we are connecting to Binance's AWS-fronted WS *from* AWS.

  The decisive question: does WS work from a normal residential connection (your phone / laptop
  / home wi-fi)? If yes, the event-driven engine belongs on your device and Render stays a
  REST-only fallback. If no, we design REST-only everywhere.

HOW TO RUN  (about 60 seconds)
  Phone (Termux):            Laptop/PC:
    pkg install python         pip install websocket-client
    pip install websocket-client
    python ws_check.py         python ws_check.py

  It only OPENS connections and reads market data. No keys, no orders, nothing to configure.

WHAT TO SEND BACK
  Just paste the whole printed table.
"""

from __future__ import annotations
import socket
import sys
import time

try:
    import websocket
except ImportError:
    sys.exit("Missing dependency.  Run:  pip install websocket-client")

# (label, url, extra headers)
CANDIDATES = [
    # --- REST control: proves what a working connection to Binance looks like here ---
    ("REST  fapi ping          ", "https://fapi.binance.com/fapi/v1/ping", None),

    # --- futures market-data WS, both documented hosts and both path styles ---
    ("WS    fapi  /ws           ", "wss://fapi.binance.com/ws/btcusdt@aggTrade", None),
    ("WS    fapi  /stream       ", "wss://fapi.binance.com/stream?streams=btcusdt@aggTrade", None),
    ("WS    fstream /ws         ", "wss://fstream.binance.com/ws/btcusdt@aggTrade", None),
    ("WS    fstream /stream     ", "wss://fstream.binance.com/stream?streams=btcusdt@aggTrade", None),

    # --- spot WS: if futures-WS is blocked but spot-WS works, that is a very useful clue ---
    ("WS    spot   /ws          ", "wss://stream.binance.com:9443/ws/btcusdt@aggTrade", None),

    # --- identity permutations, in case the WAF is keying off them ---
    ("WS    fapi  + browser UA  ", "wss://fapi.binance.com/ws/btcusdt@aggTrade",
     {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"}),
    ("WS    fstream + browser UA", "wss://fstream.binance.com/ws/btcusdt@aggTrade",
     {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}),
]


def dns(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except Exception as e:
        return f"DNS-FAIL({type(e).__name__})"


def check(label: str, url: str, headers: dict | None):
    row = {"label": label, "url": url, "ok": False, "detail": ""}
    if url.startswith("https"):
        import json as _json, urllib.request, urllib.error
        try:
            t0 = time.perf_counter()
            with urllib.request.urlopen(url, timeout=12) as r:
                body = r.read(200).decode("utf-8", "replace")
            row.update(ok=(r.status == 200), http=r.status,
                       ms=round((time.perf_counter() - t0) * 1000), detail=body[:80])
        except urllib.error.HTTPError as e:
            row.update(http=e.code, detail=f"HTTP {e.code}")
        except Exception as e:
            row["detail"] = f"{type(e).__name__}: {e}"
        return row

    host = url.split("//", 1)[1].split("/", 1)[0].split(":")[0]
    row["dns"] = dns(host)
    try:
        t0 = time.perf_counter()
        kw = {"header": [f"{k}: {v}" for k, v in headers.items()]} if headers else {}
        ws = websocket.create_connection(url, timeout=12, **kw)
        ws.settimeout(6)
        row["ms"] = round((time.perf_counter() - t0) * 1000)
        try:
            msg = ws.recv()
            row.update(ok=True, detail=f"first msg: {str(msg)[:70]}")
        except Exception as e:
            row["detail"] = f"connected but no data: {type(e).__name__}"
        try:
            ws.close()
        except Exception:
            pass
    except Exception as e:
        row["detail"] = f"{type(e).__name__}: {str(e)[:95]}"
    return row


def main():
    print(__doc__)
    print("=" * 100)
    print(f"host: {socket.gethostname()}   time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 100)
    results = []
    for label, url, headers in CANDIDATES:
        r = check(label, url, headers)
        results.append(r)
        status = "OK   " if r["ok"] else "FAIL "
        extra = f" http={r.get('http')}" if "http" in r else (f" dns={r.get('dns')}" if "dns" in r else "")
        print(f"  {status} {label} {str(r.get('ms','')).rjust(6)} ms{extra:24s} {r['detail'][:60]}")

    ws_ok = [r for r in results if r["ok"] and "WS" in r["label"]]
    rest_ok = [r for r in results if r["ok"]]
    print("\n" + "=" * 100)
    print(f"WebSocket working : {len(ws_ok)} of {len([r for r in results if 'WS' in r['label']])}")
    print(f"Anything working  : {len(rest_ok)} of {len(results)}")
    print("\nHOW TO READ THIS")
    print("  WebSocket works  -> the event-driven engine belongs on THIS device.")
    print("  WS fails, REST ok-> same cloud-style filtering; we design REST-only (which the")
    print("                      strategy tolerates, because Binance holds the exits natively).")
    print("  Both fail        -> this connection cannot reach Binance at all; tell me and we")
    print("                      re-plan.")
    print("\nPaste this whole output back into the chat.")


if __name__ == "__main__":
    main()
