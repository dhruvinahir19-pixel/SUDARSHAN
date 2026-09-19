#!/usr/bin/env python3
"""
coinswitch_pairs.py — count CoinSwitch PRO perpetual futures, and measure their liquidity.

WHY THIS EXISTS
  CoinSwitch gates EVERY market-data endpoint behind authentication. Verified exhaustively
  (not assumed) — all of these return 401 with no key:
      /trade/api/v2/futures/all-pairs/ticker   -> 401 Invalid access
      /trade/api/v2/futures/ticker             -> 401 Invalid access
      /trade/api/v2/futures/klines             -> 401 Invalid access
      /trade/api/v2/futures/trades             -> 401 Invalid access
      /trade/api/v2/futures/instrument_info    -> 401 API Key or Signature is not Correct
      dma.coinswitch.co/v5/market/...          -> 401 Signature validation failed
  The ONLY public endpoint on the entire API is GET /trade/api/v2/time (200).

  Also established, so nobody re-walks this:
    * developer.coinswitch.co  -> NO DNS RECORD. It does not exist.
    * api-trading.coinswitch.co -> the DOCS WEBSITE (Docusaurus). API paths return HTML 404.
    * The real base URL, from their own api-surfaces page:
          Spot v2     https://coinswitch.co/trade/api/v2
          Futures v2  https://coinswitch.co/trade/api/v2/futures
          HFT         https://dma.coinswitch.co/v5   and   /dma/api/v1

  So a key is genuinely required. This module is what turns that key into the answer.

WHAT IT REPORTS
  1. COUNT      — `/trade/api/v2/futures/all-pairs/ticker?exchange=EXCHANGE_2` returns
                  `data` keyed by symbol. The number of keys IS the number of tradable pairs.
  2. LIQUIDITY  — the same response carries 24 h quote volume, best bid/ask, open interest and
                  funding rate per pair. So we get a liquidity ranking, not just a count —
                  which is what actually decides whether a $50-200 account can trade a pair.
  3. RULES      — `/futures/instrument_info` gives min quantity, step size, tick size,
                  leverage limits, taker/maker fees, maintenance margin per symbol.
  4. COVERAGE   — how many of OUR 301 traded symbols exist there, and their measured liquidity.

AUTH (their documented Ed25519 scheme)
    signed_message = METHOD + path_with_query + epoch        (body is NOT signed)
    headers: X-AUTH-APIKEY, X-AUTH-SIGNATURE, X-AUTH-EPOCH
    Drift: keep within ±5 s of server time; >60 s is rejected.

SAFETY
  Read-only. There is no order-placement path in this file.
"""

from __future__ import annotations
import csv
import json
import os
import statistics
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

BASE_Q      = "https://coinswitch.co"                 # from the official api-surfaces page
FUTURES     = "/trade/api/v2/futures"
HFT_HOST    = "https://dma.coinswitch.co"
UA          = "sudarshan-pairs/1.0"
OUR_TRADES  = [Path("output/year2026/trades_pick15.csv")]
OUT_DIR     = Path("output/broker_audit")


# ------------------------------------------------------------------ signing
def sign(method: str, path_with_query: str, secret_hex: str, epoch: str) -> str:
    """Exactly the documented scheme: METHOD + decoded path + epoch, Ed25519, hex."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    msg = f"{method.upper()}{path_with_query}{epoch}"
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(secret_hex))
    return sk.sign(msg.encode("utf-8")).hex()


def auth_get(path: str, params: dict | None = None, key: str = "", secret: str = "",
             host: str = BASE_Q, timeout: float = 25.0):
    """Signed GET. Returns (status, parsed, ms, error). Never raises."""
    p = dict(params or {})
    if p:
        sep = "&" if "?" in path else "?"
        path_q = path + sep + urllib.parse.urlencode(p)
    else:
        path_q = path
    decoded = urllib.parse.unquote_plus(path_q)
    epoch = str(int(time.time() * 1000))
    t0 = time.perf_counter()
    try:
        headers = {"Content-Type": "application/json",
                   "X-AUTH-APIKEY": key,
                   "X-AUTH-SIGNATURE": sign("GET", decoded, secret, epoch),
                   "X-AUTH-EPOCH": epoch,
                   "User-Agent": UA}
    except Exception as e:
        return None, None, 0.0, f"signing failed: {type(e).__name__}: {e}"
    try:
        req = urllib.request.Request(host + decoded, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read(20_000_000).decode("utf-8", "replace")
            ms = (time.perf_counter() - t0) * 1000
            try:
                return r.status, json.loads(raw), ms, None
            except ValueError:
                return r.status, raw[:400], ms, None
    except urllib.error.HTTPError as e:
        ms = (time.perf_counter() - t0) * 1000
        try:
            return e.code, json.loads(e.read(8000).decode("utf-8", "replace")), ms, None
        except Exception:
            return e.code, None, ms, None
    except Exception as e:
        return None, None, (time.perf_counter() - t0) * 1000, f"{type(e).__name__}: {e}"


def _load_ours() -> set[str]:
    ours = set()
    for p in OUR_TRADES:
        if p.exists():
            with p.open() as fh:
                for rec in csv.DictReader(fh):
                    ours.add(rec["sym"].upper())
    return ours


def _norm(sym: str) -> str:
    """Binance XUSDT -> CoinSwitch X (CoinSwitch futures symbols are already BASEQUOTE)."""
    return sym.upper()


# ------------------------------------------------------------------ main
def run(key: str = "", secret: str = "") -> dict:
    rep: dict = {"ran_at": datetime.now(timezone.utc).isoformat(),
                 "base_url": BASE_Q, "steps": []}

    def step(name, ok, detail="", **extra):
        row = {"step": name, "ok": bool(ok), "detail": detail}
        row.update(extra)
        rep["steps"].append(row)
        return row

    if not key or not secret:
        step("credentials", False, "no COINSWITCH_API_KEY / COINSWITCH_SECRET_KEY set — "
                                   "every market-data endpoint needs one (verified: 401 without)")
        rep["verdict"] = "no_credentials"
        return rep

    # ---- 0. clock (public endpoint, tells us whether our epoch is sane) ----
    try:
        with urllib.request.urlopen(BASE_Q + "/trade/api/v2/time", timeout=15) as r:
            srv = json.loads(r.read(200).decode()).get("serverTime")
        drift = int(time.time() * 1000) - int(srv) if srv else None
        step("server_time", True, f"serverTime={srv} drift={drift} ms (reject >60000 ms)")
    except Exception as e:
        step("server_time", False, f"{type(e).__name__}: {e}")

    # ---- 1. INSTRUMENT RULES ----
    st, info, ms, err = auth_get(f"{FUTURES}/instrument_info",
                                {"exchange": "EXCHANGE_2"}, key, secret)
    inst = {}
    if st == 200 and isinstance(info, dict):
        data = info.get("data", info)
        inst = data.get("EXCHANGE_2", data) if isinstance(data, dict) else {}
        step("instrument_info", True, f"{len(inst)} instruments in {ms:.0f} ms")
    else:
        step("instrument_info", False, f"HTTP {st} {json.dumps(info)[:200] if info else err}")

    # ---- 2. ALL-PAIRS TICKER = the count + the liquidity picture ----
    st, tick, ms, err = auth_get(f"{FUTURES}/all-pairs/ticker",
                                 {"exchange": "EXCHANGE_2"}, key, secret)
    pairs: dict = {}
    if st == 200 and isinstance(tick, dict):
        d = tick.get("data", tick)
        pairs = d if isinstance(d, dict) else {}
        step("all_pairs_ticker", True, f"{len(pairs)} pairs returned in {ms:.0f} ms")
    else:
        step("all_pairs_ticker", False, f"HTTP {st} {json.dumps(tick)[:200] if tick else err}")

    # ---- 3. HFT instruments (may need a separate provisioning step) ----
    st_h, hft, ms_h, err_h = auth_get("/v5/market/instruments-info", {"category": "linear"},
                                      key, secret, host=HFT_HOST)
    hft_n = None
    if st_h == 200 and isinstance(hft, dict):
        res = hft.get("result", {})
        lst = res.get("list", res if isinstance(res, list) else [])
        hft_n = len(lst)
        step("hft_instruments", True, f"{hft_n} HFT instruments in {ms_h:.0f} ms")
    else:
        step("hft_instruments", False,
             f"HTTP {st_h} — expected 401 until an HFT Transfer Funds call provisions the account")

    # ---- 4. COUNT + LIQUIDITY RANKING ----
    rows = []
    for sym, t in pairs.items():
        try:
            qv = float(t.get("quote_asset_volume_24h") or 0)
        except (TypeError, ValueError):
            qv = 0.0
        rows.append({
            "symbol": sym,
            "last_price": t.get("last_price"),
            "quote_vol_24h": qv,
            "best_bid": t.get("best_bid_price"),
            "best_ask": t.get("best_ask_price"),
            "spread_bps": _spread_bps(t.get("best_bid_price"), t.get("best_ask_price")),
            "open_interest": t.get("open_interest"),
            "funding_rate": t.get("funding_rate"),
        })
    rows.sort(key=lambda r: -r["quote_vol_24h"])

    # ---- 5. COVERAGE vs OUR universe ----
    ours = _load_ours()
    present = sorted(ours & set(pairs))
    missing = sorted(ours - set(pairs))
    cov = {"our_symbols": len(ours), "present": len(present),
           "coverage_pct": round(100 * len(present) / len(ours), 1) if ours else None,
           "missing_count": len(missing)}
    by_sym = {r["symbol"]: r for r in rows}
    our_liquidity = [dict(sym=s, **{k: by_sym[s][k] for k in
                                    ("quote_vol_24h", "spread_bps", "open_interest")})
                     for s in present if s in by_sym]
    our_liquidity.sort(key=lambda r: -r["quote_vol_24h"])

    spreads = [r["spread_bps"] for r in rows if r["spread_bps"] is not None]
    vol = [r["quote_vol_24h"] for r in rows if r["quote_vol_24h"] > 0]

    rep.update({
        "count_perpetual_pairs": len(pairs),
        "count_instruments": len(inst),
        "count_hft_instruments": hft_n,
        "coverage_vs_our_universe": cov,
        "liquidity": {
            "median_spread_bps_all_pairs": round(statistics.median(spreads), 2) if spreads else None,
            "median_quote_vol_24h_usd": round(statistics.median(vol), 0) if vol else None,
            "top20_by_volume": rows[:20],
            "bottom10_by_volume": rows[-10:],
            "our_symbols_ranked": our_liquidity[:30],
        },
        "missing_examples": missing[:40],
        "verdict": "OK" if pairs else "failed",
    })

    # ---- 6. persist ----
    try:
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        if rows:
            with (OUT_DIR / "coinswitch_pairs.csv").open("w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
                w.writeheader()
                w.writerows(rows)
        (OUT_DIR / "coinswitch_report.json").write_text(json.dumps(rep, indent=1))
    except Exception as e:
        rep["persist_error"] = str(e)
    return rep


def _spread_bps(bid, ask):
    try:
        b, a = float(bid), float(ask)
        if b > 0 and a > 0:
            return round((a - b) / ((a + b) / 2) * 10_000, 2)
    except (TypeError, ValueError):
        pass
    return None


def safe_run(**kw) -> dict:
    import traceback
    try:
        return run(**kw)
    except Exception:
        return {"verdict": "CRASHED", "traceback": traceback.format_exc()[-1200:]}


if __name__ == "__main__":
    k = os.environ.get("COINSWITCH_API_KEY", "").strip()
    s = os.environ.get("COINSWITCH_SECRET_KEY", "").strip()
    out = safe_run(key=k, secret=s)
    print(json.dumps({kk: vv for kk, vv in out.items() if kk != "liquidity"}, indent=1))
    liq = out.get("liquidity") or {}
    if liq.get("top20_by_volume"):
        print("\ntop 15 futures pairs by 24h quote volume:")
        for r in liq["top20_by_volume"][:15]:
            print(f"  {r['symbol']:16s} vol=${r['quote_vol_24h']:>15,.0f}  spread={r['spread_bps']} bps")
    cov = out.get("coverage_vs_our_universe")
    if cov:
        print(f"\ncoverage of our universe: {cov['present']}/{cov['our_symbols']} "
              f"({cov['coverage_pct']}%)")
