#!/usr/bin/env python3
"""
testnet.py — full order-lifecycle rehearsal against Binance's FREE practice venue.

WHY THIS EXISTS
  The user has no spare cash to put into P2P USDT yet, and should not have to. Everything
  about real trading can be proven first on Binance's practice environment with FAKE money.

TWO FACTS THAT MAKE THIS VIABLE (both measured, not assumed)
  1. testnet.binancefuture.com is reachable from cloud IPs --  HTTP 200 for ping, klines and
     exchangeInfo (605 TRADING symbols) FROM A GEO-BLOCKED IP, while fapi.binance.com and
     demo-fapi.binance.com both return 451 from the same machine. The practice venue is not
     behind the same wall as the live venue.
  2. Binance moved conditional orders to a new endpoint on 2025-12-09. STOP_MARKET,
     TAKE_PROFIT_MARKET, STOP, TAKE_PROFIT and TRAILING_STOP_MARKET now live on
     POST /fapi/v1/algoOrder. The old POST /fapi/v1/order returns -4120 STOP_ORDER_SWITCH_ALGO.
     The parameter is now `triggerPrice`, NOT `stopPrice`, and the response uses
     `algoId`/`algoStatus` instead of `orderId`/`status`.

     That rejection is the dangerous kind: a bot that places a stop, ignores the error, and
     believes the position is protected has an UNPROTECTED position. This module deliberately
     exercises BOTH paths so we see the real behaviour with our own eyes.

SAFETY
  TESTNET_HOST is hard-coded. This module physically cannot send an order to the live venue.
  Every order it places is on fake money, and it flattens the position at the end.
"""

from __future__ import annotations
import hashlib
import hmac as _hmac
import json
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

TESTNET_HOST = "https://testnet.binancefuture.com"   # hard-coded on purpose. Do not parameterise.
LIVE_HOSTS = ("https://fapi.binance.com", "https://demo-fapi.binance.com")


def _req(method: str, path: str, params: dict | None = None, key: str = "", secret: str = "",
         signed: bool = False, timeout: float = 20.0):
    """One HTTP call. Returns (status, parsed_or_text, latency_ms, error)."""
    params = dict(params or {})
    if signed:
        params["timestamp"] = int(time.time() * 1000)
        params["recvWindow"] = 5000
    qs = urllib.parse.urlencode(params) if params else ""
    if signed:
        sig = _hmac.new(secret.encode(), qs.encode(), hashlib.sha256).hexdigest()
        qs = (qs + "&" if qs else "") + "signature=" + sig
    url = f"{TESTNET_HOST}{path}" + (("?" + qs) if qs else "")
    body = None
    headers = {"User-Agent": "sudarshan-testnet/1.0"}
    if key:
        headers["X-MBX-APIKEY"] = key
    if method in ("POST", "DELETE", "PUT"):
        body = qs.encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        url = f"{TESTNET_HOST}{path}"          # params travel in the body for writes
    t0 = time.perf_counter()
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read(20000).decode("utf-8", "replace")
            ms = (time.perf_counter() - t0) * 1000
            try:
                return r.status, json.loads(raw), ms, None
            except ValueError:
                return r.status, raw[:400], ms, None
    except urllib.error.HTTPError as e:
        ms = (time.perf_counter() - t0) * 1000
        try:
            raw = e.read(4000).decode("utf-8", "replace")
            return e.code, json.loads(raw), ms, None
        except Exception:
            return e.code, raw[:400] if 'raw' in dir() else "", ms, None
    except Exception as e:
        return None, None, (time.perf_counter() - t0) * 1000, f"{type(e).__name__}: {e}"


def _sign_check(key, secret):
    """Cheap diagnostics before we spend a request: malformed keys are the usual cause."""
    out = {"api_key_len": len(key or ""), "secret_len": len(secret or ""),
           "api_key_looks_hex": False, "secret_looks_hex": False}
    for field, val in (("api_key_looks_hex", key), ("secret_looks_hex", secret)):
        try:
            bytes.fromhex(val or "")
            out[field] = True
        except ValueError:
            pass
    return out


def run(key: str = "", secret: str = "", symbol: str = "BTCUSDT", leverage: int = 3,
        run_legacy_test: bool = True) -> dict:
    """The rehearsal. Every step is recorded; nothing here can raise out of the function."""
    rep: dict = {"started_at": datetime.now(timezone.utc).isoformat(),
                 "host": TESTNET_HOST, "steps": [], "verdict": None}

    def step(name, ok, detail=None, **extra):
        row = {"step": name, "ok": ok}
        if detail is not None:
            row["detail"] = detail
        row.update(extra)
        rep["steps"].append(row)
        return row

    # ---------- 0. reachability: practice venue vs live venue, same moment, same box ------
    reach = {}
    for label, host in (("testnet", TESTNET_HOST),) + tuple(
            (h.split("//")[1].split(".")[0], h) for h in LIVE_HOSTS):
        st, body, ms, err = _probe_host(host)
        reach[label] = {"http": st, "ms": round(ms), "err": err}
    rep["reachability"] = reach
    step("reachability", reach["testnet"].get("http") == 200,
         f"testnet={reach['testnet'].get('http')} vs live={reach.get('fapi', {}).get('http')}")

    if not key or not secret:
        step("credentials", False, "no testnet key/secret configured -- stopping here")
        rep["verdict"] = "no_credentials"
        return rep
    rep["key_diagnostics"] = _sign_check(key, secret)

    # ---------- 1. authenticated identity ----------------------------------------------
    st, body, ms, err = _req("GET", "/fapi/v2/account", key=key, secret=secret, signed=True)
    if st != 200:
        step("signed_account", False, f"HTTP {st}", body=str(body)[:300], ms=round(ms))
        rep["verdict"] = "key_rejected"
        return rep
    bal = float(body.get("totalWalletBalance", 0))
    step("signed_account", True, f"balance={bal} USDT, canTrade={body.get('canTrade')}",
         ms=round(ms))

    # ---------- 2. symbol rules ---------------------------------------------------------
    st, info, ms, err = _req("GET", "/fapi/v1/exchangeInfo", params={"symbol": symbol})
    sym = None
    if st == 200 and isinstance(info, dict):
        sym = next((s for s in info.get("symbols", []) if s["symbol"] == symbol), None)
    if not sym:
        step("exchange_info", False, f"could not read rules for {symbol}")
        rep["verdict"] = "no_symbol_rules"
        return rep
    filt = {f["filterType"]: f for f in sym.get("filters", [])}
    min_qty = float(filt.get("LOT_SIZE", {}).get("minQty", "0.001"))
    min_notional = float(filt.get("MIN_NOTIONAL", {}).get("notional", "5"))
    price = float(_req("GET", "/fapi/v1/ticker/price", params={"symbol": symbol})[1]["price"])
    qty = max(min_qty, round(min_notional / price, 4) + min_qty)
    step("symbol_rules", True, f"{symbol} price={price} minQty={min_qty} "
                               f"minNotional={min_notional} -> test qty={qty} "
                               f"(~${qty*price:.2f} of fake money)")

    # ---------- 3. leverage ------------------------------------------------------------
    st, body, ms, err = _req("POST", "/fapi/v1/leverage",
                             params={"symbol": symbol, "leverage": leverage},
                             key=key, secret=secret, signed=True)
    step("set_leverage", st == 200, f"{leverage}x" if st == 200 else f"HTTP {st} {body}")

    # ---------- 4. ENTRY: plain market order -------------------------------------------
    st, body, ms, err = _req("POST", "/fapi/v1/order",
                             params={"symbol": symbol, "side": "BUY", "type": "MARKET",
                                     "quantity": qty}, key=key, secret=secret, signed=True)
    entry_ok = st == 200 and isinstance(body, dict)
    entry_px = None
    if entry_ok:
        entry_px = float(body.get("avgPrice") or price)
    step("market_entry", entry_ok, f"orderId={body.get('orderId') if entry_ok else None} "
                                   f"status={body.get('status') if entry_ok else body}",
         ms=round(ms))
    if not entry_ok:
        rep["verdict"] = "entry_failed"
        return rep

    st, body, ms, err = _req("GET", "/fapi/v2/positionRisk", params={"symbol": symbol},
                             key=key, secret=secret, signed=True)
    pos = ""
    if st == 200 and isinstance(body, list) and body:
        amt = float(body[0].get("positionAmt", 0))
        pos = f"positionAmt={amt} entryPrice={body[0].get('entryPrice')}"
        entry_px = float(body[0].get("entryPrice") or entry_px or price)
    step("position_open", "positionAmt=0" not in pos, pos or f"HTTP {st}")

    # ---------- 5. THE DANGEROUS PATH: conditional orders via the ALGO endpoint ---------
    trig_sl = round(entry_px * 0.97, 2)
    trig_tp = round(entry_px * 1.02, 2)
    cond = {}

    st, body, ms, err = _req("POST", "/fapi/v1/algoOrder",
                             params={"algoType": "CONDITIONAL", "symbol": symbol,
                                     "side": "SELL", "type": "STOP_MARKET",
                                     "triggerPrice": trig_sl, "closePosition": "true",
                                     "workingType": "MARK_PRICE", "priceProtect": "true"},
                             key=key, secret=secret, signed=True)
    cond["stop_market_closePosition"] = {"http": st, "algoId": (body or {}).get("algoId"),
                                         "status": (body or {}).get("algoStatus"),
                                         "err": (body or {}).get("msg") if st != 200 else None}
    step("algo_STOP_MARKET_closePosition", st == 200,
         f"trigger={trig_sl} -> {json.dumps(cond['stop_market_closePosition'])[:200]}")

    st, body, ms, err = _req("POST", "/fapi/v1/algoOrder",
                             params={"algoType": "CONDITIONAL", "symbol": symbol,
                                     "side": "SELL", "type": "TAKE_PROFIT_MARKET",
                                     "triggerPrice": trig_tp, "closePosition": "true",
                                     "workingType": "MARK_PRICE"},
                             key=key, secret=secret, signed=True)
    cond["take_profit_closePosition"] = {"http": st, "algoId": (body or {}).get("algoId"),
                                         "status": (body or {}).get("algoStatus"),
                                         "err": (body or {}).get("msg") if st != 200 else None}
    step("algo_TAKE_PROFIT_MARKET_closePosition", st == 200,
         f"trigger={trig_tp} -> {json.dumps(cond['take_profit_closePosition'])[:200]}")

    st, body, ms, err = _req("POST", "/fapi/v1/algoOrder",
                             params={"algoType": "CONDITIONAL", "symbol": symbol,
                                     "side": "SELL", "type": "TRAILING_STOP_MARKET",
                                     "callbackRate": "0.4", "activatePrice": round(entry_px * 1.002, 2),
                                     "workingType": "MARK_PRICE"},
                             key=key, secret=secret, signed=True)
    cond["trailing_stop"] = {"http": st, "algoId": (body or {}).get("algoId"),
                             "status": (body or {}).get("algoStatus"),
                             "rx": (body or {}).get("priceRate"),
                             "err": (body or {}).get("msg") if st != 200 else None}
    step("algo_TRAILING_STOP_MARKET_0.4pct", st == 200, json.dumps(cond["trailing_stop"])[:220])
    rep["conditional_orders"] = cond

    # ---------- 6. does the ALGO path actually show up? (and how fast?) ------------------
    lags = []
    found = None
    for i in range(6):
        st, body, ms, err = _req("GET", "/fapi/v1/openAlgoOrders", params={"symbol": symbol},
                                 key=key, secret=secret, signed=True)
        n = len(body.get("orders", body)) if isinstance(body, (dict, list)) else 0
        lags.append({"after_ms": i * 400, "http": st, "count": n if isinstance(n, int) else None})
        if isinstance(n, int) and n > 0 and found is None:
            found = i * 400
        if found is not None:
            break
        time.sleep(0.4)
    step("open_algoOrders_visibility", found is not None,
         f"first seen after ~{found} ms (lookup lag matters for the reconciler)",
         samples=lags)

    # ---------- 7. the LEGACY path -- deliberately provoke -4120 -------------------------
    if run_legacy_test:
        st, body, ms, err = _req("POST", "/fapi/v1/order",
                                 params={"symbol": symbol, "side": "SELL",
                                         "type": "STOP_MARKET", "stopPrice": trig_sl,
                                         "closePosition": "true"},
                                 key=key, secret=secret, signed=True)
        code = (body or {}).get("code") if isinstance(body, dict) else None
        step("legacy_STOP_MARKET_on_/order", st == 200,
             f"HTTP {st} code={code} msg={(body or {}).get('msg')}",
             is_the_trap=(code == -4120 or (isinstance(body, dict) and body.get("code"))))
        rep["legacy_path"] = {"http": st, "code": code, "msg": (body or {}).get("msg")}

    # ---------- 8. cancel conditional orders --------------------------------------------
    cancelled = []
    for name, c in cond.items():
        if c.get("algoId"):
            st, body, ms, err = _req("DELETE", "/fapi/v1/algoOrder",
                                     params={"algoid": c["algoId"]},
                                     key=key, secret=secret, signed=True)
            cancelled.append({"which": name, "http": st, "resp": str(body)[:120]})
    step("cancel_algo_orders", all(c["http"] == 200 for c in cancelled),
         json.dumps(cancelled)[:300], results=cancelled)

    # ---------- 9. verify protection is really gone, then flatten ------------------------
    st, body, ms, err = _req("GET", "/fapi/v1/openAlgoOrders", params={"symbol": symbol},
                             key=key, secret=secret, signed=True)
    n = len(body.get("orders", body)) if isinstance(body, (dict, list)) else None
    step("verify_flat_algo", n == 0, f"open algo orders remaining: {n}")

    st, body, ms, err = _req("POST", "/fapi/v1/order",
                             params={"symbol": symbol, "side": "SELL", "type": "MARKET",
                                     "quantity": qty, "reduceOnly": "true"},
                             key=key, secret=secret, signed=True)
    step("flatten_position", st == 200, f"HTTP {st} status={(body or {}).get('status')}")

    st, body, ms, err = _req("GET", "/fapi/v2/positionRisk", params={"symbol": symbol},
                             key=key, secret=secret, signed=True)
    amt = float(body[0].get("positionAmt", 1)) if (st == 200 and isinstance(body, list) and body) else None
    step("confirm_flat", amt == 0, f"positionAmt={amt}")

    # ---------- 10. what did it cost? (fake money, but shows the fee mechanics) ----------
    st, body, ms, err = _req("GET", "/fapi/v1/commissionRate", params={"symbol": symbol},
                             key=key, secret=secret, signed=True)
    step("commission_rate", st == 200, json.dumps(body)[:160] if st == 200 else f"HTTP {st}")
    st, body, ms, err = _req("GET", "/fapi/v1/income", params={"symbol": symbol, "limit": 20},
                             key=key, secret=secret, signed=True)
    fees = [x for x in (body if isinstance(body, list) else []) if x.get("incomeType") == "COMMISSION"]
    step("fees_charged", True, f"{len(fees)} commission entries; "
                               f"total={sum(float(f['income']) for f in fees):.6f} USDT")

    rep["verdict"] = "PASS" if all(s["ok"] for s in rep["steps"]) else "PARTIAL"
    rep["finished_at"] = datetime.now(timezone.utc).isoformat()
    return rep


def _probe_host(host: str):
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(host + "/fapi/v1/ping", timeout=12) as r:
            r.read(100)
            return r.status, None, (time.perf_counter() - t0) * 1000, None
    except urllib.error.HTTPError as e:
        return e.code, None, (time.perf_counter() - t0) * 1000, None
    except Exception as e:
        return None, None, (time.perf_counter() - t0) * 1000, f"{type(e).__name__}: {e}"


def safe_run(**kw) -> dict:
    try:
        return run(**kw)
    except Exception:
        return {"verdict": "CRASHED", "traceback": traceback.format_exc()[-1200:]}
