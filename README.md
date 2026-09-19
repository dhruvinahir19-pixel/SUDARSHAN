# SUDARSHAN — Render free-tier connectivity probe

**Purpose:** find out whether a Render free Docker service can actually reach Binance —
and stay alive doing it — *before* we write a single line of trading logic.

This is deliberately a dumb script that mimics the real thing (public call → signed call →
fetch klines → compute ATR/swings), records what happens, and reports it on a phone-friendly page.

---

## 1. What we already know — and why your instinct was right

I ran this probe intentionally from a **US datacenter** to reproduce your original problem. Here is
what Binance answered, verbatim:

```
HTTP 451
{"code":0,"msg":"Service unavailable from a restricted location according to
 'b. Eligibility' in https://www.binance.com/en/terms. Please contact us..."}
```

That is not a rate-limit ban. That is a **geo-block**, and it is triggered by *where the request
comes from*, not by how many requests you send. **Render's default region is Oregon (US West).**
Deploying there without changing the region means you get 451 forever, on every request, no matter
how clean your code is — which matches "IP banned every minute" exactly.

So the variable under test is **the region**, and you picked the right one to be curious about.

| Render region | Binance's likely verdict | Evidence |
|---|---|---|
| Oregon / Ohio / Virginia (US) | ❌ **451** | **Proven — reproduced above, and by GitHub Actions (Azure-US) runners** |
| Frankfurt (Germany) | ⚠️ risky | EU moved to the MiCA "Binance Futures Credits (BNFCR)" system; several sources list futures as blocked for EU |
| **Singapore** | ❓ **unknown — worth testing** | Sources *conflict*. MAS put Binance on the Investor Alert List (not a ban) and Binance runs a spot-only local entity; yet a first-hand SG user reports futures and options working fine. **Nobody can settle this from documents. The probe settles it in 24 h.** |

---

## 2. The plan: deploy the same probe in THREE regions at once

This is the whole trick, and it costs nothing:

- Free tier gives **750 instance-hours per workspace per month**, counted across *all* free services.
- Three services running for 48 hours = **144 hours. Well within budget.**
- You get a side-by-side answer instead of a guess.

| Service | Region | What it tells us |
|---|---|---|
| `sudarshan-probe-sg` | **Singapore** | The real candidate |
| `sudarshan-probe-fra` | Frankfurt | Is the EU also viable? (MiCA question) |
| `sudarshan-probe-us` | Oregon | Control group — should show 451, proving the mechanism |

Run them for **48–72 hours**, then compare the `/status` pages.

---

## 3. Deploy (≈10 minutes, no card, GitHub account only)

### 3.1 Put these files in a GitHub repo
Files: `app.py`, `Dockerfile`, `requirements.txt`, `render.yaml`, `README.md`.
Public repo is fine — **the app contains no secrets** (keys come from environment variables).

### 3.2 Create the services
**Option A — Blueprint (fastest):** Render dashboard → **New +** → **Blueprint** → pick the repo.
`render.yaml` pins `region: singapore`, `plan: free`, `runtime: docker`.

**Option B — manual:** **New +** → **Web Service** → pick repo → Language: **Docker** →
Instance Type: **Free** → **Region: Singapore (Southeast Asia)** → Health Check Path: `/health`.

> ⚠️ **The single most important click in this whole exercise is the Region dropdown.** Do not leave
> it on the default.

For the other two regions, repeat with a different name and region.

### 3.3 Add your Binance key (optional but do it)
Service → **Environment** → add:

| Key | Value |
|---|---|
| `BINANCE_API_KEY` | your **Ed25519 public key**, hex |
| `BINANCE_SECRET` | your **Ed25519 private key**, hex |
| `KEY_TYPE` | `ed25519` (or `hmac` if you use a classic key) |
| `HEARTBEAT_URL` | *(optional)* a healthchecks.io ping URL |

Without keys it still tests public connectivity — useful for a quick first look.
**Never** paste keys into the repo or into a chat.

### 3.4 Keep it awake
Render sleeps a free web service after **15 minutes without inbound traffic**. Point a free
UptimeRobot monitor at `https://<your-service>.onrender.com/health` every **5 minutes**.
This is also a test in its own right: if the service still shows interruptions, then keep-alive
doesn't fully work — which is critical to know *before* trusting it with exits.

### 3.5 Read the results
Open `https://<your-service>.onrender.com/` on your phone. Better: `/status` for JSON.

---

## 4. How to read the numbers

| Signal | Meaning |
|---|---|
| `futures_ping: 200` | **The win condition.** Binance futures reachable from this region. |
| `451` | Geo-block. This region is dead for us. Move on. |
| `403` / `418` | IP-level block/ban — the shared-Render-IP hazard. Region won't save you. |
| `429` | Rate limit hit. Informational: our real usage is far lower. |
| `signed_account: 200` | **Second win condition.** Authenticated trading path works from a shared datacenter IP with **no whitelist**. |
| `-2015` in body | Key lacks Futures/Reading permission — fix in Binance key settings, not a network problem. |
| `region_proven` | The physical location we're *actually* running in. If this doesn't say Singapore, the region dropdown lied. |
| `distinct_egress_ips` | If this grows, the IP is not stable → **whitelisting is impossible forever** (not a problem for us: we use a self-generated Ed25519 key precisely to avoid whitelisting). |
| `uptime_pct_estimate` / `interruption_count` | Whether the free tier is genuinely 24/7 under keep-alive. This is the number that decides if we can run the engine here. |
| `compute_ms_total` | How long our real indicator work takes on a 0.1-CPU instance. |

### Decision table

| Result | Verdict |
|---|---|
| SG `200` + signed `200` + uptime ~100 % over 72 h | **Render becomes a viable Layer-1 host.** We still keep the device as failover. |
| SG `200` but uptime < 99 % | Usable only *because* exits live on Binance (native trailing stop). Entries get missed; exits don't. |
| SG `451` | Render is finished as an execution host. Fall back to R2: your own device. |
| Service silently disappears from the dashboard | See §5 — you hit the suspension clause. |

---

## 5. The hard truths (read before you fall in love with Render)

These are from Render's **own documentation**, not forum rumour:

1. **"Service-initiated traffic threshold."** Render may **suspend** a free web service that
   "initiates an uncommonly high volume of traffic over the public internet", and explicitly names
   *"invoking external APIs"* as the example. Restoration is only possible by **moving to a paid
   plan**. There is a widely-shared case of exactly this: an app permanently suspended for
   "service-initiated traffic", with Render's support conceding the rule was undocumented.
   **A trading bot that polls an exchange API is that exact workload.** This is the one risk I
   cannot engineer around — only stay under the radar of (which is why the probe defaults to one
   round every 5 minutes, and why the real design should lean on WebSockets instead of REST polling).
2. **750 instance-hours/month = exactly one always-on service.** One service running 24/7 uses
   ~720–744 h. A second always-on service pushes you over, and exceeding the cap **suspends all
   free web services** until the next month. (Three probes for 48 h = 144 h, which is why the test
   is affordable.)
3. **Free tier = web services only.** No free background workers, no free cron jobs. This is why
   the probe is a *web service* — and why the real engine, if it ever runs here, must also be
   shaped as a web service that happens to do background work.
4. **No persistent disk.** Every restart or spin-down **wipes the filesystem**. No SQLite, no local
   state. Position state must live on Binance and/or Neon. (And the free Render Postgres **expires
   after 30 days** — then it's deleted after a 14-day grace period.)
5. **No SSH, no shell.** You debug through logs and HTTP endpoints only. The probe gives you that.
6. **0.1 CPU / 512 MB RAM.** Our workload is tiny, but this is genuinely small.
7. **Render may restart a free service at any time.**
8. **Compliance, stated plainly:** your Binance account is KYC'd to **India**, and it stays an
   Indian account regardless of where the requests originate. Pointing it at a **Singapore**
   datacenter is not a VPN, but it *is* routing around the venue's location logic — the same
   category of risk we flagged for P2P funding. It may work indefinitely; it could also invite a
   compliance review. I'm telling you so you can weigh it, not to scare you. The clean version of
   this architecture is the one where the egress is genuinely in India — **your own device (R2
   Layer 1)** — and this probe is how we find out whether we even need to consider the alternative.

---

## 6. What this probe does NOT prove

- It does not prove Render will still be alive in month 3 (§5.1).
- It does not test **order placement** — deliberately. That stays on the R2 probe list, done
  manually with a minimum-size order.
- It does not replace the bar-vs-tick trail fidelity test on Binance Futures Demo.

---

## 7. Endpoint reference

| Path | Contents |
|---|---|
| `/` | Phone-friendly dashboard, auto-refreshes |
| `/status` | JSON summary: tallies, uptime, interruptions, egress, latest round |
| `/log` | Raw last 500 probe rounds |
| `/health` | `{"ok":true}` — use this as the UptimeRobot + Render health check target |

**Safety note:** there is no order-placement code path anywhere in `app.py`. The file cannot submit,
modify or cancel an order even if you wanted it to. Every call is a read.
