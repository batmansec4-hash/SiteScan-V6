import hashlib, hmac, json, os, re, secrets, smtplib, threading, time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

import dns.resolver
import requests
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from markupsafe import Markup
from starlette.middleware.sessions import SessionMiddleware

from . import db, report_pdf, scanner
from .db import ins, q

SECRET = os.environ.get("SECRET_KEY", "dev-only-change-me")
MAX_DOMAINS = int(os.environ.get("MAX_DOMAINS", "50"))
HOURLY_LIMIT = int(os.environ.get("HOURLY_LIMIT", "30"))
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
RESEND_API_KEY = os.environ.get("RESEND_API_KEY")  # optional: HTTP-based email, works where SMTP ports are blocked


def now():
    return datetime.now(timezone.utc)


def hash_pw(pw, salt=None):
    salt = salt or secrets.token_hex(16)
    return salt + "$" + hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 200_000).hex()


def check_pw(pw, stored):
    return hmac.compare_digest(hash_pw(pw, stored.split("$")[0]), stored)


def send_email(to, subject, body):
    """Sends via Resend's HTTPS API if RESEND_API_KEY is set (works even where outbound
    SMTP ports are blocked, e.g. Render's free tier), otherwise falls back to SMTP."""
    frm = os.environ.get("SMTP_FROM", "alerts@localhost")
    if RESEND_API_KEY:
        try:
            requests.post("https://api.resend.com/emails", timeout=10,
                          headers={"Authorization": f"Bearer {RESEND_API_KEY}"},
                          json={"from": frm, "to": [to], "subject": subject, "text": body})
        except requests.RequestException as e:
            print("resend error:", e)
        return
    host = os.environ.get("SMTP_HOST")
    if not host:
        print(f"[email -> {to}] {subject}\n{body}")
        return
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = frm, to, subject
    m.set_content(body)
    with smtplib.SMTP(host, int(os.environ.get("SMTP_PORT", "587"))) as s:
        s.starttls()
        if os.environ.get("SMTP_USER"):
            s.login(os.environ["SMTP_USER"], os.environ.get("SMTP_PASS", ""))
        s.send_message(m)


def execute_scan(scan_id, domain_id):
    d = q("select * from domains where id=?", (domain_id,), one=True)
    sc = q("select deep from scans where id=?", (scan_id,), one=True)
    try:
        res = scanner.run_scan(d["domain"], bool(sc["deep"]))
        prev = q("select result from scans where domain_id=? and status='done' and id<? order by id desc limit 1",
                 (domain_id, scan_id), one=True)
        q("update scans set status='done', score=?, result=? where id=?", (res["score"], json.dumps(res), scan_id))
    except Exception as e:
        q("update scans set status='error', result=? where id=?", (json.dumps({"error": str(e)}), scan_id))
        return
    if prev:  # change alert: new serious findings since last scan
        old = {f["id"] for f in json.loads(prev["result"]).get("findings", [])}
        new = [f for f in res["findings"] if f["severity"] in ("critical", "high") and f["id"] not in old]
        if new:
            u = q("select email from users where id=?", (d["user_id"],), one=True)
            send_email(u["email"], f"New security issues on {d['domain']}",
                       "\n".join(f"- {f['title']}: {f['plain']}" for f in new))


def run_due_rescans():
    """One pass: re-scan every domain whose last scan is 30+ days old (or never finished).
    Called either by the always-on thread (traditional hosts) or by an external cron hit
    (serverless hosts like Vercel, where nothing stays running between requests)."""
    cutoff = (now() - timedelta(days=30)).isoformat()
    n = 0
    for d in q("""select id from domains where exists(select 1 from scans where domain_id=domains.id) and
                  (select max(created_at) from scans where domain_id=domains.id) < ?""", (cutoff,)):
        last = q("select deep, authorized_at from scans where domain_id=? order by id desc limit 1", (d["id"],), one=True)
        sid = ins("insert into scans(domain_id,created_at,status,deep,authorized_at) values(?,?,'running',?,?)",
                  (d["id"], now().isoformat(), last["deep"], last["authorized_at"]))
        execute_scan(sid, d["id"])
        n += 1
    return n


def scheduler_thread():
    """Traditional always-on hosts only (Render, a VPS, local dev): checks hourly in the
    background. Never started on Vercel - see ON_VERCEL below - because a serverless
    function doesn't stay alive between requests, so a sleeping thread never fires there."""
    while os.environ.get("AUTO_RESCAN", "1") == "1":
        time.sleep(3600)
        try:
            run_due_rescans()
        except Exception as e:
            print("scheduler error:", e)


ON_VERCEL = bool(os.environ.get("VERCEL"))  # Vercel sets this automatically for every deployment


@asynccontextmanager
async def lifespan(app):
    db.init_schema()
    q("update scans set status='error' where status='running'")
    if not ON_VERCEL:
        threading.Thread(target=scheduler_thread, daemon=True).start()
    yield


app = FastAPI(lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=SECRET, same_site="lax",
                   https_only=os.environ.get("HTTPS_ONLY") == "1", max_age=14 * 86400)
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))


def user_of(request):
    uid = request.session.get("uid")
    return q("select * from users where id=?", (uid,), one=True) if uid else None


CATS = ["HTTPS & TLS", "Web security", "Email security", "DNS & domain", "Exposure", "Vulnerability scan", "CMS & discovery"]
SEVS = ["critical", "high", "medium", "low", "info"]


def score_color(sc):
    return "#2fa866" if sc >= 80 else "#d9a21b" if sc >= 65 else "#e0782b" if sc >= 50 else "#d9453b"


def gauge_svg(score, grade):
    c = 2 * 3.14159 * 54
    return Markup(f'<svg viewBox="0 0 140 140" width="150" height="150" role="img" aria-label="Score {score} out of 100">'
                  f'<circle cx="70" cy="70" r="54" fill="none" stroke-width="12" style="stroke:var(--line)"/>'
                  f'<circle cx="70" cy="70" r="54" fill="none" stroke="{score_color(score)}" stroke-width="12" stroke-linecap="round" '
                  f'stroke-dasharray="{c * score / 100:.1f} {c:.1f}" transform="rotate(-90 70 70)"/>'
                  f'<text x="70" y="74" text-anchor="middle" font-size="34" font-weight="700" fill="currentColor">{score}</text>'
                  f'<text x="70" y="96" text-anchor="middle" font-size="13" fill="currentColor" opacity=".7">Grade {grade}</text></svg>')


def spark(scores, w=90, h=26):
    v = [x for x in scores if x is not None]
    if len(v) < 2:
        return Markup('<span class="muted">-</span>')
    pts = " ".join(f"{i * (w - 4) / (len(v) - 1) + 2:.1f},{h - 3 - x / 100 * (h - 6):.1f}" for i, x in enumerate(v))
    return Markup(f'<svg width="{w}" height="{h}"><polyline points="{pts}" fill="none" stroke="{score_color(v[-1])}" stroke-width="2"/></svg>')


def trend_svg(points):
    pts = [(lab, v) for lab, v in points if v is not None]
    if len(pts) < 2:
        return Markup('<p class="muted">Run at least two scans to see a trend.</p>')
    W, H, L, B = 640, 200, 34, 26
    xs = lambda i: L + i * (W - L - 10) / (len(pts) - 1)
    ys = lambda v: 10 + (100 - v) / 100 * (H - B - 10)
    grid = "".join(f'<line x1="{L}" x2="{W - 10}" y1="{ys(g):.0f}" y2="{ys(g):.0f}" style="stroke:var(--line)"/>'
                   f'<text x="{L - 6}" y="{ys(g) + 4:.0f}" text-anchor="end" font-size="11" fill="currentColor" opacity=".6">{g}</text>' for g in (0, 50, 100))
    line = " ".join(f"{xs(i):.1f},{ys(v):.1f}" for i, (_, v) in enumerate(pts))
    dots = "".join(f'<circle cx="{xs(i):.1f}" cy="{ys(v):.1f}" r="4" fill="{score_color(v)}"><title>{lab}: {v}</title></circle>' for i, (lab, v) in enumerate(pts))
    labs = "".join(f'<text x="{xs(i):.1f}" y="{H - 6}" text-anchor="middle" font-size="11" fill="currentColor" opacity=".6">{pts[i][0]}</text>'
                   for i in sorted({0, len(pts) - 1}))
    return Markup(f'<svg viewBox="0 0 {W} {H}" width="100%" role="img" aria-label="Score trend">{grid}'
                  f'<polyline points="{line}" fill="none" stroke="var(--accent)" stroke-width="2"/>{dots}{labs}</svg>')


def summarize(rep):
    fs = rep.get("findings", [])
    counts = {k: sum(1 for f in fs if f["severity"] == k) for k in SEVS}
    run = rep.get("categories_run") or [c for c in CATS if c != "Exposure" or rep.get("active_checks_run")]
    cats = []
    for c in CATS:
        mine = [f for f in fs if f.get("category") == c]
        if c not in run:
            cats.append({"name": c, "score": None, "issues": 0})
        else:
            cats.append({"name": c, "score": max(0, 100 - sum(scanner.POINTS[f["severity"]] for f in mine)),
                         "issues": sum(1 for f in mine if f["severity"] != "info")})
    return {"counts": counts, "cats": cats}


def render(request, name, **ctx):
    u = user_of(request)
    side = []
    if u:
        for r in q("""select d.id, d.domain, (select score from scans s where s.domain_id=d.id and s.status='done'
                      order by s.id desc limit 1) score from domains d where user_id=? order by id""", (u["id"],)):
            side.append({**dict(r), "color": score_color(r["score"]) if r["score"] is not None else "var(--mut)"})
    return templates.TemplateResponse(request, name, {"user": u, "side_domains": side, "sc": score_color, **ctx})


def need_user(request):
    u = user_of(request)
    if not u:
        raise HTTPException(303, headers={"Location": "/login"})
    return u


def owned(request, did):
    u = need_user(request)
    d = q("select * from domains where id=? and user_id=?", (did, u["id"]), one=True)
    if not d:
        raise HTTPException(404)
    return u, d


def start_scan(u, did, deep, authorized):
    """Runs the scan synchronously and returns an error string, or None on success.
    Synchronous (not a background task) because a serverless function isn't guaranteed
    to keep running after it sends its HTTP response - this way it works the same on
    Vercel, Render, or a laptop, just taking a few extra seconds before the redirect."""
    if deep and not authorized:
        return "Confirm you are authorized to test this domain to run deep checks."
    last = q("select created_at from scans where domain_id=? order by id desc limit 1", (did,), one=True)
    if last and now() - datetime.fromisoformat(last["created_at"]) < timedelta(seconds=60):
        return "Please wait a minute between scans of the same domain."
    since = (now() - timedelta(hours=1)).isoformat()
    n = q("select count(*) c from scans s join domains d on d.id=s.domain_id where d.user_id=? and s.created_at>?", (u["id"], since), one=True)["c"]
    if n >= HOURLY_LIMIT:
        return "Hourly scan limit reached. Try again later."
    sid = ins("insert into scans(domain_id,created_at,status,deep,authorized_at) values(?,?,'running',?,?)",
              (did, now().isoformat(), int(deep), now().isoformat() if deep else None))
    execute_scan(sid, did)
    return None


@app.get("/healthz")
def healthz():
    """Plain, DB-free endpoint for an external uptime pinger to keep a free-tier instance awake."""
    return {"ok": True}


@app.get("/cron/rescan")
def cron_rescan(request: Request):
    """Vercel Cron hits this once a day (see vercel.json) since a sleeping background
    thread can't survive on serverless. Vercel signs the request with this header when
    CRON_SECRET is set in the project's environment variables - set it there to stop
    anyone else from triggering scans by hitting this URL directly."""
    secret = os.environ.get("CRON_SECRET")
    if secret and request.headers.get("authorization") != f"Bearer {secret}":
        raise HTTPException(401)
    return {"rescanned": run_due_rescans()}


@app.get("/")
def home(request: Request):
    if user_of(request):
        return RedirectResponse("/dashboard", 303)
    return render(request, "index.html")


@app.get("/signup")
def signup_page(request: Request):
    return render(request, "auth.html", mode="signup", error=None)


@app.post("/signup")
def signup(request: Request, email: str = Form(...), password: str = Form(...)):
    email = email.strip().lower()
    err = None
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        err = "Enter a valid email address."
    elif len(password) < 10:
        err = "Password must be at least 10 characters."
    elif q("select 1 from users where email=?", (email,), one=True):
        err = "That email is already registered."
    if err:
        return render(request, "auth.html", mode="signup", error=err)
    request.session["uid"] = ins("insert into users(email,pw,created_at) values(?,?,?)", (email, hash_pw(password), now().isoformat()))
    return RedirectResponse("/dashboard", 303)


@app.get("/login")
def login_page(request: Request):
    return render(request, "auth.html", mode="login", error=None)


@app.post("/login")
def login(request: Request, email: str = Form(...), password: str = Form(...)):
    u = q("select * from users where email=?", (email.strip().lower(),), one=True)
    if not u or not check_pw(password, u["pw"]):
        time.sleep(1)
        return render(request, "auth.html", mode="login", error="Wrong email or password.")
    request.session["uid"] = u["id"]
    return RedirectResponse("/dashboard", 303)


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/", 303)


@app.get("/dashboard")
def dashboard(request: Request, error: str = ""):
    u = need_user(request)
    items, scores, urgent = [], [], 0
    for d in q("select * from domains where user_id=? order by id", (u["id"],)):
        done = q("select created_at,score,result from scans where domain_id=? and status='done' order by id desc limit 10", (d["id"],))
        running = q("select 1 from scans where domain_id=? and status='running'", (d["id"],), one=True)
        last = done[0] if done else None
        counts = summarize(json.loads(last["result"]))["counts"] if last else None
        if last and last["score"] is not None:
            scores.append(last["score"])
        if counts:
            urgent += counts["critical"] + counts["high"]
        items.append({"id": d["id"], "domain": d["domain"], "score": last["score"] if last else None, "counts": counts, "running": bool(running),
                      "spark": spark([r["score"] for r in reversed(done)]), "last": last["created_at"][:16].replace("T", " ") if last else "never"})
    stats = {"domains": len(items), "avg": round(sum(scores) / len(scores)) if scores else None, "urgent": urgent}
    return render(request, "dashboard.html", items=items, stats=stats, error=error, active="dash")


@app.post("/scan")
def new_scan(request: Request, domain: str = Form(...), deep: str = Form(""), authorized: str = Form("")):
    u = need_user(request)
    dom = re.sub(r"^https?://", "", domain.strip().lower()).split("/")[0].split(":")[0]
    if not DOMAIN_RE.match(dom):
        return RedirectResponse("/dashboard?error=Enter+a+valid+domain+like+example.com", 303)
    row = q("select id from domains where user_id=? and domain=?", (u["id"], dom), one=True)
    if not row:
        if q("select count(*) c from domains where user_id=?", (u["id"],), one=True)["c"] >= MAX_DOMAINS:
            return RedirectResponse("/dashboard?error=Domain+limit+reached", 303)
        did = ins("insert into domains(user_id,domain,created_at) values(?,?,?)", (u["id"], dom, now().isoformat()))
    else:
        did = row["id"]
    err = start_scan(u, did, bool(deep), bool(authorized))
    return RedirectResponse(f"/domains/{did}" + (f"?msg={requests.utils.quote(err)}" if err else ""), 303)


@app.get("/domains/{did}")
def domain_page(request: Request, did: int, msg: str = ""):
    u, d = owned(request, did)
    scans = q("select id,created_at,status,score,deep from scans where domain_id=? order by id desc limit 20", (did,))
    latest = q("select id,created_at,result from scans where domain_id=? and status='done' order by id desc limit 1", (did,), one=True)
    rep = json.loads(latest["result"]) if latest else None
    pts = [(sc["created_at"][5:10], sc["score"]) for sc in reversed(scans) if sc["status"] == "done"]
    ok = bool(rep) and rep.get("score") is not None
    return render(request, "domain.html", d=d, scans=scans, msg=msg, report=rep, summ=summarize(rep) if rep else None, sevs=SEVS,
                  latest_id=latest["id"] if latest else None, running=any(sc["status"] == "running" for sc in scans),
                  failed=bool(scans) and scans[0]["status"] == "error", active_id=did, ok=ok,
                  gauge=gauge_svg(rep["score"], rep["grade"]) if ok else None, trend=trend_svg(pts))


@app.post("/domains/{did}/scan")
def rescan(request: Request, did: int, deep: str = Form(""), authorized: str = Form("")):
    u, d = owned(request, did)
    err = start_scan(u, did, bool(deep), bool(authorized))
    return RedirectResponse(f"/domains/{did}" + (f"?msg={requests.utils.quote(err)}" if err else ""), 303)


@app.post("/domains/{did}/delete")
def delete(request: Request, did: int):
    owned(request, did)
    q("delete from scans where domain_id=?", (did,))
    q("delete from domains where id=?", (did,))
    return RedirectResponse("/dashboard", 303)


def done_scan(request, sid):
    u = need_user(request)
    s = q("""select s.result, d.domain from scans s join domains d on d.id=s.domain_id
             where s.id=? and d.user_id=? and s.status='done'""", (sid, u["id"]), one=True)
    if not s:
        raise HTTPException(404)
    return s["domain"], json.loads(s["result"])


@app.get("/reports/{sid}/pdf")
def report_pdf_route(request: Request, sid: int):
    domain, rep = done_scan(request, sid)
    data = report_pdf.build_pdf(rep, summarize(rep))
    return Response(data, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="{domain}-security-report.pdf"'})


@app.get("/reports/{sid}/json")
def report_json_route(request: Request, sid: int):
    domain, rep = done_scan(request, sid)
    return Response(json.dumps(rep, indent=2), media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="{domain}-security-report.json"'})
