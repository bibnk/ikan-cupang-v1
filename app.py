# app.py
# Flask web app for IMAP Email Checker + Get Email + Access Code Login

import os
import uuid
import shutil
import threading
from datetime import datetime, timedelta
import time
import json
import hashlib
from functools import wraps
from flask import Flask, render_template, request, jsonify, Response, send_file, session, redirect, url_for

from imap_engine import (
    ImapChecker,
    parse_accounts,
    parse_senders,
    parse_proxies,
    _load_skip_domains,
    _save_skip_domains,
    _validate_skip_entries,
    _load_subject_exclusion_list,
    _save_subject_exclusion_list,
    _validate_exclusion_entries,
)
from filelock import Timeout
from get_email_engine import fetch_emails, delete_email, list_folders, list_folder_emails, get_single_email
from loop_delete_engine import LoopDeleteJob

app = Flask(__name__)


@app.context_processor
def _inject_base():
    # Under DispatcherMiddleware the tool is mounted at a secret prefix.
    # request.script_root == that prefix ("" when run standalone), so all
    # front-end fetch() calls can be made prefix-aware via window.APP_BASE.
    from flask import request
    return {"app_base": request.script_root or ""}

# Production: persist secret key so sessions survive restarts
_key_file = os.path.join(os.path.dirname(__file__), '.secret_key')
if os.path.exists(_key_file):
    with open(_key_file, 'r') as f:
        app.secret_key = f.read().strip()
else:
    app.secret_key = os.urandom(32).hex()
    with open(_key_file, 'w') as f:
        f.write(app.secret_key)

# ---- Access Code System ----
CODES_FILE = os.path.join(os.path.dirname(__file__), "access_codes.json")


def hash_code(code):
    return hashlib.sha256(code.encode()).hexdigest()


def load_codes():
    if os.path.exists(CODES_FILE):
        try:
            with open(CODES_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    # Default: "sbb"
    default = [{"code_hash": hash_code("sbb"), "label": "default"}]
    save_codes(default)
    return default


def save_codes(codes):
    with open(CODES_FILE, 'w') as f:
        json.dump(codes, f, indent=2)


def verify_code(code):
    codes = load_codes()
    h = hash_code(code)
    for c in codes:
        if c["code_hash"] == h:
            return c  # Return the full code entry (hash + label)
    return None


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("authenticated"):
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"error": "Unauthorized"}), 401
            target_url = request.full_path if request.query_string else request.path
            return redirect(url_for("login_page", next=target_url))
        return f(*args, **kwargs)
    return decorated


# ---- Store active jobs ----
jobs = {}  # {job_id: {"checker": ImapChecker, "created_at": datetime, "expires_at": datetime, "meta": {...}}}
JOBS_DIR = os.path.join(os.path.dirname(__file__), "jobs")
os.makedirs(JOBS_DIR, exist_ok=True)
DEFAULT_EXPIRY_DAYS = 3
EXTEND_DAYS = 7

DEFAULT_SENDERS_TEXT = """noreply@booking.com
rewards@booking.com
email.campaign@sg.booking.com
@account.agoda.com
@agoda.com"""
DEFAULT_SENDERS = [s.strip() for s in DEFAULT_SENDERS_TEXT.splitlines() if s.strip()]


def cleanup_expired_jobs():
    """Remove jobs older than their expiry time."""
    now = datetime.now()
    expired = [jid for jid, jdata in jobs.items() if now > jdata["expires_at"]]
    for jid in expired:
        jdata = jobs.pop(jid)
        checker = jdata.get("checker")
        if checker and hasattr(checker, 'stop'):
            try:
                checker.stop()
            except Exception:
                pass
        # clean up files
        job_dir = os.path.join(JOBS_DIR, jid)
        if os.path.isdir(job_dir):
            shutil.rmtree(job_dir, ignore_errors=True)


def save_job_meta(job_id, jdata):
    """Persist job metadata to disk for crash recovery and history."""
    try:
        job_dir = os.path.join(JOBS_DIR, job_id)
        os.makedirs(job_dir, exist_ok=True)
        meta_file = os.path.join(job_dir, "meta.json")
        data = {
            "job_id": job_id,
            "created_at": jdata["created_at"].strftime("%Y-%m-%d %H:%M:%S") if isinstance(jdata.get("created_at"), datetime) else str(jdata.get("created_at")),
            "expires_at": jdata["expires_at"].strftime("%Y-%m-%d %H:%M:%S") if isinstance(jdata.get("expires_at"), datetime) else str(jdata.get("expires_at")),
            "owner": jdata.get("owner", ""),
            "owner_label": jdata.get("owner_label", "unknown"),
            "meta": jdata.get("meta", {}),
        }
        with open(meta_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


# ---- Login ----

@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "POST":
        code = request.form.get("code", "").strip()
        code_entry = verify_code(code)
        if code_entry:
            session["authenticated"] = True
            session["is_admin"] = (code == "sbb")
            session["code_hash"] = code_entry["code_hash"]
            session["user_label"] = code_entry.get("label", "unknown")
            next_url = request.args.get("next") or request.form.get("next")
            if next_url and next_url.startswith("/") and not next_url.startswith("//"):
                return redirect(next_url)
            return redirect(url_for("index"))
        return render_template("login.html", error="Kode akses salah!")
    return render_template("login.html", error=None)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


# ---- Pages ----

@app.route("/")
@login_required
def index():
    return render_template("index.html", is_admin=session.get("is_admin", False))


@app.route("/get-email")
@login_required
def get_email_page():
    return render_template("get_email.html", is_admin=session.get("is_admin", False))


@app.route("/admin")
@login_required
def admin_page():
    if not session.get("is_admin"):
        return redirect(url_for("index"))
    codes = load_codes()
    return render_template("admin.html", codes=codes, is_admin=True)


@app.route("/api/admin/add-code", methods=["POST"])
@login_required
def add_code():
    if not session.get("is_admin"):
        return jsonify({"error": "Admin only"}), 403
    data = request.get_json()
    new_code = data.get("code", "").strip()
    label = data.get("label", "").strip() or "custom"
    if not new_code:
        return jsonify({"error": "Kode tidak boleh kosong"}), 400
    if len(new_code) < 3:
        return jsonify({"error": "Kode minimal 3 karakter"}), 400

    codes = load_codes()
    h = hash_code(new_code)
    if any(c["code_hash"] == h for c in codes):
        return jsonify({"error": "Kode sudah ada"}), 400

    codes.append({"code_hash": h, "label": label})
    save_codes(codes)
    return jsonify({"success": True, "message": f"Kode '{label}' berhasil ditambahkan"})


@app.route("/api/admin/delete-code", methods=["POST"])
@login_required
def delete_code():
    if not session.get("is_admin"):
        return jsonify({"error": "Admin only"}), 403
    data = request.get_json()
    idx = data.get("index", -1)
    codes = load_codes()
    if idx < 0 or idx >= len(codes):
        return jsonify({"error": "Index tidak valid"}), 400
    removed = codes.pop(idx)
    save_codes(codes)
    return jsonify({"success": True, "message": f"Kode '{removed.get('label', '')}' dihapus"})


@app.route("/api/admin/skip-domains", methods=["GET"])
@login_required
def get_skip_domains():
    if not session.get("is_admin"):
        return jsonify({"error": "Admin only"}), 403
    try:
        domains = _load_skip_domains()
    except Timeout:
        return jsonify({"error": "Skip-domains file is busy, please retry"}), 503
    return jsonify({"domains": domains}), 200


@app.route("/api/admin/skip-domains", methods=["POST"])
@login_required
def post_skip_domains():
    if not session.get("is_admin"):
        return jsonify({"error": "Admin only"}), 403

    # Requirement 8.4 + 9.6: structural validation BEFORE per-entry validation.
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid payload"}), 400
    domains_raw = data.get("domains")
    if not isinstance(domains_raw, list):
        return jsonify({"error": "Invalid payload"}), 400
    if not all(isinstance(x, str) for x in domains_raw):
        return jsonify({"error": "Invalid payload"}), 400

    # Requirement 9.1-9.5: per-entry validation, all-or-nothing short-circuit.
    valid, rejected = _validate_skip_entries(domains_raw)
    if rejected:
        return jsonify({"error": "Invalid entries", "rejected": rejected}), 400

    # Requirement 3.1, 8.2, 8.3: full-replace atomic write under FileLock.
    try:
        _save_skip_domains(valid)
    except Timeout:
        return jsonify({"error": "Skip-domains file is busy, please retry"}), 503

    return jsonify({"success": True, "domains": valid}), 200


@app.route("/api/admin/subject-exclusion-list", methods=["GET"])
@login_required
def get_subject_exclusion_list():
    if not session.get("is_admin"):
        return jsonify({"error": "Admin only"}), 403
    try:
        patterns = _load_subject_exclusion_list()
    except Timeout:
        return jsonify({"error": "Subject-exclusion list is busy, please retry"}), 503
    return jsonify({"patterns": patterns}), 200


@app.route("/api/admin/subject-exclusion-list", methods=["POST"])
@login_required
def post_subject_exclusion_list():
    if not session.get("is_admin"):
        return jsonify({"error": "Admin only"}), 403

    # Requirement 8.4 + 9.7: structural validation BEFORE per-entry validation.
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid payload"}), 400
    patterns_raw = data.get("patterns")
    if not isinstance(patterns_raw, list):
        return jsonify({"error": "Invalid payload"}), 400
    if not all(isinstance(x, str) for x in patterns_raw):
        return jsonify({"error": "Invalid payload"}), 400

    # Requirement 9.1-9.6: per-entry validation, all-or-nothing short-circuit.
    valid, rejected = _validate_exclusion_entries(patterns_raw)
    if rejected:
        return jsonify({"error": "Invalid entries", "rejected": rejected}), 400

    # Requirement 3.1, 8.2, 8.3: full-replace atomic write under FileLock.
    try:
        _save_subject_exclusion_list(valid)
    except Timeout:
        return jsonify({"error": "Subject-exclusion list is busy, please retry"}), 503

    return jsonify({"success": True, "patterns": valid}), 200


# ---- IMAP Checker API ----

@app.route("/api/check", methods=["POST"])
@login_required
def start_check():
    cleanup_expired_jobs()
    data = request.get_json()

    accounts_text = data.get("accounts", "").strip()
    senders_text = data.get("senders", "").strip()
    keywords_text = data.get("keywords", "").strip()
    proxies_text = data.get("proxies", "").strip()
    search_days = int(data.get("search_days", 365))
    max_threads = int(data.get("max_threads", 20))

    if not accounts_text:
        return jsonify({"error": "Accounts tidak boleh kosong"}), 400
    if not senders_text and not keywords_text:
        return jsonify({"error": "Isi minimal salah satu: Target Sender atau Keyword"}), 400

    # Count raw non-empty input lines BEFORE parsing for dedup-stats feedback.
    raw_input_lines = sum(
        1 for line in accounts_text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    )
    accounts = parse_accounts(accounts_text)
    duplicates_removed = max(0, raw_input_lines - len(accounts))

    senders = parse_senders(senders_text) if senders_text else []
    keywords = [k.strip() for k in keywords_text.splitlines() if k.strip()] if keywords_text else []
    proxy_list = parse_proxies(proxies_text) if proxies_text else []

    if not accounts:
        return jsonify({"error": "Tidak ditemukan akun valid. Format: email:password"}), 400

    max_threads = max(1, min(max_threads, 1000))
    search_days = max(1, min(search_days, 3650))

    if not senders and not keywords:
        senders = list(DEFAULT_SENDERS)

    job_id = str(uuid.uuid4())[:8]
    results_dir = os.path.join(JOBS_DIR, job_id)
    now = datetime.now()

    checker = ImapChecker(
        job_id=job_id,
        results_dir=results_dir,
        accounts=accounts,
        target_senders=senders,
        keywords=keywords,
        search_days=search_days,
        max_threads=max_threads,
        proxy_list=proxy_list,
    )

    meta = {
        "job_type": "check",
        "total_accounts": len(accounts),
        "total_senders": len(senders),
        "total_keywords": len(keywords),
        "total_proxies": len(proxy_list),
        "senders": senders,
        "keywords": keywords,
        "search_days": search_days,
        "max_threads": max_threads,
        "senders_text": senders_text[:100],
        "keywords_text": keywords_text[:100],
    }
    jdata = {
        "checker": checker,
        "created_at": now,
        "expires_at": now + timedelta(days=DEFAULT_EXPIRY_DAYS),
        "owner": session.get("code_hash", ""),
        "owner_label": session.get("user_label", "unknown"),
        "meta": meta,
    }
    jobs[job_id] = jdata
    save_job_meta(job_id, jdata)
    checker.run()

    return jsonify({
        "job_id": job_id,
        "total_accounts": len(accounts),
        "total_senders": len(senders),
        "total_keywords": len(keywords),
        "total_proxies": len(proxy_list),
        "duplicates_removed": duplicates_removed,
    })


@app.route("/api/stop/<job_id>", methods=["POST"])
@login_required
def stop_check(job_id):
    jdata = jobs.get(job_id)
    if not jdata:
        return jsonify({"error": "Job not found"}), 404
    jdata["checker"].stop()
    return jsonify({"message": "Stop signal sent", "job_id": job_id})


def parse_live_report(content):
    accounts = []
    current_acc = None
    for line in content.splitlines():
        line_s = line.strip()
        if line_s.startswith("[+] Account:"):
            cred = line_s.split("[+] Account:", 1)[1].strip()
            em, pw = cred.split(":", 1) if ":" in cred else (cred, "")
            current_acc = {
                "account": em,
                "password": pw,
                "email_count": 0,
                "emails": []
            }
            accounts.append(current_acc)
        elif current_acc and line_s.startswith("|") and not line_s.startswith("|--") and not line_s.startswith("| No."):
            parts = [p.strip() for p in line_s.split("|")[1:-1]]
            if len(parts) >= 4:
                current_acc["emails"].append({
                    "date": parts[1],
                    "from": parts[2],
                    "subject": parts[3]
                })
                current_acc["email_count"] = len(current_acc["emails"])
        elif line_s and ":" in line_s and not line_s.startswith("="):
            if not current_acc and "@" in line_s:
                em, pw = line_s.split(":", 1)
                accounts.append({
                    "account": em,
                    "password": pw,
                    "email_count": 0,
                    "emails": []
                })
    return accounts


@app.route("/api/status/<job_id>")
@login_required
def job_status(job_id):
    jdata = jobs.get(job_id)
    if not jdata and os.path.isdir(os.path.join(JOBS_DIR, job_id)):
        results_dir = os.path.join(JOBS_DIR, job_id)
        meta_path = os.path.join(results_dir, "meta.json")
        mdata = {}
        if os.path.exists(meta_path):
            try:
                mdata = json.load(open(meta_path, "r", encoding="utf-8"))
            except Exception:
                pass
        meta = mdata.get("meta", {})

        def _count_lines(fname):
            p = os.path.join(results_dir, fname)
            if os.path.exists(p):
                try:
                    with open(p, "rb") as f:
                        return sum(1 for _ in f)
                except Exception:
                    return 0
            return 0

        live_path = os.path.join(results_dir, "live.txt")
        live_accs = []
        if os.path.exists(live_path):
            try:
                with open(live_path, "r", encoding="utf-8", errors="replace") as f:
                    live_accs = parse_live_report(f.read())
            except Exception:
                pass

        live_c = len(live_accs)
        die_c = _count_lines("die.txt")
        noemail_c = _count_lines("noemail.txt")
        unreg_c = _count_lines("unreg_accounts.txt") or _count_lines("unreg.txt")
        skipped_c = _count_lines("domain_skipped.txt")
        total_acc = meta.get("total_accounts", live_c + die_c + noemail_c + unreg_c + skipped_c)
        checked = live_c + die_c + noemail_c + unreg_c + skipped_c
        pct = round((checked / total_acc * 100), 1) if total_acc > 0 else 100

        def generate_static():
            prog = {
                "status": "done",
                "job_id": job_id,
                "job_type": meta.get("job_type", "check"),
                "parent_job_id": meta.get("parent_job_id"),
                "percentage": min(100, pct),
                "checked": checked,
                "total": total_acc,
                "live": live_c,
                "die": die_c,
                "noemail": noemail_c,
                "unreg": unreg_c,
                "skipped": skipped_c,
                "live_accounts": live_accs,
            }
            yield f"data: {json.dumps(prog)}\n\n"
        return Response(generate_static(), mimetype="text/event-stream")
    elif not jdata:
        return jsonify({"error": "Job not found"}), 404
    checker = jdata["checker"]
    meta = jdata.get("meta", {})

    def generate():
        while True:
            progress = checker.get_progress()
            progress["job_id"] = job_id
            progress["job_type"] = meta.get("job_type", "check")
            progress["parent_job_id"] = meta.get("parent_job_id")
            yield f"data: {json.dumps(progress)}\n\n"
            if progress["status"] in ("done", "stopped"):
                break
            time.sleep(0.5)

    return Response(generate(), mimetype="text/event-stream")


@app.route("/api/download/<job_id>/<file_type>")
@login_required
def download_file(job_id, file_type):
    allowed = {
        "live": "live.txt",
        "noemail": "noemail.txt",
        "die": "die.txt",
        "unreg": "unreg.txt",
        "unreg_accounts": "unreg_accounts.txt",
        "domain_skipped": "domain_skipped.txt",
    }
    if file_type not in allowed:
        return jsonify({"error": "Invalid file type"}), 400

    filepath = os.path.abspath(os.path.join(JOBS_DIR, job_id, allowed[file_type]))
    if not os.path.exists(filepath):
        return jsonify({"error": "File belum tersedia atau kosong"}), 404

    return send_file(filepath, as_attachment=True,
                     download_name=f"{file_type}_{job_id}.txt", mimetype="text/plain")


@app.route("/api/resolve-unreg/<job_id>", methods=["POST"])
@login_required
def resolve_unreg_job(job_id):
    cleanup_expired_jobs()
    results_dir = os.path.join(JOBS_DIR, job_id)
    jdata = jobs.get(job_id)
    if not jdata and os.path.isdir(results_dir):
        # Fallback load dari disk jika service sempat restart
        jdata = {
            "owner": session.get("code_hash", ""),
            "owner_label": session.get("user_label", "unknown"),
            "checker": None,
        }
    elif not jdata:
        return jsonify({"error": "Job tidak ditemukan"}), 404

    user_hash = session.get("code_hash", "")
    if not session.get("is_admin") and jdata.get("owner") != user_hash:
        return jsonify({"error": "Unauthorized"}), 403
    unreg_acc_file = os.path.join(results_dir, "unreg_accounts.txt")
    unreg_dom_file = os.path.join(results_dir, "unreg.txt")

    accounts = []
    if os.path.exists(unreg_acc_file):
        with open(unreg_acc_file, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line and ":" in line:
                    em, pw = line.split(":", 1)
                    accounts.append({"email": em.strip(), "password": pw.strip()})

    # Fallback jika unreg_accounts.txt belum ada (misal job lama): filter checker.accounts berdasarkan unreg.txt
    if not accounts and os.path.exists(unreg_dom_file):
        unreg_doms = set(line.strip().lower() for line in open(unreg_dom_file, errors="replace") if line.strip())
        checker = jdata.get("checker")
        if checker and hasattr(checker, "accounts"):
            for acc in checker.accounts:
                dom = acc["email"].split("@")[-1].lower()
                if dom in unreg_doms:
                    accounts.append(acc)

    if not accounts:
        return jsonify({"error": "Tidak ada akun unreg yang ditemukan untuk job ini"}), 400

    # Kumpulkan domain unreg unik
    unique_domains = list(dict.fromkeys(a["email"].split("@")[-1].lower() for a in accounts if "@" in a["email"]))

    from concurrent.futures import ThreadPoolExecutor
    from imap_config import (
        query_mx, map_mx_to_imap, save_master_imap_configs, lookup_imap_config,
        save_master_unusable_domains, is_unusable_domain
    )

    new_configs = {}
    unusable_domains = set()

    def _resolve(dom):
        if is_unusable_domain(dom):
            return dom, None
        mx = query_mx(dom)
        if mx:
            cfg = map_mx_to_imap(mx, domain=dom)
            if cfg:
                return dom, cfg
        return dom, None

    with ThreadPoolExecutor(max_workers=min(30, max(1, len(unique_domains)))) as executor:
        for dom, cfg in executor.map(_resolve, unique_domains):
            if cfg:
                new_configs[dom] = cfg
            else:
                unusable_domains.add(dom)

    if new_configs:
        save_master_imap_configs(new_configs)
    if unusable_domains:
        save_master_unusable_domains(unusable_domains)

    # Filter akun: HANYA akun yang berhubungan dengan unreg dan domainnya berhasil di-resolve
    checking_accounts = [
        a for a in accounts
        if lookup_imap_config(a["email"].split("@")[-1].lower(), extra_configs=new_configs)
    ]

    if not checking_accounts:
        return jsonify({
            "success": False,
            "message": f"Dari {len(unique_domains)} domain unreg, tidak ada server IMAP yang berhasil di-resolve.",
            "total_unreg_accounts": len(accounts),
            "resolved_domains": len(new_configs),
            "checking_accounts": 0,
        })

    # Start new job dengan checking_accounts saja
    new_job_id = str(uuid.uuid4())[:8]
    new_results_dir = os.path.join(JOBS_DIR, new_job_id)
    now = datetime.now()

    parent_checker = jdata.get("checker")
    parent_meta = jdata.get("meta", {})
    target_senders = (
        getattr(parent_checker, "target_senders", None)
        or parent_meta.get("senders")
        or list(DEFAULT_SENDERS)
    )
    keywords = (
        getattr(parent_checker, "keywords", None)
        or parent_meta.get("keywords")
        or []
    )
    search_days = getattr(parent_checker, "search_days", parent_meta.get("search_days", 365))
    max_threads = getattr(parent_checker, "max_threads", parent_meta.get("max_threads", 20))
    proxy_list = getattr(parent_checker, "proxy_list", [])

    new_checker = ImapChecker(
        job_id=new_job_id,
        results_dir=new_results_dir,
        accounts=checking_accounts,
        target_senders=target_senders,
        keywords=keywords,
        search_days=search_days,
        max_threads=max_threads,
        proxy_list=proxy_list,
    )

    new_meta = {
        "job_type": "resolve_unreg",
        "parent_job_id": job_id,
        "resolved_domains": len(new_configs),
        "total_accounts": len(checking_accounts),
        "total_senders": len(target_senders),
        "total_keywords": len(keywords),
        "total_proxies": len(proxy_list),
        "senders": target_senders,
        "keywords": keywords,
        "search_days": search_days,
        "max_threads": max_threads,
        "senders_text": getattr(parent_checker, "senders_text", "")[:100],
        "keywords_text": getattr(parent_checker, "keywords_text", "")[:100],
    }
    new_jdata = {
        "checker": new_checker,
        "created_at": now,
        "expires_at": now + timedelta(days=DEFAULT_EXPIRY_DAYS),
        "owner": jdata.get("owner", session.get("code_hash", "")),
        "owner_label": jdata.get("owner_label", session.get("user_label", "unknown")),
        "meta": new_meta,
    }
    jobs[new_job_id] = new_jdata
    save_job_meta(new_job_id, new_jdata)
    new_checker.run()

    return jsonify({
        "success": True,
        "new_job_id": new_job_id,
        "resolved_domains": len(new_configs),
        "total_unreg_accounts": len(accounts),
        "checking_accounts": len(checking_accounts),
    })


@app.route("/api/resolve-unreg-bg/<job_id>", methods=["POST"])
@login_required
def resolve_unreg_bg(job_id):
    results_dir = os.path.join(JOBS_DIR, job_id)
    if not os.path.isdir(results_dir):
        return jsonify({"error": "Job tidak ditemukan"}), 404

    def _bg_task():
        unreg_dom_file = os.path.join(results_dir, "unreg.txt")
        if not os.path.exists(unreg_dom_file):
            return
        domains = [line.strip().lower() for line in open(unreg_dom_file, errors="replace") if line.strip()]
        if not domains:
            return

        from concurrent.futures import ThreadPoolExecutor
        from imap_config import (
            query_mx, map_mx_to_imap, save_master_imap_configs,
            save_master_unusable_domains, is_unusable_domain, lookup_imap_config
        )

        todo_domains = [d for d in dict.fromkeys(domains) if not lookup_imap_config(d) and not is_unusable_domain(d)]
        if not todo_domains:
            return

        new_configs = {}
        unusable_domains = set()

        def _resolve_one(dom):
            mx = query_mx(dom)
            if mx:
                cfg = map_mx_to_imap(mx, domain=dom)
                if cfg:
                    return dom, cfg
            return dom, None

        with ThreadPoolExecutor(max_workers=min(30, len(todo_domains))) as pool:
            for count, (dom, cfg) in enumerate(pool.map(_resolve_one, todo_domains), 1):
                if cfg:
                    new_configs[dom] = cfg
                else:
                    unusable_domains.add(dom)

                # Periodic flush every 50 domains
                if count % 50 == 0:
                    if new_configs:
                        save_master_imap_configs(new_configs)
                        new_configs.clear()
                    if unusable_domains:
                        save_master_unusable_domains(unusable_domains)
                        unusable_domains.clear()

        # Final flush
        if new_configs:
            save_master_imap_configs(new_configs)
        if unusable_domains:
            save_master_unusable_domains(unusable_domains)

    threading.Thread(target=_bg_task, daemon=True).start()
    return jsonify({"success": True, "message": "Background MX resolve started"})


# ---- Get Email API ----

@app.route("/api/get-email", methods=["POST"])
@login_required
def api_get_email():
    data = request.get_json()

    email_addr = data.get("email", "").strip()
    password = data.get("password", "").strip()
    senders_text = data.get("senders", "").strip()
    keywords_text = data.get("keywords", "").strip()
    search_days = int(data.get("search_days", 365))

    if not email_addr or not password:
        return jsonify({"success": False, "error": "Email dan password wajib diisi."}), 400
    # Default sender if both empty
    if not senders_text and not keywords_text:
        senders_text = "@booking.com"

    senders = [s.strip() for s in senders_text.splitlines() if s.strip()] if senders_text else []
    keywords = [k.strip() for k in keywords_text.splitlines() if k.strip()] if keywords_text else []

    result = fetch_emails(email_addr, password, senders, keywords, search_days)
    return jsonify(result)


@app.route("/api/delete-email", methods=["POST"])
@login_required
def api_delete_email():
    data = request.get_json()

    email_addr = data.get("email", "").strip()
    password = data.get("password", "").strip()
    uid = data.get("uid", "").strip()
    folder = data.get("folder", "INBOX").strip()

    if not email_addr or not password:
        return jsonify({"success": False, "error": "Email dan password wajib diisi."}), 400
    if not uid:
        return jsonify({"success": False, "error": "UID email tidak valid."}), 400

    result = delete_email(email_addr, password, uid, folder=folder)
    return jsonify(result)


# ---- Email Browser API ----

@app.route("/api/email-folders", methods=["POST"])
@login_required
def api_email_folders():
    data = request.get_json()
    email_addr = data.get("email", "").strip()
    password = data.get("password", "").strip()

    if not email_addr or not password:
        return jsonify({"success": False, "error": "Email dan password wajib diisi."}), 400

    result = list_folders(email_addr, password)
    return jsonify(result)


@app.route("/api/email-list", methods=["POST"])
@login_required
def api_email_list():
    data = request.get_json()
    email_addr = data.get("email", "").strip()
    password = data.get("password", "").strip()
    folder = data.get("folder", "INBOX").strip()
    page = int(data.get("page", 1))

    if not email_addr or not password:
        return jsonify({"success": False, "error": "Email dan password wajib diisi."}), 400

    result = list_folder_emails(email_addr, password, folder=folder, page=page)
    return jsonify(result)


@app.route("/api/email-view", methods=["POST"])
@login_required
def api_email_view():
    data = request.get_json()
    email_addr = data.get("email", "").strip()
    password = data.get("password", "").strip()
    folder = data.get("folder", "INBOX").strip()
    uid = data.get("uid", "").strip()

    if not email_addr or not password:
        return jsonify({"success": False, "error": "Email dan password wajib diisi."}), 400
    if not uid:
        return jsonify({"success": False, "error": "UID email tidak valid."}), 400

    result = get_single_email(email_addr, password, folder=folder, uid=uid)
    return jsonify(result)


# ---- History API ----

@app.route("/history")
@login_required
def history_page():
    return render_template("history.html", is_admin=session.get("is_admin", False))


@app.route("/api/jobs")
@login_required
def list_jobs():
    cleanup_expired_jobs()
    user_hash = session.get("code_hash", "")
    is_admin = session.get("is_admin", False)
    result = []
    seen = set()

    for jid, jdata in jobs.items():
        seen.add(jid)
        # Only show own jobs (admin sees all)
        if not is_admin and jdata.get("owner") != user_hash:
            continue
        checker = jdata.get("checker")
        progress = checker.get_progress() if (checker and hasattr(checker, "get_progress")) else {}
        meta = jdata.get("meta", {})
        created_at_val = jdata.get("created_at")
        expires_at_val = jdata.get("expires_at")
        c_str = created_at_val.strftime("%Y-%m-%d %H:%M:%S") if isinstance(created_at_val, datetime) else str(created_at_val or "")
        e_str = expires_at_val.strftime("%Y-%m-%d %H:%M:%S") if isinstance(expires_at_val, datetime) else str(expires_at_val or "")

        entry = {
            "job_id": jid,
            "job_type": meta.get("job_type", "check"),
            "parent_job_id": meta.get("parent_job_id"),
            "status": progress.get("status", "unknown"),
            "percentage": progress.get("percentage", 0),
            "checked": progress.get("checked", 0),
            "total": progress.get("total", meta.get("total_accounts", 0)),
            "live": progress.get("live", 0),
            "die": progress.get("die", 0),
            "noemail": progress.get("noemail", 0),
            "unreg": progress.get("unreg", 0),
            "skipped": progress.get("skipped", 0),
            "created_at": c_str,
            "expires_at": e_str,
            "meta": meta,
        }
        if is_admin:
            entry["owner_label"] = jdata.get("owner_label", "unknown")
        result.append(entry)

    # Disk scan for persisted jobs
    if os.path.isdir(JOBS_DIR):
        for jid in os.listdir(JOBS_DIR):
            if jid in seen:
                continue
            jdir = os.path.join(JOBS_DIR, jid)
            if not os.path.isdir(jdir):
                continue
            meta_path = os.path.join(jdir, "meta.json")
            mdata = {}
            if os.path.exists(meta_path):
                try:
                    with open(meta_path, "r", encoding="utf-8") as f:
                        mdata = json.load(f)
                except Exception:
                    pass
            if not is_admin and mdata.get("owner") and mdata.get("owner") != user_hash:
                continue

            def _lines(name):
                p = os.path.join(jdir, name)
                if os.path.exists(p):
                    try:
                        with open(p, "rb") as f:
                            return sum(1 for _ in f)
                    except Exception:
                        return 0
                return 0

            live_c = _lines("live.txt")
            die_c = _lines("die.txt")
            noemail_c = _lines("noemail.txt")
            unreg_c = _lines("unreg_accounts.txt") or _lines("unreg.txt")
            skipped_c = _lines("domain_skipped.txt")
            meta = mdata.get("meta", {})
            total_acc = meta.get("total_accounts", live_c + die_c + noemail_c + unreg_c + skipped_c)
            checked = live_c + die_c + noemail_c + unreg_c + skipped_c
            pct = round((checked / total_acc * 100), 1) if total_acc > 0 else 100

            try:
                c_time = datetime.fromtimestamp(os.path.getctime(jdir)).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                c_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            entry = {
                "job_id": jid,
                "job_type": meta.get("job_type", "check"),
                "parent_job_id": meta.get("parent_job_id"),
                "status": "done",
                "percentage": min(100, pct),
                "checked": checked,
                "total": total_acc,
                "live": live_c,
                "die": die_c,
                "noemail": noemail_c,
                "unreg": unreg_c,
                "skipped": skipped_c,
                "created_at": mdata.get("created_at", c_time),
                "expires_at": mdata.get("expires_at", c_time),
                "meta": meta,
            }
            if is_admin:
                entry["owner_label"] = mdata.get("owner_label", "unknown")
            result.append(entry)

    result.sort(key=lambda x: x["created_at"], reverse=True)
    return jsonify(result)


@app.route("/api/jobs/<job_id>/extend", methods=["POST"])
@login_required
def extend_job(job_id):
    jdata = jobs.get(job_id)
    job_dir = os.path.join(JOBS_DIR, job_id)
    user_hash = session.get("code_hash", "")
    is_admin = session.get("is_admin", False)

    if not jdata and os.path.isdir(job_dir):
        meta_file = os.path.join(job_dir, "meta.json")
        mdata = {}
        if os.path.exists(meta_file):
            try:
                mdata = json.load(open(meta_file, "r", encoding="utf-8"))
            except Exception:
                pass
        if not is_admin and mdata.get("owner") and mdata.get("owner") != user_hash:
            return jsonify({"error": "Unauthorized"}), 403

        exp_str = str(mdata.get("expires_at") or "")
        try:
            curr_exp = datetime.strptime(exp_str, "%Y-%m-%d %H:%M:%S")
        except Exception:
            curr_exp = datetime.now() + timedelta(days=DEFAULT_EXPIRY_DAYS)
        new_exp = curr_exp + timedelta(days=EXTEND_DAYS)
        mdata["expires_at"] = new_exp.strftime("%Y-%m-%d %H:%M:%S")
        try:
            with open(meta_file, "w", encoding="utf-8") as f:
                json.dump(mdata, f, indent=2)
        except Exception:
            pass
        return jsonify({
            "success": True,
            "message": f"Job diperpanjang {EXTEND_DAYS} hari",
            "expires_at": mdata["expires_at"],
        })

    if not jdata:
        return jsonify({"error": "Job not found"}), 404
    if not is_admin and jdata.get("owner") != user_hash:
        return jsonify({"error": "Unauthorized"}), 403
    jdata["expires_at"] = jdata["expires_at"] + timedelta(days=EXTEND_DAYS)
    save_job_meta(job_id, jdata)
    return jsonify({
        "success": True,
        "message": f"Job diperpanjang {EXTEND_DAYS} hari",
        "expires_at": jdata["expires_at"].strftime("%Y-%m-%d %H:%M:%S"),
    })


@app.route("/api/jobs/<job_id>/delete", methods=["POST"])
@login_required
def delete_job(job_id):
    jdata = jobs.get(job_id)
    job_dir = os.path.join(JOBS_DIR, job_id)
    user_hash = session.get("code_hash", "")
    is_admin = session.get("is_admin", False)

    if not jdata and not os.path.isdir(job_dir):
        return jsonify({"error": "Job not found"}), 404

    if not jdata and os.path.isdir(job_dir):
        meta_file = os.path.join(job_dir, "meta.json")
        if os.path.exists(meta_file):
            try:
                mdata = json.load(open(meta_file, "r", encoding="utf-8"))
                if not is_admin and mdata.get("owner") and mdata.get("owner") != user_hash:
                    return jsonify({"error": "Unauthorized"}), 403
            except Exception:
                pass
        shutil.rmtree(job_dir, ignore_errors=True)
        return jsonify({"success": True, "message": "Job dihapus"})

    if jdata:
        if not is_admin and jdata.get("owner") != user_hash:
            return jsonify({"error": "Unauthorized"}), 403

        jobs.pop(job_id, None)
        checker = jdata.get("checker")
        if checker and hasattr(checker, 'stop'):
            try:
                checker.stop()
            except Exception:
                pass
    if os.path.isdir(job_dir):
        shutil.rmtree(job_dir, ignore_errors=True)
    return jsonify({"success": True, "message": "Job dihapus"})


@app.route("/api/jobs/<job_id>/live")
@login_required
def job_live_list(job_id):
    jdata = jobs.get(job_id)
    job_dir = os.path.join(JOBS_DIR, job_id)
    user_hash = session.get("code_hash", "")
    is_admin = session.get("is_admin", False)

    if not jdata and not os.path.isdir(job_dir):
        return jsonify({"error": "Job not found"}), 404

    if not jdata and os.path.isdir(job_dir):
        meta_file = os.path.join(job_dir, "meta.json")
        if os.path.exists(meta_file):
            try:
                mdata = json.load(open(meta_file, "r", encoding="utf-8"))
                if not is_admin and mdata.get("owner") and mdata.get("owner") != user_hash:
                    return jsonify({"error": "Unauthorized"}), 403
            except Exception:
                pass
    elif jdata:
        if not is_admin and jdata.get("owner") != user_hash:
            return jsonify({"error": "Unauthorized"}), 403

    live_file = os.path.join(job_dir, "live.txt")
    accounts = []
    if os.path.exists(live_file):
        with open(live_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line:
                    accounts.append(line)
    return jsonify({"success": True, "accounts": accounts, "count": len(accounts)})


# ---- Loop Delete API ----

loop_delete_jobs = {}


@app.route("/loop-delete")
@login_required
def loop_delete_page():
    return render_template("loop_delete.html", is_admin=session.get("is_admin", False))


@app.route("/api/loop-delete/start", methods=["POST"])
@login_required
def start_loop_delete():
    data = request.get_json()

    email_addr = data.get("email", "").strip()
    password = data.get("password", "").strip()
    senders_text = data.get("senders", "").strip()
    keywords_text = data.get("keywords", "").strip()
    interval = int(data.get("interval", 5))

    if not email_addr or not password:
        return jsonify({"success": False, "error": "Email dan password wajib diisi."}), 400
    if not senders_text and not keywords_text:
        return jsonify({"success": False, "error": "Isi minimal salah satu: Sender atau Keyword."}), 400

    senders = [s.strip() for s in senders_text.splitlines() if s.strip()] if senders_text else []
    keywords = [k.strip() for k in keywords_text.splitlines() if k.strip()] if keywords_text else []

    job_id = str(uuid.uuid4())[:8]
    job = LoopDeleteJob(
        job_id=job_id,
        email_address=email_addr,
        password=password,
        senders=senders,
        keywords=keywords,
        interval=interval,
    )

    if not job.start():
        return jsonify({"success": False, "error": job.error or "Gagal memulai loop delete"}), 400

    loop_delete_jobs[job_id] = job
    return jsonify({"success": True, "job_id": job_id})


@app.route("/api/loop-delete/stop/<job_id>", methods=["POST"])
@login_required
def stop_loop_delete(job_id):
    job = loop_delete_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    job.stop()
    return jsonify({"success": True, "message": "Loop dihentikan"})


@app.route("/api/loop-delete/restart/<job_id>", methods=["POST"])
@login_required
def restart_loop_delete(job_id):
    job = loop_delete_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    if job.running:
        return jsonify({"error": "Job masih berjalan"}), 400
    if not job.start():
        return jsonify({"success": False, "error": job.error or "Gagal restart"}), 400
    return jsonify({"success": True, "message": "Loop dimulai ulang"})


@app.route("/api/loop-delete/delete/<job_id>", methods=["POST"])
@login_required
def delete_loop_delete(job_id):
    job = loop_delete_jobs.pop(job_id, None)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    if job.running:
        job.stop()
    return jsonify({"success": True, "message": "Job dihapus"})


@app.route("/api/loop-delete/status/<job_id>")
@login_required
def loop_delete_status(job_id):
    job = loop_delete_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(job.get_status())


@app.route("/api/loop-delete/list")
@login_required
def list_loop_delete_jobs():
    result = []
    for jid, job in loop_delete_jobs.items():
        result.append(job.get_status())
    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000, threaded=True)
