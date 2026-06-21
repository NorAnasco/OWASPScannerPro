from flask import Flask, render_template, request, jsonify, Response, stream_with_context, session, redirect, url_for, send_file
from flask_cors import CORS
import json, uuid, threading, os, time, io, sys
from scanners.zap_scanner import ZapScanner
from scanners.nikto_scanner import NiktoScanner
from scanners.burp_scanner import BurpScanner
from scanners.nmap_scanner import NmapScanner
from scanners.owasp_analyzer import OwaspAnalyzer
from utils.report_generator import ReportGenerator
from utils.target_validator import validate_target
from utils.audit_logger import AuditLogger
from utils.crypto_utils import encrypt, decrypt
from utils.rate_limiter import login_limiter, api_limiter
from utils.scan_scheduler import ScanScheduler
from database.db import Database
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
from dotenv import load_dotenv
import sqlite3
from datetime import datetime, timedelta
# Initialiser la base de données
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "database", "scanner.db")
db = Database(db_path=DB_PATH)
audit = AuditLogger(db_path=DB_PATH)

# Fonction callback pour le scheduler (lance un scan sans validation HTTP)
def _scheduler_run_scan(target: str, tools: list, owasp_ids: list, username: str = 'scheduler', project_id: str = None) -> str:
    """Callback utilisée par le ScanScheduler pour lancer un scan sans validation HTTP."""
    import uuid as uuid_mod
    scan_id = str(uuid_mod.uuid4())
    encrypted_target = encrypt(target)
    db.save_scan(scan_id, encrypted_target, tools, owasp_ids, created_by=username, project_id=project_id)
    
    with scan_sessions_lock:
        scan_sessions[scan_id] = {
            "target": target, "tools": tools, "owasp_ids": owasp_ids,
            "status": "running", "events": [], "results": {}
        }
    
    audit.log(username, 'scan_start', {'target': target, 'tools': tools, 'scheduled': True}, scan_id=scan_id)
    
    thread = threading.Thread(
        target=run_scan_pipeline,
        args=(scan_id, target, tools, owasp_ids), daemon=True
    )
    thread.start()
    return scan_id


def _start_scan_internal(target: str, tools: list, owasp_ids: list, username: str = 'anonymous', project_id: str = None) -> str:
    """Crée un scan, l'enregistre en mémoire et lance le thread d'exécution."""
    scan_id = str(uuid.uuid4())
    encrypted_target = encrypt(target)
    db.save_scan(scan_id, encrypted_target, tools, owasp_ids, created_by=username, project_id=project_id)
    
    with scan_sessions_lock:
        scan_sessions[scan_id] = {
            "target": target,
            "tools": tools,
            "owasp_ids": owasp_ids,
            "status": "running",
            "events": [],
            "results": {}
        }
    
    audit.log(username, 'scan_start', {'target': target, 'tools': tools, 'owasp_ids': list(owasp_ids)}, scan_id=scan_id)
    
    thread = threading.Thread(
        target=run_scan_pipeline,
        args=(scan_id, target, tools, owasp_ids),
        daemon=True
    )
    thread.start()
    return scan_id


def _monitor_scan_batch(batch_id: str, scan_ids: list):
    """Met à jour le statut du lot après la fin de tous les scans."""
    while True:
        time.sleep(0.5)
        statuses = []
        error_message = None
        with scan_sessions_lock:
            for scan_id in scan_ids:
                s = scan_sessions.get(scan_id)
                if not s:
                    statuses.append('missing')
                else:
                    statuses.append(s.get('status'))
                    if s.get('status') == 'error':
                        error_message = f"Scan {scan_id} en erreur"
        if statuses and all(status in ('done', 'error') for status in statuses):
            db.update_scan_batch_status(batch_id, 'error' if error_message else 'done', error_message)
            break


# Initialiser et démarrer le scheduler
scheduler = ScanScheduler(db_path=DB_PATH, scan_runner=_scheduler_run_scan)
scheduler.start()


def current_user():
    return session.get('username', 'anonymous')


def is_admin_user():
    return session.get('role') == 'admin'


def owner_sql(alias: str = 's'):
    if is_admin_user():
        return '', []
    return f" AND {alias}.created_by = ?", [current_user()]


def can_access_scan(scan_id: str) -> bool:
    scan = db.get_scan(scan_id)
    return bool(scan and (is_admin_user() or scan.get('created_by') == current_user()))


def can_access_project(project_id: str) -> bool:
    project = db.get_project(project_id)
    return bool(project and (is_admin_user() or project.get('created_by') == current_user()))


def can_access_batch(batch_id: str) -> bool:
    batch = db.get_scan_batch(batch_id)
    return bool(batch and (is_admin_user() or batch.get('created_by') == current_user()))


def get_scheduled_task(task_id: int):
    for task in scheduler.get_scheduled_scans():
        if task.get('id') == task_id:
            return task
    return None


def can_access_scheduled_task(task_id: int) -> bool:
    task = get_scheduled_task(task_id)
    return bool(task and (is_admin_user() or task.get('created_by') == current_user()))


app = Flask(__name__)
load_dotenv()
# 🔑 Clé secrète chargée depuis l'environnement (avec fallback développement)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "OWASP_SCANNER_PRO_SUPER_SECRET_KEY_PPE_2026")
CORS(app)

# Cache en mémoire des scans ACTIFS uniquement (streaming SSE)
# Les resultats sont persistes dans la DB
scan_sessions = {}
scan_sessions_lock = threading.Lock()

load_dotenv()

DB_NAME = DB_PATH  # Chemin vers ta base de données SQLite


# Décorateur pour protéger les routes avec authentification basique
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/login", methods=["GET", "POST"])
@login_limiter.limit(max_attempts=5, window=60, error_message="Trop de tentatives de connexion. Réessayez dans {window} secondes.")
def login():
    # Si l'utilisateur est déjà connecté, on le redirige vers l'accueil
    if session.get('logged_in'):
        return redirect(url_for('index'))

    error = None
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        # Connexion à la BDD pour chercher l'utilisateur
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        # Vérification des identifiants et du hash du mot de passe
        if user and check_password_hash(user['password_hash'], password):
            # Réinitialiser le rate limiter pour cette IP
            login_limiter.reset(request.remote_addr or '0.0.0.0')
            
            session['logged_in'] = True
            session['username'] = user['username']
            session['role'] = user['role']
            
            # 🔐 Audit : connexion réussie
            audit.log(username, 'login', {'role': user['role']})
            
            return redirect(url_for('index'))
        else:
            # 🔐 Audit : tentative échouée + compteur rate limiter
            login_limiter.record_attempt(request.remote_addr or '0.0.0.0')
            remaining = login_limiter.get_remaining(request.remote_addr or '0.0.0.0', 5, 60)
            audit.log(username or 'unknown', 'login_fail', {'reason': 'Invalid credentials', 'remaining': remaining})
            error = f"ACCÈS REFUSÉ : Identifiants invalides ({remaining} tentative(s) restante(s))"
            
    return render_template("login.html", error=error)


@app.route("/logout")
@login_required
def logout():
    # 🔐 Audit : déconnexion
    audit.log(session.get('username', 'unknown'), 'logout')
    session.pop("logged_in", None)
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    return render_template("index.html")


def _get_config_from_db():
    """Lit la configuration depuis la table app_config."""
    defaults = {
        'nmap_real': 'false', 'zap_real': 'false', 'nikto_real': 'false', 'burp_real': 'false',
        'zap_host': '127.0.0.1', 'zap_port': '8080',
        'burp_host': '127.0.0.1', 'burp_port': '1337',
        'debug_mode': 'false'
    }
    try:
        conn = sqlite3.connect(DB_NAME)
        rows = conn.execute("SELECT key, value FROM app_config").fetchall()
        conn.close()
        for k, v in rows:
            defaults[k] = v
    except Exception:
        pass  # Conserver les defaults si la table n'existe pas encore
    return defaults

@app.route("/api/config", methods=["GET"])
@login_required
def get_config():
    """Retourne la configuration sans exposer les valeurs sensibles."""
    cfg = _get_config_from_db()
    return jsonify({
        "app_version": "2.1",
        "python_version": sys.version.split()[0],
        "database_path": DB_PATH,
        "database_exists": os.path.exists(DB_PATH),
        "secret_key_configured": bool(os.getenv("FLASK_SECRET_KEY")),
        "anthropic_key_configured": bool(os.getenv("ANTHROPIC_API_KEY")),
        "real_tools": {
            "nmap": cfg.get('nmap_real', 'false') == 'true',
            "zap": cfg.get('zap_real', 'false') == 'true',
            "nikto": cfg.get('nikto_real', 'false') == 'true',
            "burp": cfg.get('burp_real', 'false') == 'true'
        },
        "zap": {
            "host": cfg.get('zap_host', '127.0.0.1'),
            "port": cfg.get('zap_port', '8080')
        },
        "burp": {
            "host": cfg.get('burp_host', '127.0.0.1'),
            "port": cfg.get('burp_port', '1337')
        },
        "security": {
            "user_isolation": True,
            "audit_logging": True,
            "target_encryption": True,
            "rate_limiting": True,
            "https_recommended": True,
            "debug_mode": cfg.get('debug_mode', 'false') == 'true'
        }
    }), 200

@app.route("/api/config", methods=["PUT"])
@login_required
def update_config():
    """Met à jour la configuration (admin seulement)."""
    if session.get('role') != 'admin':
        return jsonify({'error': 'Accès refusé. Seul un admin peut modifier la configuration.'}), 403
    
    data = request.get_json() or {}
    allowed_keys = {'nmap_real', 'zap_real', 'nikto_real', 'burp_real',
                    'zap_host', 'zap_port', 'burp_host', 'burp_port', 'debug_mode'}
    username = session.get('username', 'anonymous')
    updated = []
    
    try:
        conn = sqlite3.connect(DB_NAME)
        for key, value in data.items():
            if key in allowed_keys:
                # Convertir les booléens en string pour la DB
                if isinstance(value, bool):
                    value = 'true' if value else 'false'
                conn.execute(
                    "INSERT INTO app_config (key, value, updated_by, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = CURRENT_TIMESTAMP",
                    (key, str(value), username)
                )
                updated.append(key)
        conn.commit()
        conn.close()
        
        if updated:
            audit.log(username, 'config_update', {'keys': updated, 'values': {k: data[k] for k in updated if k in data}})
        
        return jsonify({
            'message': f'Configuration mise à jour : {", ".join(updated)}',
            'updated': updated
        }), 200
    except Exception as e:
        print(f"[-] Erreur update config : {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route("/api/scan/start", methods=["POST"])
@login_required
def start_scan():
    data = request.get_json()
    target = data.get("target", "").strip()
    tools = data.get("tools", ["zap", "nikto", "burp", "ai"])
    owasp_ids = data.get("owasp_ids", [f"A{str(i).zfill(2)}" for i in range(1, 11)])
    project_id = data.get("project_id") or None

    valid, error = validate_target(target)
    if not valid:
        return jsonify({"error": error}), 400

    scan_id = _start_scan_internal(target, tools, owasp_ids, session.get('username', 'anonymous'), project_id)
    return jsonify({"scan_id": scan_id})


@app.route("/api/scan/stream/<scan_id>")
@login_required
def stream_scan(scan_id):
    """SSE endpoint — envoie les événements au fur et à mesure"""
    if not can_access_scan(scan_id):
        return jsonify({"error": "Accès refusé."}), 403
    def event_stream():
        last_index = 0
        while True:
            session = scan_sessions.get(scan_id)
            if not session:
                yield f"data: {json.dumps({'type':'error','message':'Scan introuvable'})}\n\n"
                break

            events = session["events"]
            while last_index < len(events):
                event = events[last_index]
                yield f"data: {json.dumps(event)}\n\n"
                last_index += 1

            if session["status"] in ("done", "error"):
                break

            threading.Event().wait(0.3)

    return Response(
        stream_with_context(event_stream()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no"
        }
    )


@app.route("/api/scan/result/<scan_id>")
@login_required
def get_result(scan_id):
    if not can_access_scan(scan_id):
        return jsonify({"error": "Accès refusé."}), 403
    session = scan_sessions.get(scan_id)
    if not session:
        return jsonify({"error": "Introuvable"}), 404
    return jsonify(session.get("results", {}))


@app.route("/api/scan/status/<scan_id>")
@login_required
def get_scan_status(scan_id):
    if not can_access_scan(scan_id):
        return jsonify({"error": "Accès refusé."}), 403
    session = scan_sessions.get(scan_id)
    if not session:
        return jsonify({"error": "Introuvable"}), 404
    return jsonify({
        "scan_id": scan_id,
        "status": session.get("status"),
        "events": session.get("events", [])[-12:],
        "results_ready": bool(session.get("results"))
    })


@app.route("/api/report/<scan_id>/<fmt>")
@login_required
def download_report(scan_id, fmt):
    if not can_access_scan(scan_id):
        return jsonify({"error": "Accès refusé."}), 403
    session = scan_sessions.get(scan_id)
    if not session or session["status"] != "done":
        return jsonify({"error": "Scan non terminé"}), 404

    gen = ReportGenerator(session["results"])
    if fmt == "pdf":
        content = gen.to_pdf()
        if not isinstance(content, bytes):
            content = content.encode("utf-8")
        return send_file(
            io.BytesIO(content),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"rapport_{scan_id[:8]}.pdf"
        )
    elif fmt == "json":
        content = gen.to_json().encode("utf-8")
        return send_file(
            io.BytesIO(content),
            mimetype="application/json",
            as_attachment=True,
            download_name=f"rapport_{scan_id[:8]}.json"
        )
    elif fmt == "markdown":
        content = gen.to_markdown().encode("utf-8")
        return send_file(
            io.BytesIO(content),
            mimetype="text/markdown; charset=utf-8",
            as_attachment=True,
            download_name=f"rapport_{scan_id[:8]}.md"
        )
    else:
        return jsonify({"error": "Format non supporté"}), 400


# ─── Pipeline principal ──────────────────────────────────────────────────────

def push_event(scan_id, event: dict):
    with scan_sessions_lock:
        if scan_id in scan_sessions:
            scan_sessions[scan_id]["events"].append(event)


def run_scan_pipeline(scan_id, target, tools, owasp_ids):
    with scan_sessions_lock:
        session = scan_sessions[scan_id]
    all_findings = []

    try:
        push_event(scan_id, {"type": "phase", "phase": "init",
                              "message": f"Résolution DNS & empreinte de {target}", "pct": 5})

        # ── 0. Nmap (cartographie réseau) ────────────────────────────────────
        if "nmap" in tools:
            push_event(scan_id, {"type": "phase", "phase": "nmap",
                                  "message": "Nmap — détection des ports ouverts", "pct": 15})
            nmap = NmapScanner(target)
            nmap_findings = nmap.run()
            all_findings.extend(nmap_findings)
            push_event(scan_id, {"type": "tool_done", "tool": "nmap",
                                  "count": len(nmap_findings), "pct": 25})

        # ── 1. ZAP ──────────────────────────────────────────────────────────
        if "zap" in tools:
            push_event(scan_id, {"type": "phase", "phase": "zap",
                                  "message": "OWASP ZAP — scan passif + actif", "pct": 30})
            zap = ZapScanner(target)
            zap_findings = zap.run(owasp_ids)
            all_findings.extend(zap_findings)
            push_event(scan_id, {"type": "tool_done", "tool": "zap",
                                  "count": len(zap_findings), "pct": 45})

        # ── 2. Nikto ────────────────────────────────────────────────────────
        if "nikto" in tools:
            push_event(scan_id, {"type": "phase", "phase": "nikto",
                                  "message": "Nikto — fichiers dangereux & CVE serveur", "pct": 50})
            nikto = NiktoScanner(target)
            nikto_findings = nikto.run()
            all_findings.extend(nikto_findings)
            push_event(scan_id, {"type": "tool_done", "tool": "nikto",
                                  "count": len(nikto_findings), "pct": 65})

        # ── 3. Burp ─────────────────────────────────────────────────────────
        if "burp" in tools:
            push_event(scan_id, {"type": "phase", "phase": "burp",
                                  "message": "Burp Suite — fuzzing & injection", "pct": 70})
            burp = BurpScanner(target)
            burp_findings = burp.run(owasp_ids)
            all_findings.extend(burp_findings)
            push_event(scan_id, {"type": "tool_done", "tool": "burp",
                                  "count": len(burp_findings), "pct": 80})

        # ── 4. IA OWASP ─────────────────────────────────────────────────────
        if "ai" in tools:
            push_event(scan_id, {"type": "phase", "phase": "ai",
                                  "message": "Corrélation IA OWASP — analyse des patterns", "pct": 85})
            ai = OwaspAnalyzer(target)
            ai_findings = ai.analyze(all_findings, owasp_ids)
            all_findings.extend(ai_findings)
            push_event(scan_id, {"type": "tool_done", "tool": "ai",
                                  "count": len(ai_findings), "pct": 93})

        # ── 5. Rapport final ────────────────────────────────────────────────
        push_event(scan_id, {"type": "phase", "phase": "report",
                              "message": "Consolidation du rapport", "pct": 96})
        results = build_final_report(target, all_findings, tools)
        with scan_sessions_lock:
            if scan_id in scan_sessions:
                scan_sessions[scan_id]["results"] = results
                scan_sessions[scan_id]["status"] = "done"
        
        # Sauvegarder dans la DB
        push_event(scan_id, {"type": "phase", "phase": "db", "message": "Sauvegarde des findings en base", "pct": 98})
        db.save_findings(scan_id, all_findings)
        push_event(scan_id, {"type": "phase", "phase": "finalize", "message": "Finalisation du scan", "pct": 99})
        db.update_scan_results(scan_id, results["score"], results["risk_level"])
        db.save_results(scan_id, target, tools, results["score"], results["risk_level"], results["stats"])
        db.update_scan_status(scan_id, "done")
        
        push_event(scan_id, {"type": "done", "results": results, "pct": 100})

    except Exception as exc:
        with scan_sessions_lock:
            if scan_id in scan_sessions:
                scan_sessions[scan_id]["status"] = "error"
        # Sauvegarder l'erreur dans la DB
        db.update_scan_status(scan_id, "error", str(exc))
        push_event(scan_id, {"type": "error", "message": str(exc)})


def build_final_report(target, findings, tools_used):
    """Agrège tous les findings et calcule le score global."""
    severity_order = {"critique": 0, "élevé": 1, "moyen": 2, "faible": 3, "ok": 4}
    findings.sort(key=lambda f: severity_order.get(f.get("statut", "ok"), 5))

    crit = sum(1 for f in findings if f.get("statut") == "critique")
    high = sum(1 for f in findings if f.get("statut") == "élevé")
    med  = sum(1 for f in findings if f.get("statut") == "moyen")
    ok   = sum(1 for f in findings if f.get("statut") == "ok")

    # Score : 100 - pénalités
    score = max(0, 100 - crit * 20 - high * 8 - med * 3)
    risk = "Critique" if crit > 0 else "Élevé" if high > 0 else "Moyen" if med > 0 else "Faible"

    return {
        "target": target,
        "tools_used": tools_used,
        "score": score,
        "risk_level": risk,
        "stats": {"critique": crit, "élevé": high, "moyen": med, "ok": ok},
        "findings": findings
    }


# ─── NOUVEAUX ENDPOINTS — HISTORIQUE & BASE DE DONNÉES ─────────────────────

@app.route("/api/scans", methods=["GET"])
@login_required
def list_scans():
    """Liste tous les scans (avec pagination)"""
    try:
        page =request.args.get("page", 1, type=int)
        limit = request.args.get("limit", 50, type=int)
        offset = (page - 1) * limit

        scans = db.list_scans(
            offset=offset,
            limit=limit,
            date_from=request.args.get("date_from"),
            date_to=request.args.get("date_to"),
            tool=request.args.get("tool"),
            score_min=request.args.get("score_min", type=int),
            score_max=request.args.get("score_max", type=int),
            project_id=request.args.get("project_id"),
            created_by=None if is_admin_user() else current_user(),
        )

        #Mappage de compatibilité Frontend vers backend
        scans_compatibles = []
        for s in scans:
            # On crée un disctionnaire compatible à partir des données de la BDD
            scan_item = dict(s)

            # Correction du bouton "voir"
            if "id" in scan_item:
                scan_item["scan_id"] = scan_item["id"]

            # Correction de la date (alias completed_at en date)
            scan_item["date"] = scan_item.get("completed_at") or scan_item.get("started_at")
            scan_item["created_at"] = scan_item.get("started_at")
            if scan_item.get("target"):
                scan_item["target"] = decrypt(scan_item["target"])

            # Correction du niveau de risque (alias risk_level -> risk/risque)
            scan_item["risk"] = scan_item.get("risk_level")
            scan_item["risque"] = scan_item.get("risk_level")

            scans_compatibles.append(scan_item)

        return jsonify(scans_compatibles), 200

    except Exception as e:
        print(f"[-] Erreur /api/scans : {str(e)}")
        return jsonify({"error": "Erreur lors du chargement de l'historique"}), 500

@app.route("/api/scans/<scan_id>", methods=["GET"])
@login_required
def get_scan_detail(scan_id):
    """Recupere le detail complet d'un scan"""
    try:
        scan = db.get_scan(scan_id)
        if not scan:
            return jsonify({"error": "Scan introuvable"}), 404
        if not is_admin_user() and scan.get('created_by') != current_user():
            return jsonify({"error": "Accès refusé."}), 403
        
        # Convertir les JSON strings de la DB en objets Python avant envoi
        scan['tools'] = json.loads(scan['tools']) if scan['tools'] else []
        scan['owasp_ids'] = json.loads(scan['owasp_ids']) if scan['owasp_ids'] else []
        
        # Récupérer les findings et les résultats condensés
        findings = db.get_findings_for_scan(scan_id)
        results = db.get_results(scan_id)
        
        return jsonify({
            "scan": scan,
            "findings": findings,
            "results": results
        }), 200
    except Exception as e:
        print(f"[-] Erreur /api/scans/{scan_id} : {str(e)}")
        return jsonify({"error": "Erreur lors du chargement du scan"}), 500


@app.route("/api/projects", methods=["GET"])
@login_required
def list_projects():
    try:
        projects = db.list_projects()
        if not is_admin_user():
            projects = [p for p in projects if p.get('created_by') == current_user()]
        return jsonify(projects), 200
    except Exception as e:
        print(f"[-] Erreur /api/projects : {str(e)}")
        return jsonify({"error": "Erreur lors du chargement des projets"}), 500


@app.route("/api/projects", methods=["POST"])
@login_required
def create_project():
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "Nom du projet requis."}), 400

    project_id = str(uuid.uuid4())
    try:
        db.create_project(
            project_id=project_id,
            name=name,
            client=(data.get("client") or "").strip(),
            environment=data.get("environment") or "prod",
            description=(data.get("description") or "").strip(),
            start_date=data.get("start_date"),
            end_date=data.get("end_date"),
            created_by=session.get('username', 'anonymous')
        )
        audit.log(session.get('username', 'unknown'), 'project_create', {'project_id': project_id, 'name': name})
        return jsonify({"message": "Projet créé avec succès.", "project_id": project_id}), 201
    except Exception as e:
        print(f"[-] Erreur création projet : {str(e)}")
        return jsonify({"error": "Erreur lors de la création du projet"}), 500


@app.route("/api/projects/<project_id>", methods=["GET"])
@login_required
def get_project(project_id):
    if not can_access_project(project_id):
        return jsonify({"error": "Accès refusé."}), 403
    project = db.get_project(project_id)
    if not project:
        return jsonify({"error": "Projet introuvable"}), 404
    return jsonify({
        "project": project,
        "stats": db.get_project_stats(project_id)
    }), 200


@app.route("/api/projects/<project_id>", methods=["PUT"])
@login_required
def update_project(project_id):
    if not can_access_project(project_id):
        return jsonify({"error": "Accès refusé."}), 403
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "Nom du projet requis."}), 400
    if not db.get_project(project_id):
        return jsonify({"error": "Projet introuvable"}), 404
    try:
        db.update_project(
            project_id=project_id,
            name=name,
            client=(data.get("client") or "").strip(),
            environment=data.get("environment") or "prod",
            description=(data.get("description") or "").strip(),
            start_date=data.get("start_date"),
            end_date=data.get("end_date")
        )
        return jsonify({"message": "Projet mis à jour avec succès."}), 200
    except Exception as e:
        print(f"[-] Erreur update projet {project_id} : {str(e)}")
        return jsonify({"error": "Erreur lors de la mise à jour du projet"}), 500


@app.route("/api/projects/<project_id>", methods=["DELETE"])
@login_required
def delete_project(project_id):
    if not can_access_project(project_id):
        return jsonify({"error": "Accès refusé."}), 403
    try:
        db.delete_project(project_id)
        audit.log(session.get('username', 'unknown'), 'project_delete', {'project_id': project_id})
        return jsonify({"message": "Projet supprimé avec succès."}), 200
    except Exception as e:
        print(f"[-] Erreur suppression projet {project_id} : {str(e)}")
        return jsonify({"error": "Erreur lors de la suppression du projet"}), 500


@app.route("/api/projects/<project_id>/stats", methods=["GET"])
@login_required
def get_project_stats(project_id):
    if project_id == 'global':
        stats = db.get_project_stats(None)
        if not is_admin_user():
            stats = db.get_project_stats(created_by=current_user())
        return jsonify(stats), 200
    if not can_access_project(project_id):
        return jsonify({"error": "Accès refusé."}), 403
    return jsonify(db.get_project_stats(project_id)), 200


def _finding_key(f: dict) -> str:
    return "|".join([
        str(f.get("owasp_id", "")),
        str(f.get("nom", "")),
        str(f.get("technique", "")),
        str(f.get("preuve", "")),
    ]).lower()


def _compare_findings(left: list, right: list) -> dict:
    left_map = {_finding_key(f): f for f in left}
    right_map = {_finding_key(f): f for f in right}
    left_keys = set(left_map)
    right_keys = set(right_map)

    new = [right_map[k] for k in sorted(right_keys - left_keys)]
    fixed = [left_map[k] for k in sorted(left_keys - right_keys)]
    changed = []
    unchanged = []

    for key in sorted(left_keys & right_keys):
        l = left_map[key]
        r = right_map[key]
        if l.get("statut") != r.get("statut") or float(l.get("cvss") or 0) != float(r.get("cvss") or 0):
            changed.append({"before": l, "after": r})
        else:
            unchanged.append(r)

    return {
        "new": new,
        "fixed": fixed,
        "changed": changed,
        "unchanged": unchanged,
        "summary": {
            "new_count": len(new),
            "fixed_count": len(fixed),
            "changed_count": len(changed),
            "unchanged_count": len(unchanged),
        }
    }


@app.route("/api/scans/diff", methods=["POST"])
@login_required
def compare_scans():
    """Compare deux scans terminés et retourne les vulnérabilités nouvelles, corrigées et modifiées."""
    data = request.get_json() or {}
    left_scan_id = data.get("left_scan_id")
    right_scan_id = data.get("right_scan_id")
    if not left_scan_id or not right_scan_id or left_scan_id == right_scan_id:
        return jsonify({"error": "Deux scans différents sont requis."}), 400

    try:
        if not db.get_scan(left_scan_id) or not db.get_scan(right_scan_id):
            return jsonify({"error": "Un des scans est introuvable."}), 404
        if not can_access_scan(left_scan_id) or not can_access_scan(right_scan_id):
            return jsonify({"error": "Accès refusé."}), 403
        left = db.get_findings_for_scan(left_scan_id) or []
        right = db.get_findings_for_scan(right_scan_id) or []
        diff = _compare_findings(left, right)
        diff.update({
            "left_scan_id": left_scan_id,
            "right_scan_id": right_scan_id,
            "created_by": session.get('username', 'anonymous')
        })
        db.save_scan_diff(left_scan_id, right_scan_id, diff, session.get('username', 'anonymous'))
        audit.log(session.get('username', 'unknown'), 'scan_diff', {
            'left_scan_id': left_scan_id,
            'right_scan_id': right_scan_id,
            'summary': diff['summary']
        })
        return jsonify(diff), 200
    except Exception as e:
        print(f"[-] Erreur /api/scans/diff : {str(e)}")
        return jsonify({"error": "Erreur lors de la comparaison des scans"}), 500


@app.route("/api/findings/<int:finding_id>/annotate", methods=["POST"])
@login_required
def annotate_finding(finding_id):
    """Ajoute ou met à jour le statut et les commentaires d'un finding."""
    data = request.get_json() or {}
    status = data.get("status")
    comment = (data.get("comment") or "").strip()

    allowed = {"none", "faux_positif", "confirme", "en_correction", "corrige"}
    if status not in allowed:
        return jsonify({"error": "Statut invalide."}), 400
    if not comment:
        return jsonify({"error": "Commentaire requis."}), 400

    try:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row
        exists = conn.execute("SELECT id FROM findings WHERE id = ?", (finding_id,)).fetchone()
        conn.close()
        if not exists:
            return jsonify({"error": "Finding introuvable."}), 404
        db.annotate_finding(finding_id, status, comment, session.get('username', 'anonymous'))
        audit.log(session.get('username', 'unknown'), 'finding_annotate', {
            'finding_id': finding_id,
            'status': status
        })
        return jsonify({"message": "Finding annoté avec succès."}), 200
    except Exception as e:
        print(f"[-] Erreur annotation finding {finding_id} : {str(e)}")
        return jsonify({"error": "Erreur lors de l'annotation"}), 500


@app.route("/api/findings/<int:finding_id>/comments", methods=["GET"])
@login_required
def get_finding_comments(finding_id):
    """Retourne l'historique des commentaires d'un finding."""
    try:
        return jsonify({"comments": db.get_finding_comments(finding_id)}), 200
    except Exception as e:
        print(f"[-] Erreur commentaires finding {finding_id} : {str(e)}")
        return jsonify({"error": "Erreur lors du chargement des commentaires"}), 500


@app.route("/api/batch-scans/start", methods=["POST"])
@login_required
def start_batch_scans():
    """Lance plusieurs scans de cibles différentes en parallèle."""
    data = request.get_json() or {}
    targets = data.get("targets") or []
    tools = data.get("tools", ["zap", "nikto", "burp", "ai"])
    owasp_ids = data.get("owasp_ids", [f"A{str(i).zfill(2)}" for i in range(1, 11)])
    project_id = data.get("project_id") or None

    if not isinstance(targets, list) or not targets:
        return jsonify({"error": "Au moins une cible est requise."}), 400

    targets = [t.strip() for t in targets if t and t.strip()]
    if not targets:
        return jsonify({"error": "Aucune cible valide."}), 400

    try:
        for target in targets:
            valid, error = validate_target(target)
            if not valid:
                return jsonify({"error": f"Cible invalide '{target}' : {error}"}), 400

        batch_id = str(uuid.uuid4())
        scan_ids = [_start_scan_internal(t, tools, owasp_ids, session.get('username', 'anonymous'), project_id) for t in targets]
        db.save_scan_batch(batch_id, targets, scan_ids, session.get('username', 'anonymous'))
        audit.log(session.get('username', 'unknown'), 'batch_scan', {
            'batch_id': batch_id,
            'targets': targets,
            'scan_ids': scan_ids
        })
        threading.Thread(target=_monitor_scan_batch, args=(batch_id, scan_ids), daemon=True).start()
        return jsonify({"batch_id": batch_id, "scan_ids": scan_ids}), 201
    except Exception as e:
        print(f"[-] Erreur batch scans : {str(e)}")
        return jsonify({"error": "Erreur lors du lancement des scans"}), 500


@app.route("/api/batch-scans/<batch_id>", methods=["GET"])
@login_required
def get_batch_scans(batch_id):
    """Retourne l'état d'un scan multi-cibles."""
    if not can_access_batch(batch_id):
        return jsonify({"error": "Accès refusé."}), 403
    batch = db.get_scan_batch(batch_id)
    if not batch:
        return jsonify({"error": "Lot introuvable"}), 404
    return jsonify(batch), 200



@app.route("/api/scans/<scan_id>", methods=["DELETE"])
@login_required
def delete_scan(scan_id):
    """Supprime un scan et tous ses findings"""
    if not can_access_scan(scan_id):
        return jsonify({"error": "Accès refusé."}), 403
    try:
        scan = db.get_scan(scan_id)
        target_info = scan.get('target', 'unknown') if scan else 'unknown'
        db.delete_scan(scan_id)
        # 🔐 Audit : suppression de scan
        audit.log(
            session.get('username', 'unknown'),
            'scan_delete',
            {'scan_id': scan_id, 'target': decrypt(target_info) if scan else 'unknown'},
            scan_id=scan_id
        )
        return jsonify({"message": "Scan supprimé avec succès"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/stats", methods=["GET"])
@login_required
def get_stats():
    """Recupere les statistiques globales"""
    try:
        stats = db.get_stats()
        return jsonify(stats), 200
    except Exception as e:
        print(f"[-] Erreur /api/stats : {str(e)}")
        return jsonify({"error": "Erreur lors du chargement des statistiques"}), 500




# La base de données est initialisée par Database.__init__() via le schema.sql
# (voir database/db.py et database/schema.sql)


@app.route('/api/admin/add-user', methods=['POST'])
@login_required
def add_user():
    # 1. Sécurité : Vérification du rôle RBAC dans la session
    if session.get('role') != 'admin':
        return jsonify({'error': 'Accès refusé. Autorisation insuffisante.'}), 403

    # 2. Récupération des données JSON envoyées par le JavaScript
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    role = data.get('role', 'auditor')

    # 3. Validation des champs
    if not username or not password:
        return jsonify({'error': 'Tous les champs sont obligatoires.'}), 400

    # 4. Hachage sécurisé du mot de passe
    hashed_password = generate_password_hash(password)

    # 5. Insertion en Base de Données
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, hashed_password, role)
        )
        
        conn.commit()
        conn.close()
        
        # 🔐 Audit : création d'utilisateur
        audit.log(
            session.get('username', 'unknown'),
            'user_create',
            {'target_username': username, 'role': role}
        )
        
        return jsonify({'message': f"Le collaborateur '{username}' a bien été enregistré."}), 201

    except sqlite3.IntegrityError:
        return jsonify({'error': f"Le nom d'utilisateur '{username}' est déjà utilisé."}), 400
        
    except Exception as e:
        return jsonify({'error': f"Erreur interne de la base de données : {str(e)}"}), 500
    
@app.route('/api/admin/get-users', methods=['GET'])
@login_required
def get_users():
    # Sécurité : Seul l'admin connecté peut lister les utilisateurs
    if session.get('role') != 'admin':
        return jsonify({'error': 'Accès refusé.'}), 403

    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        cursor.execute("SELECT username, role FROM users")
        rows = cursor.fetchall()
        conn.close()

        users_list = [{'username': row[0], 'role': row[1]} for row in rows]
        return jsonify(users_list), 200

    except Exception as e:
        return jsonify({'error': f"Erreur de lecture : {str(e)}"}), 500

@app.route('/api/admin/delete-user/<username>', methods=['DELETE'])
@login_required
def delete_user(username):
    if session.get('role') != 'admin':
        return jsonify({'error': 'Accès refusé.'}), 403
    
    if username == session.get('username'):
        return jsonify({'error': 'Action impossible : vous ne pouvez pas supprimer votre propre compte.'}), 400

    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE username = ?", (username,))
        conn.commit()
        conn.close()
        
        # 🔐 Audit : suppression d'utilisateur
        audit.log(
            session.get('username', 'unknown'),
            'user_delete',
            {'target_username': username}
        )
        
        return jsonify({'message': f"L'utilisateur '{username}' a été supprimé avec succès."}), 200
    except Exception as e:
        return jsonify({'error': f"Erreur lors de la suppression : {str(e)}"}), 500


# ─── SCHEDULER ENDPOINTS ──────────────────────────────────────────────

@app.route('/api/scheduler/tasks', methods=['GET'])
@login_required
def get_scheduled_tasks():
    """Liste les scans programmés."""
    try:
        tasks = scheduler.get_scheduled_scans()
        if not is_admin_user():
            tasks = [t for t in tasks if t.get('created_by') == current_user()]
        return jsonify(tasks), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scheduler/tasks', methods=['POST'])
@login_required
def create_scheduled_task():
    """Crée un scan programmé."""
    if session.get('role') != 'admin':
        return jsonify({'error': 'Accès refusé. Seul un admin peut planifier des scans.'}), 403

    data = request.get_json()
    target = data.get('target', '').strip()
    tools = data.get('tools', ['zap', 'nikto', 'burp', 'ai'])
    owasp_ids = data.get('owasp_ids', [f"A{str(i).zfill(2)}" for i in range(1, 11)])
    interval = data.get('interval_minutes', 60)

    if not target:
        return jsonify({'error': 'Cible requise.'}), 400

    task_id = scheduler.schedule_scan(
        target=target, tools=tools, owasp_ids=owasp_ids,
        interval_minutes=interval,
        created_by=session.get('username', 'anonymous')
    )
    
    audit.log(
        session.get('username', 'unknown'),
        'scan_start',
        {'target': target, 'scheduled': True, 'interval': interval, 'task_id': task_id}
    )

    return jsonify({'message': 'Scan programmé avec succès.', 'task_id': task_id}), 201

@app.route('/api/scheduler/tasks/<int:task_id>', methods=['DELETE'])
@login_required
def delete_scheduled_task(task_id):
    """Supprime un scan programmé."""
    if not can_access_scheduled_task(task_id):
        return jsonify({'error': 'Accès refusé.'}), 403
    scheduler.delete_scheduled_scan(task_id)
    return jsonify({'message': 'Tâche supprimée.'}), 200

@app.route('/api/scheduler/tasks/<int:task_id>/toggle', methods=['POST'])
@login_required
def toggle_scheduled_task(task_id):
    """Active/désactive un scan programmé."""
    if not can_access_scheduled_task(task_id):
        return jsonify({'error': 'Accès refusé.'}), 403
    data = request.get_json()
    enabled = data.get('enabled', True)
    scheduler.toggle_scheduled_scan(task_id, enabled)
    return jsonify({'message': 'Tâche mise à jour.'}), 200


# ─── DASHBOARD STATS ENDPOINTS ─────────────────────────────────────────

@app.route('/api/dashboard/stats', methods=['GET'])
@login_required
def dashboard_stats():
    """Stats enrichies pour le dashboard (évolution du score)."""
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        # Stats globales ou utilisateur selon rôle
        owner_clause, owner_params = owner_sql('s')
        finding_owner_clause, _ = owner_sql('s')

        cursor.execute(f"SELECT COUNT(*) FROM scans s WHERE 1=1 {owner_clause}", owner_params)
        total_scans = cursor.fetchone()[0]

        cursor.execute(f"SELECT COUNT(*) FROM findings f JOIN scans s ON s.id = f.scan_id WHERE 1=1 {finding_owner_clause}", owner_params)
        total_findings = cursor.fetchone()[0]

        cursor.execute(f"SELECT AVG(score) FROM scans s WHERE status = 'done' {owner_clause}", owner_params)
        avg_score = cursor.fetchone()[0] or 0

        # Répartition des risques
        cursor.execute(f"""
            SELECT risk_level, COUNT(*) as count 
            FROM scans s WHERE status = 'done' {owner_clause}
            GROUP BY risk_level
        """, owner_params)
        risk_distribution = {row[0]: row[1] for row in cursor.fetchall()}

        # Scans par statut
        cursor.execute(f"SELECT status, COUNT(*) FROM scans s WHERE 1=1 {owner_clause}", owner_params)
        status_counts = {row[0]: row[1] for row in cursor.fetchall()}

        # Top 5 des cibles les plus scannées
        cursor.execute(f"""
            SELECT target, COUNT(*) as count 
            FROM scans s WHERE 1=1 {owner_clause}
            GROUP BY target 
            ORDER BY count DESC LIMIT 5
        """, owner_params)
        top_targets = [{'target': decrypt(row[0]) if row[0] else 'unknown', 'count': row[1]} for row in cursor.fetchall()]

        # Évolution du score (30 derniers scans)
        cursor.execute(f"""
            SELECT score, started_at FROM scans s
            WHERE status = 'done' AND score IS NOT NULL {owner_clause}
            ORDER BY started_at DESC LIMIT 30
        """, owner_params)
        score_history = [
            {'score': row[0], 'date': row[1]}
            for row in reversed(cursor.fetchall())
        ]

        # Findings par OWASP ID
        cursor.execute(f"""
            SELECT owasp_id, COUNT(*) as count 
            FROM findings f JOIN scans s ON s.id = f.scan_id
            WHERE 1=1 {finding_owner_clause}
            GROUP BY owasp_id 
            ORDER BY count DESC
        """, owner_params)
        owasp_findings = [{'id': row[0], 'count': row[1]} for row in cursor.fetchall()]

        # Activité récente (10 dernières actions)
        recent_logs = audit.get_logs(limit=10, username_filter=None if is_admin_user() else current_user())
        recent_activity = [
            {
                'username': a.get('username'),
                'action': a.get('action'),
                'action_label': a.get('action_label'),
                'timestamp': a.get('timestamp'),
                'scan_id': a.get('scan_id'),
                'ip_address': a.get('ip_address'),
                'details': a.get('details')
            }
            for a in recent_logs
        ]

        conn.close()

        return jsonify({
            'total_scans': total_scans,
            'total_findings': total_findings,
            'avg_score': round(avg_score, 1),
            'risk_distribution': risk_distribution,
            'status_counts': status_counts,
            'top_targets': top_targets,
            'score_history': score_history,
            'owasp_findings': owasp_findings,
            'recent_activity': recent_activity
        }), 200
    except Exception as e:
        print(f"[-] Erreur /api/dashboard/stats : {str(e)}")
        return jsonify({'error': str(e)}), 500


# ─── AUDIT & COMPLIANCE ENDPOINTS ───────────────────────────────────────

@app.route('/api/audit/logs', methods=['GET'])
@login_required
def get_audit_logs():
    """Récupère les logs d'audit (admin only)"""
    if session.get('role') != 'admin':
        return jsonify({'error': 'Accès refusé.'}), 403

    try:
        page = request.args.get('page', 1, type=int)
        limit = request.args.get('limit', 50, type=int)
        offset = (page - 1) * limit
        action_filter = request.args.get('action')
        username_filter = request.args.get('username')

        logs = audit.get_logs(
            limit=limit, offset=offset,
            action_filter=action_filter,
            username_filter=username_filter
        )
        total = audit.count_logs(
            action_filter=action_filter,
            username_filter=username_filter
        )

        return jsonify({
            'logs': logs,
            'total': total,
            'page': page,
            'limit': limit
        }), 200
    except Exception as e:
        print(f"[-] Erreur /api/audit/logs : {str(e)}")
        return jsonify({'error': 'Erreur lors du chargement des logs'}), 500

@app.route('/api/audit/actions', methods=['GET'])
@login_required
def get_audit_actions():
    """Retourne la liste des types d'actions disponibles pour le filtre"""
    if session.get('role') != 'admin':
        return jsonify({'error': 'Accès refusé.'}), 403
    return jsonify(audit.ACTIONS), 200

@app.route('/api/gdpr/forget', methods=['POST'])
@login_required
def gdpr_forget():
    """
    RGPD — Right to be forgotten.
    Efface toutes les traces d'un utilisateur (admin only).
    """
    if session.get('role') != 'admin':
        return jsonify({'error': 'Accès refusé. Seul un admin peut effacer des données.'}), 403

    data = request.get_json()
    username = data.get('username', '').strip()

    if not username:
        return jsonify({'error': 'Nom d\'utilisateur requis.'}), 400

    # Sécurité : empêcher l'auto-effacement
    if username == session.get('username'):
        return jsonify({
            'error': 'Action impossible : vous ne pouvez pas effacer votre propre compte.'
        }), 400

    try:
        stats = audit.delete_user_data(username)
        return jsonify({
            'message': f'Données de "{username}" effacées avec succès.',
            'records_affected': stats
        }), 200
    except Exception as e:
        return jsonify({'error': f"Erreur lors de l'effacement : {str(e)}"}), 500


if __name__ == "__main__":
    app.run(debug=True, threaded=True, port=5000)
