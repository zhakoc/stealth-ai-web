import os, json, sqlite3, secrets, datetime
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import bcrypt

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")
CONFIG = os.environ.get("CONFIG_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json"))

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@app.errorhandler(500)
def internal_error(e):
    return render_template("login.html", error="Sunucu hatasi, tekrar deneyin."), 500

@app.errorhandler(404)
def not_found(e):
    return render_template("login.html", error="Sayfa bulunamadi."), 404

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        full_name TEXT DEFAULT '',
        ip_address TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_admin INTEGER DEFAULT 0,
        terms_accepted INTEGER DEFAULT 0
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS activity_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT,
        ip_address TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    conn.commit()
    conn.close()

class User(UserMixin):
    def __init__(self, id, username, email, full_name, is_admin):
        self.id = id
        self.username = username
        self.email = email
        self.full_name = full_name
        self.is_admin = is_admin

@login_manager.user_loader
def load_user(user_id):
    conn = get_db()
    u = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    if u: return User(u["id"], u["username"], u["email"], u["full_name"], u["is_admin"])
    return None

@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","").encode()
        conn = get_db()
        u = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if u and bcrypt.checkpw(password, u["password"]):
            user = User(u["id"], u["username"], u["email"], u["full_name"], u["is_admin"])
            login_user(user, remember=True)
            ip = request.remote_addr
            conn.execute("UPDATE users SET last_login=?, ip_address=? WHERE id=?", (datetime.datetime.now(), ip, u["id"]))
            conn.execute("INSERT INTO activity_log (user_id, action, ip_address) VALUES (?, 'login', ?)", (u["id"], ip))
            conn.commit(); conn.close()
            return redirect(url_for("dashboard"))
        conn.close()
        return render_template("login.html", error="Kullanici adi veya sifre hatali!")
    return render_template("login.html")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        email = request.form.get("email","").strip()
        full_name = request.form.get("full_name","").strip()
        password = request.form.get("password","").encode()
        password2 = request.form.get("password2","").encode()
        terms = request.form.get("terms")
        if not terms:
            return render_template("register.html", error="Sozlesmeyi kabul etmelisiniz!")
        if password != password2:
            return render_template("register.html", error="Sifreler eslesmiyor!")
        if len(password) < 6:
            return render_template("register.html", error="Sifre en az 6 karakter olmali!")
        hashed = bcrypt.hashpw(password, bcrypt.gensalt())
        ip = request.remote_addr
        conn = get_db()
        try:
            conn.execute("INSERT INTO users (username, email, password, full_name, ip_address, terms_accepted) VALUES (?,?,?,?,?,1)",
                        (username, email, hashed, full_name, ip))
            conn.commit()
            count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            if count == 1:
                conn.execute("UPDATE users SET is_admin=1 WHERE username=?", (username,))
                conn.commit()
            conn.close()
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            conn.close()
            return render_template("register.html", error="Kullanici adi veya e-posta zaten kayitli!")
    return render_template("register.html")

@app.route("/logout")
@login_required
def logout():
    conn = get_db()
    ip = request.remote_addr
    conn.execute("INSERT INTO activity_log (user_id, action, ip_address) VALUES (?, 'logout', ?)", (current_user.id, ip))
    conn.commit(); conn.close()
    logout_user()
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    if not current_user.is_admin:
        return redirect(url_for("chat"))
    conn = get_db()
    users = conn.execute("SELECT id, username, email, full_name, ip_address, is_admin, created_at, last_login, terms_accepted FROM users ORDER BY last_login DESC").fetchall()
    logs = conn.execute("SELECT a.*, u.username FROM activity_log a LEFT JOIN users u ON a.user_id=u.id ORDER BY a.timestamp DESC LIMIT 20").fetchall()
    online = conn.execute("SELECT id, username, email, ip_address, last_login FROM users WHERE last_login > datetime('now', '-10 minutes')").fetchall()
    conn.close()
    return render_template("dashboard.html", users=users, logs=logs, online=online)

@app.route("/chat")
@login_required
def chat():
    return render_template("chat.html")

@app.route("/privacy")
def privacy():
    return render_template("privacy.html")

@app.route("/terms")
def terms():
    return render_template("terms.html")

@app.route("/api/status")
@login_required
def api_status():
    c = {}
    if os.path.exists(CONFIG):
        with open(CONFIG,"r") as f: c = json.load(f)
    has_key = bool(c.get("or_key","").startswith("sk-or")) or bool(c.get("api_key","").startswith("AQ"))
    return jsonify({"model": c.get("model","bilinmiyor"), "api_ok": has_key})

@app.route("/api/chat", methods=["POST"])
@login_required
def api_chat():
    data = request.json
    msg = data.get("message","")
    if not msg: return jsonify({"error": "Mesaj bos"}), 400
    c = {}
    if os.path.exists(CONFIG):
        with open(CONFIG, "r") as f: c = json.load(f)
    import urllib.request, urllib.error, time
    providers = []
    ork = c.get("or_key","")
    if ork:
        providers.append({"name":"openrouter","key":ork,"model":"xiaomi/mimo-v2-flash:free",
                         "url":"https://openrouter.ai/api/v1/chat/completions","type":"openai"})
    if c.get("api_key","").startswith("AQ"):
        providers.append({"name":"google","key":c["api_key"],"model":"gemini-3.6-flash",
                         "url":f"https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent?key={c['api_key']}","type":"google"})
    sys_t = "Sen stealtH AI asistanisin. Turkce konus. Emoji kullanarak konus. Konusurken kendi goruslerini de ekle."
    cs = [{"role":"user","parts":[{"text":"[SYS]"+sys_t}]},
          {"role":"model","parts":[{"text":"Anladim!"}]},
          {"role":"user","parts":[{"text":msg}]}]
    for prov in providers:
        for attempt in range(3):
            try:
                if prov["type"] == "google":
                    body = json.dumps({"contents":cs,"generationConfig":{"maxOutputTokens":2000,"temperature":0.8}}).encode()
                    req = urllib.request.Request(prov["url"], data=body, headers={"Content-Type":"application/json"})
                    resp = urllib.request.urlopen(req, timeout=60)
                    reply = json.loads(resp.read())["candidates"][0]["content"]["parts"][0]["text"]
                else:
                    messages = [{"role":"system","content":cs[0]["parts"][0]["text"]}]
                    for m in cs[2:]: messages.append({"role":m["role"],"content":m["parts"][0]["text"]})
                    body = json.dumps({"model":prov["model"],"messages":messages,"max_tokens":2000,"temperature":0.8}).encode()
                    req = urllib.request.Request(prov["url"], data=body, headers={"Content-Type":"application/json","Authorization":f"Bearer {prov['key']}","HTTP-Referer":"https://stealth-ai.com","X-Title":"stealtH AI"})
                    resp = urllib.request.urlopen(req, timeout=60)
                    reply = json.loads(resp.read())["choices"][0]["message"]["content"]
                return jsonify({"reply": reply, "provider": prov["name"]})
            except urllib.error.HTTPError as e:
                if e.code in (503,429) and attempt < 2: time.sleep(3); continue
                break
            except: break
    return jsonify({"error": "API'ler calismadi. OpenRouter key gerekli."}), 500

@app.route("/settings", methods=["GET","POST"])
@login_required
def settings():
    if not current_user.is_admin:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        c = {}
        if os.path.exists(CONFIG):
            with open(CONFIG,"r") as f: c = json.load(f)
        c["api_key"] = request.form.get("api_key","").strip()
        c["or_key"] = request.form.get("or_key","").strip()
        c["model"] = request.form.get("model","xiaomi/mimo-v2-flash:free").strip()
        c["workspace"] = request.form.get("workspace","").strip()
        with open(CONFIG,"w") as f: json.dump(c, f, indent=2, ensure_ascii=False)
        return render_template("settings.html", success="Ayarlar kaydedildi!", config=c)
    c = {}
    if os.path.exists(CONFIG):
        with open(CONFIG,"r") as f: c = json.load(f)
    return render_template("settings.html", config=c)

if __name__ == "__main__":
    init_db()
    print("=" * 50)
    print("  stealtH AI Web Dashboard")
    print("  http://localhost:5000")
    print("=" * 50)
    app.run(host="0.0.0.0", port=5000, debug=False)
