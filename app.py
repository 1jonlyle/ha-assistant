import os
from datetime import datetime

import anthropic
import requests
from flask import Flask, jsonify, redirect, render_template_string, request, url_for
from flask_login import (LoginManager, UserMixin, current_user, login_required,
                         login_user, logout_user)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-key-change-me")

# Railway provides DATABASE_URL for Postgres; fall back to SQLite locally.
db_url = os.getenv("DATABASE_URL", "sqlite:///ha_assistant.db")
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    ha_url = db.Column(db.String(255))
    ha_token = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


with app.app_context():
    db.create_all()


# ---------------------------------------------------------------- templates

BASE_CSS = """
:root {
  --bg: #14171c; --panel: #1d2129; --panel2: #232833;
  --line: #313847; --text: #e8eaf0; --dim: #8b93a5;
  --accent: #ffb454; --accent-dark: #d99230; --err: #ff6b6b; --ok: #5dd39e;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background: var(--bg); color: var(--text); min-height: 100vh;
  font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
}
a { color: var(--accent); text-decoration: none; }
.card {
  background: var(--panel); border: 1px solid var(--line);
  border-radius: 10px; padding: 28px;
}
h1 { font-size: 22px; margin-bottom: 4px; }
.sub { color: var(--dim); font-size: 14px; margin-bottom: 22px; }
label { display: block; font-size: 13px; color: var(--dim); margin: 14px 0 5px; }
input, textarea {
  width: 100%; background: var(--panel2); border: 1px solid var(--line);
  border-radius: 6px; color: var(--text); padding: 10px 12px; font-size: 15px;
}
input:focus, textarea:focus { outline: 2px solid var(--accent); outline-offset: -1px; }
button {
  background: var(--accent); color: #14171c; border: 0; border-radius: 6px;
  padding: 11px 18px; font-size: 15px; font-weight: 600; cursor: pointer;
  margin-top: 18px;
}
button:hover { background: var(--accent-dark); }
.error { color: var(--err); font-size: 14px; margin-top: 12px; }
.ok { color: var(--ok); font-size: 14px; margin-top: 12px; }
"""

AUTH_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ 'Log in' if is_login else 'Sign up' }} — HA Assistant</title>
<style>""" + BASE_CSS + """
body { display: flex; align-items: center; justify-content: center; }
.card { width: 100%; max-width: 380px; }
.brand { color: var(--accent); font-weight: 700; letter-spacing: 1px;
  font-size: 13px; text-transform: uppercase; margin-bottom: 10px; }
.swap { margin-top: 18px; font-size: 14px; color: var(--dim); }
</style>
</head>
<body>
<div class="card">
  <div class="brand">HA Assistant</div>
  <h1>{{ 'Welcome back' if is_login else 'Create your account' }}</h1>
  <div class="sub">Your Home Assistant, in plain English.</div>
  <form method="POST">
    <label for="username">Username</label>
    <input id="username" name="username" required autocomplete="username">
    {% if not is_login %}
    <label for="email">Email</label>
    <input id="email" name="email" type="email" required autocomplete="email">
    {% endif %}
    <label for="password">Password</label>
    <input id="password" name="password" type="password" required
      autocomplete="{{ 'current-password' if is_login else 'new-password' }}">
    {% if not is_login %}
    <label for="confirm">Confirm password</label>
    <input id="confirm" name="confirm" type="password" required autocomplete="new-password">
    {% endif %}
    {% if error %}<div class="error">{{ error }}</div>{% endif %}
    <button type="submit">{{ 'Log in' if is_login else 'Sign up' }}</button>
  </form>
  <div class="swap">
    {% if is_login %}
      No account yet? <a href="{{ url_for('signup') }}">Sign up</a>
    {% else %}
      Already registered? <a href="{{ url_for('login') }}">Log in</a>
    {% endif %}
  </div>
</div>
</body>
</html>
"""

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HA Assistant</title>
<style>""" + BASE_CSS + """
header {
  display: flex; align-items: center; justify-content: space-between;
  padding: 14px 24px; border-bottom: 1px solid var(--line); background: var(--panel);
}
header .brand { color: var(--accent); font-weight: 700; letter-spacing: 1px;
  font-size: 13px; text-transform: uppercase; }
header form { display: inline; }
header button { margin: 0; padding: 7px 14px; font-size: 13px;
  background: var(--panel2); color: var(--dim); border: 1px solid var(--line); }
header button:hover { color: var(--text); }
main { max-width: 860px; margin: 0 auto; padding: 24px 16px 60px; }
#setup-card { margin-bottom: 24px; }
.status { display: inline-block; font-size: 12px; padding: 3px 10px;
  border-radius: 20px; margin-left: 10px; vertical-align: middle; }
.status.on { background: rgba(93,211,158,.15); color: var(--ok); }
.status.off { background: rgba(255,107,107,.15); color: var(--err); }
#chat-box { height: 55vh; overflow-y: auto; padding: 16px;
  background: var(--panel2); border: 1px solid var(--line);
  border-radius: 8px; margin-bottom: 12px; }
.msg { max-width: 85%; padding: 10px 14px; border-radius: 10px;
  margin-bottom: 10px; font-size: 15px; line-height: 1.5;
  white-space: pre-wrap; word-wrap: break-word; }
.msg.user { background: var(--accent); color: #14171c; margin-left: auto; }
.msg.claude { background: var(--panel); border: 1px solid var(--line); }
.msg pre { background: #0e1116; border-radius: 6px; padding: 10px;
  overflow-x: auto; margin: 8px 0; font-size: 13px; }
.chat-row { display: flex; gap: 10px; }
.chat-row textarea { resize: none; height: 52px; }
.chat-row button { margin: 0; white-space: nowrap; }
.hint { color: var(--dim); font-size: 13px; margin-top: 10px; }
details summary { cursor: pointer; color: var(--dim); font-size: 14px; }
</style>
</head>
<body>
<header>
  <div class="brand">HA Assistant</div>
  <div>
    <span style="color:var(--dim);font-size:14px;margin-right:12px;">{{ username }}</span>
    <form method="POST" action="{{ url_for('logout') }}"><button>Log out</button></form>
  </div>
</header>
<main>
  <div class="card" id="setup-card">
    <details {{ '' if configured else 'open' }}>
      <summary>
        Home Assistant connection
        <span class="status {{ 'on' if configured else 'off' }}" id="ha-status">
          {{ 'Connected' if configured else 'Not connected' }}
        </span>
      </summary>
      <label for="ha-url">Home Assistant URL</label>
      <input id="ha-url" placeholder="http://homeassistant.local:8123" value="{{ ha_url }}">
      <label for="ha-token">Long-lived access token</label>
      <input id="ha-token" type="password" placeholder="Paste your token">
      <div class="hint">In Home Assistant: your profile &rarr; Security &rarr;
        Long-lived access tokens &rarr; Create token.</div>
      <button onclick="saveHA()">Save &amp; test connection</button>
      <div id="setup-msg"></div>
    </details>
  </div>

  <div id="chat-box">
    <div class="msg claude">Hey! Tell me what you want your Home Assistant to do
&mdash; a dashboard, an automation, an integration &mdash; and I'll build the config for you.

Try: "Build me a dashboard for my living room lights and thermostat."</div>
  </div>
  <div class="chat-row">
    <textarea id="chat-input" placeholder="Describe what you want..."></textarea>
    <button onclick="sendMsg()" id="send-btn">Send</button>
  </div>
</main>

<script>
const history = [];

function addMsg(text, who) {
  const box = document.getElementById('chat-box');
  const div = document.createElement('div');
  div.className = 'msg ' + who;
  // Render fenced code blocks as <pre>, escape everything else.
  const esc = s => s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  const parts = text.split(/```(?:yaml|json|python)?\\n?/);
  let html = '';
  parts.forEach((p, i) => {
    html += (i % 2 === 1) ? '<pre>' + esc(p) + '</pre>' : esc(p);
  });
  div.innerHTML = html;
  box.appendChild(div);
  box.scrollTop = box.scrollHeight;
}

async function sendMsg() {
  const input = document.getElementById('chat-input');
  const btn = document.getElementById('send-btn');
  const text = input.value.trim();
  if (!text) return;
  addMsg(text, 'user');
  history.push({role: 'user', content: text});
  input.value = '';
  btn.disabled = true;
  btn.textContent = '...';
  try {
    const res = await fetch('/api/chat', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({messages: history})
    });
    const data = await res.json();
    if (data.error) {
      addMsg('Error: ' + data.error, 'claude');
    } else {
      addMsg(data.response, 'claude');
      history.push({role: 'assistant', content: data.response});
    }
  } catch (e) {
    addMsg('Network error: ' + e.message, 'claude');
  }
  btn.disabled = false;
  btn.textContent = 'Send';
}

document.getElementById('chat-input').addEventListener('keydown', e => {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMsg(); }
});

async function saveHA() {
  const msg = document.getElementById('setup-msg');
  msg.className = ''; msg.textContent = 'Testing connection...';
  try {
    const res = await fetch('/api/setup-ha', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        ha_url: document.getElementById('ha-url').value.trim(),
        ha_token: document.getElementById('ha-token').value.trim()
      })
    });
    const data = await res.json();
    if (data.success) {
      msg.className = 'ok'; msg.textContent = 'Connected!';
      const st = document.getElementById('ha-status');
      st.className = 'status on'; st.textContent = 'Connected';
    } else {
      msg.className = 'error'; msg.textContent = data.error || 'Connection failed';
    }
  } catch (e) {
    msg.className = 'error'; msg.textContent = e.message;
  }
}
</script>
</body>
</html>
"""


# ------------------------------------------------------------------- routes

@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        user = User.query.filter_by(username=request.form.get("username", "").strip()).first()
        if user and check_password_hash(user.password, request.form.get("password", "")):
            login_user(user)
            return redirect(url_for("dashboard"))
        error = "Invalid username or password."
    return render_template_string(AUTH_TEMPLATE, is_login=True, error=error)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        if password != request.form.get("confirm", ""):
            error = "Passwords do not match."
        elif len(password) < 8:
            error = "Password must be at least 8 characters."
        elif User.query.filter((User.username == username) | (User.email == email)).first():
            error = "Username or email already registered."
        else:
            user = User(username=username, email=email,
                        password=generate_password_hash(password))
            db.session.add(user)
            db.session.commit()
            login_user(user)
            return redirect(url_for("dashboard"))
    return render_template_string(AUTH_TEMPLATE, is_login=False, error=error)


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template_string(
        DASHBOARD_TEMPLATE,
        username=current_user.username,
        configured=bool(current_user.ha_token),
        ha_url=current_user.ha_url or "",
    )


@app.route("/api/setup-ha", methods=["POST"])
@login_required
def setup_ha():
    data = request.json or {}
    ha_url = (data.get("ha_url") or "").rstrip("/")
    ha_token = data.get("ha_token") or ""
    if not ha_url or not ha_token:
        return jsonify({"success": False, "error": "URL and token are both required."})
    try:
        r = requests.get(f"{ha_url}/api/",
                         headers={"Authorization": f"Bearer {ha_token}"}, timeout=8)
        if r.status_code == 200:
            current_user.ha_url = ha_url
            current_user.ha_token = ha_token
            db.session.commit()
            return jsonify({"success": True})
        return jsonify({"success": False,
                        "error": f"Home Assistant said no (HTTP {r.status_code}). Check the token."})
    except requests.exceptions.RequestException as e:
        return jsonify({"success": False, "error": f"Could not reach that URL: {e}"})


SYSTEM_PROMPT = """You are an expert Home Assistant assistant for everyday users \
who don't know YAML. When the user describes what they want:

1. Ask at most one clarifying question if truly needed; otherwise just build it.
2. Generate valid, complete YAML for dashboards (Lovelace), automations, or blueprints.
3. Wrap all YAML in ```yaml fences.
4. After the YAML, give short numbered steps for pasting it into Home Assistant \
(Settings > Dashboards > Raw configuration editor for dashboards; \
Settings > Automations > Create > Edit in YAML for automations).

Keep the tone friendly and plain-English. Never assume entity IDs \
the user hasn't given you; use obvious placeholders like light.living_room \
and tell the user to swap in their real entity names."""


@app.route("/api/chat", methods=["POST"])
@login_required
def chat():
    if not current_user.ha_token:
        return jsonify({"error": "Connect your Home Assistant first (panel above)."})
    messages = (request.json or {}).get("messages") or []
    if not messages:
        return jsonify({"error": "Empty message."})
    try:
        client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
        resp = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=2000,
            system=SYSTEM_PROMPT,
            messages=messages[-20:],  # keep the last 20 turns for context
        )
        text = "".join(b.text for b in resp.content if b.type == "text")
        return jsonify({"response": text})
    except Exception as e:
        return jsonify({"error": str(e)})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=False)
