import logging
import os
import secrets
from datetime import datetime, timedelta

import anthropic
import requests
from cryptography.fernet import Fernet, InvalidToken
from flask import Flask, jsonify, redirect, render_template_string, request, url_for
from flask_login import (LoginManager, UserMixin, current_user, login_required,
                         login_user, logout_user)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

# --- SECRET_KEY: required in production, ephemeral fallback only in debug ---
_secret = os.getenv("SECRET_KEY")
_debug_mode = os.getenv("DEBUG") == "1" or os.getenv("FLASK_ENV") == "development"
if not _secret:
    if _debug_mode:
        _secret = secrets.token_hex(32)
        logging.warning("SECRET_KEY not set; using an ephemeral key because DEBUG=1. "
                        "Sessions will NOT survive a restart.")
    else:
        raise RuntimeError("SECRET_KEY environment variable is required in production. "
                           "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\"")
app.config["SECRET_KEY"] = _secret

# --- Token encryption at rest: Fernet key is mandatory, no silent fallback ---
_enc_key = os.getenv("TOKEN_ENC_KEY")
if not _enc_key:
    raise RuntimeError("TOKEN_ENC_KEY environment variable is required (base64 Fernet key). "
                       "Generate one with: python -c \"from cryptography.fernet import Fernet; "
                       "print(Fernet.generate_key().decode())\"")
try:
    _fernet = Fernet(_enc_key.encode())
except Exception as e:
    raise RuntimeError(f"TOKEN_ENC_KEY is not a valid Fernet key: {e}")


def encrypt_token(plaintext: str) -> str:
    """Encrypt a Home Assistant token for storage."""
    return _fernet.encrypt(plaintext.encode()).decode()


def decrypt_token(ciphertext: str) -> str:
    """Decrypt a stored HA token. Legacy plaintext rows (pre-encryption) are
    returned unchanged; they get re-encrypted the next time the user saves."""
    if not ciphertext:
        return ciphertext
    try:
        return _fernet.decrypt(ciphertext.encode()).decode()
    except InvalidToken:
        return ciphertext

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
    ha_token = db.Column(db.String(1000))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class PasswordReset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    token = db.Column(db.String(64), unique=True, nullable=False)
    expires = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


with app.app_context():
    db.create_all()
    # Existing deployments created ha_token as VARCHAR(500); widen it for
    # encrypted values. Harmless no-op where unsupported (e.g. SQLite).
    try:
        db.session.execute(text('ALTER TABLE "user" ALTER COLUMN ha_token TYPE VARCHAR(1000)'))
        db.session.commit()
    except Exception:
        db.session.rollback()


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
      &nbsp;&middot;&nbsp; <a href="{{ url_for('forgot') }}">Forgot password?</a>
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
#mic-btn { background: var(--panel2); border: 1px solid var(--line); font-size: 18px; }
#mic-btn.listening { background: var(--err); animation: pulse 1.2s infinite; }
@keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: .55; } }
@media (prefers-reduced-motion: reduce) { #mic-btn.listening { animation: none; } }
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
    <button onclick="toggleVoice()" id="mic-btn" title="Speak instead of typing">&#127908;</button>
    <button onclick="sendMsg()" id="send-btn">Send</button>
  </div>
  <div class="hint">
    <label style="display:inline;cursor:pointer;">
      <input type="checkbox" id="voice-mode" style="width:auto;vertical-align:middle;" onchange="voiceModeChanged()">
      Voice chat &mdash; I'll talk back and keep listening, hands-free
    </label>
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
  if (window.speechSynthesis) speechSynthesis.cancel();
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
      speak(data.response);
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

// --- Voice input (browser speech recognition, free) ---
let recog = null, listening = false;
const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
if (!SR) {
  const mb = document.getElementById('mic-btn');
  mb.disabled = true;
  mb.title = 'Voice input needs Chrome or Edge';
}

function toggleVoice() {
  const mb = document.getElementById('mic-btn');
  const input = document.getElementById('chat-input');
  if (listening) { recog.stop(); return; }
  recog = new SR();
  recog.lang = 'en-US';
  recog.interimResults = true;
  recog.continuous = false;
  const before = input.value ? input.value + ' ' : '';
  recog.onresult = e => {
    let text = '';
    for (const r of e.results) text += r[0].transcript;
    input.value = before + text;
  };
  recog.onstart = () => { listening = true; mb.classList.add('listening'); };
  recog.onend = () => {
    listening = false; mb.classList.remove('listening');
    if (input.value.trim()) sendMsg();
  };
  recog.onerror = e => {
    listening = false; mb.classList.remove('listening');
    if (e.error === 'not-allowed') alert('Allow microphone access in your browser to use voice.');
  };
  recog.start();
}

// --- Voice chat (text-to-speech + hands-free loop) ---
function voiceOn() { return document.getElementById('voice-mode').checked; }

function voiceModeChanged() {
  if (!voiceOn()) { speechSynthesis.cancel(); if (listening && recog) recog.stop(); }
}

function speak(text) {
  if (!voiceOn() || !window.speechSynthesis) return;
  // Don't read code blocks aloud; mention them instead.
  const spoken = text
    .split(/```[\\s\\S]*?```/).join(' ... the config is in the chat ... ')
    .replace(/[*#`_]/g, '')
    .replace(/\\[Actions taken:.*?\\]/g, '')
    .trim();
  if (!spoken) return;
  speechSynthesis.cancel();
  const u = new SpeechSynthesisUtterance(spoken.slice(0, 1200));
  u.rate = 1.05;
  u.onend = () => {
    // Hands-free: after speaking, listen for the user's next request.
    if (voiceOn() && SR && !listening) toggleVoice();
  };
  speechSynthesis.speak(u);
}

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


# ------------------------------------------------------------ password reset

RESET_REQUEST_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Reset password — HA Assistant</title>
<style>""" + BASE_CSS + """
body { display: flex; align-items: center; justify-content: center; }
.card { width: 100%; max-width: 380px; }
</style></head>
<body>
<div class="card">
  <h1>{{ 'Set a new password' if token else 'Reset your password' }}</h1>
  <div class="sub">{{ 'Choose a new password for your account.' if token
      else "Enter your account email and we'll send you a reset link." }}</div>
  <form method="POST">
    {% if token %}
      <label for="password">New password</label>
      <input id="password" name="password" type="password" required autocomplete="new-password">
      <label for="confirm">Confirm new password</label>
      <input id="confirm" name="confirm" type="password" required autocomplete="new-password">
    {% else %}
      <label for="email">Email</label>
      <input id="email" name="email" type="email" required autocomplete="email">
    {% endif %}
    {% if error %}<div class="error">{{ error }}</div>{% endif %}
    {% if message %}<div class="ok">{{ message }}</div>{% endif %}
    <button type="submit">{{ 'Save new password' if token else 'Send reset link' }}</button>
  </form>
  <div style="margin-top:18px;font-size:14px;"><a href="{{ url_for('login') }}">Back to log in</a></div>
</div>
</body></html>
"""


def send_reset_email(to_email, reset_link):
    """Send the reset link via SendGrid. Returns True on success."""
    api_key = os.getenv("SENDGRID_API_KEY")
    from_email = os.getenv("FROM_EMAIL")
    if not api_key or not from_email:
        app.logger.error("SENDGRID_API_KEY or FROM_EMAIL not set")
        return False
    payload = {
        "personalizations": [{"to": [{"email": to_email}]}],
        "from": {"email": from_email, "name": "HA Assistant"},
        "subject": "Reset your HA Assistant password",
        "content": [{
            "type": "text/plain",
            "value": ("Someone (hopefully you) asked to reset your HA Assistant "
                      f"password.\n\nReset it here (link is good for 1 hour):\n{reset_link}\n\n"
                      "If you didn't ask for this, ignore this email."),
        }],
    }
    try:
        r = requests.post("https://api.sendgrid.com/v3/mail/send",
                          headers={"Authorization": f"Bearer {api_key}",
                                   "Content-Type": "application/json"},
                          json=payload, timeout=10)
        if r.status_code == 202:
            return True
        app.logger.error("SendGrid error %s: %s", r.status_code, r.text[:300])
        return False
    except requests.exceptions.RequestException as e:
        app.logger.error("SendGrid request failed: %s", e)
        return False


@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    message = error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = User.query.filter(db.func.lower(User.email) == email).first()
        if user:
            token = secrets.token_urlsafe(32)
            db.session.add(PasswordReset(user_id=user.id, token=token,
                                         expires=datetime.utcnow() + timedelta(hours=1)))
            db.session.commit()
            link = request.host_url.rstrip("/") + url_for("reset_password", token=token)
            if not send_reset_email(user.email, link):
                error = "Couldn't send the email right now. Try again in a few minutes."
        if not error:
            # Same message whether or not the account exists (don't leak emails).
            message = "If that email has an account, a reset link is on its way."
    return render_template_string(RESET_REQUEST_TEMPLATE, token=None,
                                  message=message, error=error)


@app.route("/reset/<token>", methods=["GET", "POST"])
def reset_password(token):
    pr = PasswordReset.query.filter_by(token=token, used=False).first()
    if not pr or pr.expires < datetime.utcnow():
        return render_template_string(RESET_REQUEST_TEMPLATE, token=None, message=None,
                                      error="That reset link is expired or already used. Request a new one.")
    error = None
    if request.method == "POST":
        password = request.form.get("password", "")
        if password != request.form.get("confirm", ""):
            error = "Passwords do not match."
        elif len(password) < 8:
            error = "Password must be at least 8 characters."
        else:
            user = db.session.get(User, pr.user_id)
            user.password = generate_password_hash(password)
            pr.used = True
            db.session.commit()
            login_user(user)
            return redirect(url_for("dashboard"))
    return render_template_string(RESET_REQUEST_TEMPLATE, token=token,
                                  message=None, error=error)


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
            current_user.ha_token = encrypt_token(ha_token)
            db.session.commit()
            return jsonify({"success": True})
        return jsonify({"success": False,
                        "error": f"Home Assistant said no (HTTP {r.status_code}). Check the token."})
    except requests.exceptions.RequestException as e:
        return jsonify({"success": False, "error": f"Could not reach that URL: {e}"})


SYSTEM_PROMPT = """You are an expert Home Assistant assistant for everyday users \
who don't know YAML. You are connected to the user's real Home Assistant instance.

You have tools to list their real entities, read states, and create automations \
directly on their system. Use them:
- ALWAYS call list_entities before writing any config, so you use their real \
entity IDs instead of placeholders.
- When the user asks for an automation, build it and deploy it with \
create_automation, then confirm what you created in plain English.
- Dashboards can't be deployed automatically yet: generate the dashboard YAML \
in a ```yaml fence and give short numbered steps \
(Settings > Dashboards > pencil icon > three-dot menu > Raw configuration editor).

Keep the tone friendly and plain-English. Confirm before creating anything \
destructive or that replaces an existing automation."""

HA_TOOLS = [
    {
        "name": "list_entities",
        "description": ("List the user's Home Assistant entities. Returns entity_id, "
                        "friendly name, and current state. Optionally filter by domain "
                        "(e.g. 'light', 'sensor', 'switch', 'climate') or a search word."),
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Optional domain filter, e.g. 'light'"},
                "search": {"type": "string", "description": "Optional keyword to match in entity id or name"},
            },
        },
    },
    {
        "name": "get_state",
        "description": "Get the full state and attributes of one entity by entity_id.",
        "input_schema": {
            "type": "object",
            "properties": {"entity_id": {"type": "string"}},
            "required": ["entity_id"],
        },
    },
    {
        "name": "create_automation",
        "description": ("Create (or overwrite) an automation on the user's Home Assistant. "
                        "Provide a unique snake_case automation_id and the automation config "
                        "as JSON with alias, trigger, condition (optional), and action."),
        "input_schema": {
            "type": "object",
            "properties": {
                "automation_id": {"type": "string", "description": "snake_case id, e.g. 'garage_lights_on_arrival'"},
                "config": {"type": "object", "description": "Automation config: alias, description, trigger, condition, action, mode"},
            },
            "required": ["automation_id", "config"],
        },
    },
]


def _ha_headers(user):
    return {"Authorization": f"Bearer {decrypt_token(user.ha_token)}",
            "Content-Type": "application/json"}


def run_ha_tool(user, name, tool_input):
    """Execute a tool call against the user's Home Assistant. Returns a string result."""
    base = user.ha_url
    try:
        if name == "list_entities":
            r = requests.get(f"{base}/api/states", headers=_ha_headers(user), timeout=10)
            r.raise_for_status()
            states = r.json()
            domain = (tool_input.get("domain") or "").lower().strip()
            search = (tool_input.get("search") or "").lower().strip()
            rows = []
            for s in states:
                eid = s.get("entity_id", "")
                fname = (s.get("attributes") or {}).get("friendly_name", "")
                if domain and not eid.startswith(domain + "."):
                    continue
                if search and search not in eid.lower() and search not in fname.lower():
                    continue
                rows.append(f"{eid} | {fname} | {s.get('state')}")
            if not rows:
                return "No matching entities found."
            return "\n".join(rows[:400])

        if name == "get_state":
            eid = tool_input.get("entity_id", "")
            r = requests.get(f"{base}/api/states/{eid}", headers=_ha_headers(user), timeout=10)
            if r.status_code == 404:
                return f"Entity {eid} not found."
            r.raise_for_status()
            return str(r.json())

        if name == "create_automation":
            aid = tool_input.get("automation_id", "").strip()
            config = tool_input.get("config") or {}
            if not aid or not config:
                return "Error: automation_id and config are both required."
            config.setdefault("alias", aid.replace("_", " ").title())
            r = requests.post(f"{base}/api/config/automation/config/{aid}",
                              headers=_ha_headers(user), json=config, timeout=15)
            if r.status_code in (200, 201):
                # Reload automations so it takes effect immediately.
                requests.post(f"{base}/api/services/automation/reload",
                              headers=_ha_headers(user), timeout=10)
                return f"Automation '{aid}' created and loaded successfully."
            return (f"Home Assistant rejected it (HTTP {r.status_code}): {r.text[:300]}. "
                    "Note: this requires the config integration (enabled by default "
                    "unless the user runs YAML-only automations).")

        return f"Unknown tool: {name}"
    except requests.exceptions.RequestException as e:
        return f"Could not reach Home Assistant: {e}"


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
        convo = list(messages[-20:])  # keep the last 20 turns for context
        actions = []

        for _ in range(6):  # allow up to 6 tool round-trips per user message
            resp = client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=2500,
                system=SYSTEM_PROMPT,
                tools=HA_TOOLS,
                messages=convo,
            )
            if resp.stop_reason != "tool_use":
                text = "".join(b.text for b in resp.content if b.type == "text")
                if actions:
                    text += "\n\n[Actions taken: " + "; ".join(actions) + "]"
                return jsonify({"response": text})

            # Execute every tool call in this turn, then continue the loop.
            convo.append({"role": "assistant", "content": resp.content})
            results = []
            for block in resp.content:
                if block.type == "tool_use":
                    result = run_ha_tool(current_user, block.name, block.input or {})
                    if block.name == "create_automation" and "successfully" in result:
                        actions.append(f"created automation '{(block.input or {}).get('automation_id')}'")
                    results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result,
                    })
            convo.append({"role": "user", "content": results})

        return jsonify({"response": "That took too many steps — try breaking the request into smaller pieces."})
    except Exception as e:
        return jsonify({"error": str(e)})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=False)
