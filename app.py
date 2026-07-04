from flask import Flask, render_template_string, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import anthropic
import requests
import os
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///ha_assistant.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

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
    return User.query.get(int(user_id))

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        return jsonify({'error': 'Invalid credentials'}), 401
    
    html = '''
    <!DOCTYPE html>
    
    '''
    return render_template_string(html)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm = request.form.get('confirm')
        
        if password != confirm:
            return jsonify({'error': 'Passwords do not match'}), 400
        
        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username exists'}), 400
        
        user = User(
            username=username,
            email=email,
            password=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for('dashboard'))
    
    html = '''
    <!DOCTYPE html>
    
    '''
    return render_template_string(html)

@app.route('/dashboard')
@login_required
def dashboard():
    html = '''
    <!DOCTYPE html>
    
    '''
    return render_template_string(html)

@app.route('/api/ha-status')
@login_required
def ha_status():
    return jsonify({'configured': bool(current_user.ha_token)})

@app.route('/api/setup-ha', methods=['POST'])
@login_required
def setup_ha():
    data = request.json
    ha_url = data.get('ha_url')
    ha_token = data.get('ha_token')
    
    try:
        headers = {'Authorization': f'Bearer {ha_token}'}
        response = requests.get(f'{ha_url}/api/', headers=headers, timeout=5)
        
        if response.status_code == 200:
            current_user.ha_url = ha_url
            current_user.ha_token = ha_token
            db.session.commit()
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'Auth failed'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/chat', methods=['POST'])
@login_required
def chat():
    if not current_user.ha_token:
        return jsonify({'error': 'HA not configured'})
    
    user_message = request.json.get('message')
    
    try:
        client = anthropic.Anthropic(api_key=os.getenv('ANTHROPIC_API_KEY'))
        
        system = """You are a Home Assistant expert. Help users create dashboards and blueprints by generating YAML config. 
Keep responses concise and actionable. Always wrap YAML in ```yaml``` blocks."""
        
        response = client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=1000,
            system=system,
            messages=[{'role': 'user', 'content': user_message}]
        )
        
        return jsonify({'response': response.content[0].text})
    except Exception as e:
        return jsonify({'error': str(e)})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=False, host='0.0.0.0', port=int(os...
