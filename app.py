# Aether76 AI - Web App buatan Rhadit Satya.W

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, abort # type: ignore
from flask_sqlalchemy import SQLAlchemy # type: ignore
from werkzeug.security import generate_password_hash, check_password_hash # type: ignore # type: ignore
from flask_wtf.csrf import CSRFProtect # type: ignore
from markupsafe import escape # type: ignore
from functools import wraps
from dotenv import load_dotenv # type: ignore
import openai # type: ignore
import os
import re

# Load API Key dari .env
load_dotenv()
openai.api_key = os.getenv('OPENAI_API_KEY')

# Inisialisasi aplikasi
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-aether76-ai-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///aether76ai.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

csrf = CSRFProtect(app)
db = SQLAlchemy(app)
URL_PREFIX = "/nex76"

# ---------- MODEL ----------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

# ---------- UTILS ----------
def sanitize_input(text):
    return escape(text)

def allowed_mime_type(mimetype):
    allowed = ['text/plain', 'application/json']
    return mimetype in allowed

def valid_username(username):
    return re.fullmatch(r'^\w{3,20}$', username)

def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapped

# ---------- ROUTES ----------
@app.route('/')
def root():
    return redirect(URL_PREFIX + '/login')

@app.route(f'{URL_PREFIX}/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', '').strip())
        password = request.form.get('password', '')

        if not valid_username(username):
            return render_template('register.html', error="Username tidak valid")
        if len(password) < 6:
            return render_template('register.html', error="Password minimal 6 karakter")
        if User.query.filter_by(username=username).first():
            return render_template('register.html', error="Username sudah terdaftar")

        pw_hash = generate_password_hash(password)
        new_user = User(username=username, password_hash=pw_hash)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route(f'{URL_PREFIX}/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', '').strip())
        password = request.form.get('password', '')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('chat'))
        else:
            return render_template('login.html', error="Login gagal")
    return render_template('login.html')

@app.route(f'{URL_PREFIX}/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route(f'{URL_PREFIX}/chat')
@login_required
def chat():
    return render_template('chat.html', username=session.get('username'), maker='Rhadit Satya.W')

@app.route(f'{URL_PREFIX}/chat_api', methods=['POST'])
@login_required
def chat_api():
    data = request.get_json()
    message = sanitize_input(data.get('message', '').strip())
    if not message:
        return jsonify({'response': 'Pesan kosong tidak diperbolehkan.'})

    try:
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "Kamu adalah Aether76 AI, asisten pintar buatan Rhadit Satya.W."},
                {"role": "user", "content": message}
            ]
        )
        reply = response['choices'][0]['message']['content'].strip()
        return jsonify({'response': reply})

    except Exception as e:
        print("OpenAI error:", e)
        return jsonify({'response': 'Terjadi kesalahan saat menghubungi AI.'})

@app.errorhandler(404)
def page_not_found(e):
    return redirect(url_for('login'))

# ---------- INIT DB ----------
with app.app_context():
    db.create_all()

# ---------- RUN ----------
if __name__ == '__main__':
    app.run(debug=True)
