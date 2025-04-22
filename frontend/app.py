from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import firebase_admin
from firebase_admin import credentials, auth
import requests
import plotly
import plotly.express as px
import json
import pandas as pd
from functools import wraps
import os
from dotenv import load_dotenv

load_dotenv()

# Get Firebase configuration from environment variable with error handling
try:
    firebase_config_str = os.getenv('FIREBASE_CONFIG')
    if not firebase_config_str:
        raise ValueError("FIREBASE_CONFIG environment variable is not set")
    
    # Remove any extra whitespace and newlines
    firebase_config_str = firebase_config_str.strip()
    
    # Parse the JSON string
    firebase_config = json.loads(firebase_config_str)
    
    # Initialize Firebase Admin
    cred = credentials.Certificate(firebase_config)
    default_app = firebase_admin.initialize_app(cred)
except json.JSONDecodeError as e:
    print(f"Error parsing Firebase configuration: {e}")
    raise
except ValueError as e:
    print(f"Error with Firebase configuration: {e}")
    raise
except Exception as e:
    print(f"Error initializing Firebase: {e}")
    raise

app = Flask(__name__)
app.secret_key = 'your-secret-key'  # Change this to a secure secret key

# Backend API URL
BACKEND_URL = 'http://localhost:5050'

def login_required(f):
    
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# lol
@app.route('/')
@login_required
def index():
    return render_template('dashboard.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        try:
            # Authenticate with Firebase
            response = requests.post(f'{BACKEND_URL}/login-user', json={
                'email': email,
                'password': password
            })
            
            if response.status_code == 200:
                user_data = response.json()
                session['user'] = user_data
                return redirect(url_for('index'))
            else:
                error_data = response.json()
                return render_template('login.html', error=error_data.get('error', 'Invalid credentials'))
        except Exception as e:
            return render_template('login.html', error="Authentication failed")
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            return render_template('signup.html', error="Passwords do not match")

        try:
            # Create user in Firebase
            response = requests.post(f'{BACKEND_URL}/create-user', json={
                'name': name,
                'email': email,
                'password': password
            })
            
            if response.status_code == 200:
                return redirect(url_for('login'))
            else:
                return render_template('signup.html', error="Failed to create account")
        except Exception as e:
            return render_template('signup.html', error="Account creation failed")
    
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/api/cves')
@login_required
def get_cves():
    response = requests.get(f'{BACKEND_URL}/cves')
    return jsonify(response.json())

@app.route('/api/sources')
@login_required
def get_sources():
    response = requests.get(f'{BACKEND_URL}/sources')
    return jsonify(response.json())

@app.route('/api/analysis')
@login_required
def get_analysis():
    response = requests.get(f'{BACKEND_URL}/analysis/summary')
    return jsonify(response.json())

if __name__ == '__main__':
    app.run(debug=True, port=5000)

