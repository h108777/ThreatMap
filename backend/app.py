from flask import Flask, jsonify, send_file, request
from data_extractor import get_data_from_nist
import firebase_admin
from firebase_admin import credentials, firestore, auth
import threading
import pandas as pd
import os
import json
from dotenv import load_dotenv

# Load environment variables
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
    
    # Initialize Firebase
    cred = credentials.Certificate(firebase_config)
    firebase_admin.initialize_app(cred)
    db = firestore.client()
except json.JSONDecodeError as e:
    print(f"Error parsing Firebase configuration: {e}")
    raise
except Exception as e:
    print(f"Error initializing Firebase: {e}")
    raise

app = Flask(__name__)

@app.route('/login-user', methods=['POST'])
def login_user():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400

        user = auth.get_user_by_email(email)
        if user:
            # In a real application, you should verify the password using Firebase Auth
            # This is a simplified version for demonstration
            return jsonify({
                "uid": user.uid,
                "email": user.email,
                "name": user.display_name
            })
        else:
            return jsonify({"error": "Invalid credentials"}), 401
    except Exception as e:
        print(f"Error logging in user: {e}")
        return jsonify({"error": "Authentication failed"}), 500

@app.route('/create-user', methods=['POST'])
def create_user():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        name = data.get('name')
        
        if not email or not password or not name:
            return jsonify({"error": "All fields are required"}), 400

        user = auth.create_user(
            email=email,
            password=password,
            display_name=name
        )
        
        return jsonify({
            "uid": user.uid,
            "email": user.email,
            "name": user.display_name
        })
    except Exception as e:
        print(f"Error creating user: {e}")
        return jsonify({"error": "Failed to create user"}), 500

def parse_cve_entry(cve_entry):
    cve = cve_entry.get("cve", {})
    cve_id = cve.get("id", "")

    descriptions = cve.get("descriptions", [])
    description = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "")

    severity = ""
    metrics = cve.get("metrics", {}).get("cvssMetricV2", [])
    if metrics and isinstance(metrics, list):
        severity = metrics[0].get("baseSeverity", "")

    cve_data = {
        "id": cve_id,
        "description": description,
        "published": cve.get("published", ""),
        "status": cve.get("vulnStatus", ""),
        "severity": severity,
        "source": cve.get("sourceIdentifier", ""),
    }

    return cve_data


def process_and_store_data():
    data = get_data_from_nist()
    cves = data['cve_data']
    sources = data['source_data']

    try:
        for cve_entry in cves:
            try:
                parsed = parse_cve_entry(cve_entry)
                db.collection("cves").document(parsed["id"]).set(parsed)
            except Exception as e:
                print(f"Error storing CVE {cve_entry.get('cve', {}).get('id', 'unknown')}: {e}")
    except Exception as e:
        print("Faced error while processing cves")
    try:
        for source in sources:
            source_id = source['sourceIdentifiers'][-1]
            source_data = {
                'id': source_id,
                'name': source['name'],
                'contact': source['contactEmail']
            }
            db.collection('sources').document(source_id).set(source_data)
    except Exception as e:
        print("Faced error while processing sources")

@app.route('/analysis/summary')
def summary_analysis():
    docs = db.collection('cves').get()
    data = [doc.to_dict() for doc in docs]
    df = pd.DataFrame(data)

    summary = {
        "total_cves": len(df),
        "by_severity": df['severity'].value_counts().to_dict(),
        "by_status": df['status'].value_counts().to_dict(),
    }

    return jsonify(summary)

@app.route('/fetch-data')
def fetch_data():
    thread = threading.Thread(target=process_and_store_data)
    thread.start()
    return jsonify({"message": "Data fetch and processing started in background."}), 202

@app.route('/cves')
def fetch_cves():
    docs = db.collection('cves').get()
    cves = [doc.to_dict() for doc in docs]
    return jsonify(cves)

@app.route('/sources')
def fetch_sources():
    docs = db.collection('sources').get()
    sources = [doc.to_dict() for doc in docs]
    return jsonify(sources)

@app.route('/')
def index():
    return "Backend is running"


if __name__ == '__main__':
    app.run(debug=True,port=5050)
    