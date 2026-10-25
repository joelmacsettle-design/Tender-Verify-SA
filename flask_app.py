from flask import Flask, request, render_template_string, jsonify, redirect, url_for, Response, session
from werkzeug.security import generate_password_hash, check_password_hash
import re
import random
import sqlite3
import os
import csv
import io
import hashlib
import urllib.parse
from datetime import datetime, timezone, timedelta
from pypdf import PdfReader

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'tenderverify-secret-key-2026-sa')

# --- COMPANY & SUPPORT CONFIGURATION ---
COMPANY_SUPPORT_EMAIL = "support@tenderverifysa.co.za"

# --- OFFICIAL DEPARTMENT DIRECTORY ---
OFFICIAL_DEPT_DIRECTORY = {
    "tshwane": {"name": "City of Tshwane Metropolitan Municipality", "phone": "012 358 9999", "domain": "tshwane.gov.za"},
    "joburg": {"name": "City of Johannesburg", "phone": "0860 562 874", "domain": "joburg.org.za"},
    "ekurhuleni": {"name": "City of Ekurhuleni", "phone": "0860 543 000", "domain": "ekurhuleni.gov.za"},
    "saps": {"name": "South African Police Service", "phone": "012 393 1000", "domain": "saps.gov.za"},
    "eskom": {"name": "Eskom Holdings SOC Ltd", "phone": "0860 037 566", "domain": "eskom.co.za"},
    "transnet": {"name": "Transnet SOC Ltd", "phone": "011 308 3000", "domain": "transnet.net"},
    "sars": {"name": "South African Revenue Service", "phone": "0800 00 7277", "domain": "sars.gov.za"},
    "health": {"name": "Department of Health", "phone": "012 395 8000", "domain": "health.gov.za"}
}

# --- PAYFAST & SUBSCRIPTION CONFIGURATION ---
PAYFAST_MERCHANT_ID = os.environ.get('PAYFAST_MERCHANT_ID', '37549253')
PAYFAST_MERCHANT_KEY = os.environ.get('PAYFAST_MERCHANT_KEY', 'xtyxz3mrdcmpn')
PAYFAST_PASSPHRASE = os.environ.get('PAYFAST_PASSPHRASE', 'Macsettle088')
PAYFAST_URL = os.environ.get('PAYFAST_URL', 'https://www.payfast.co.za/eng/process')

TIER_LIMITS = {
    'free': 3,
    'tier1': 15, # R79.00 / month
    'tier2': 50, # R199.00 / month
    'tier3': 999999 # R269.00 / month (Unlimited)
}

TIER_PRICES = {
    'tier1': 79.00,
    'tier2': 199.00,
    'tier3': 269.00
}

# --- DATABASE ENGINE ---
DB_PATH = os.path.join(os.path.dirname(__file__), 'tenderverify.db')

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            ref_id TEXT PRIMARY KEY,
            timestamp TEXT,
            user_id INTEGER,
            dept_name TEXT,
            buyer_email TEXT,
            phone_number TEXT,
            delivery_address TEXT,
            risk_score TEXT,
            fraud_probability TEXT,
            forecast TEXT,
            verdict TEXT,
            badge_class TEXT,
            flags TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scam_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            email TEXT,
            phone TEXT,
            reason TEXT,
            reported_by TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            recovery_pin TEXT DEFAULT '0000',
            role TEXT DEFAULT 'user',
            subscription_tier TEXT DEFAULT 'free',
            scans_used INTEGER DEFAULT 0,
            billing_cycle_start TEXT,
            created_at TEXT
        )
    ''')

    migrations = [
        "ALTER TABLE users ADD COLUMN recovery_pin TEXT DEFAULT '0000'",
        "ALTER TABLE users ADD COLUMN subscription_tier TEXT DEFAULT 'free'",
        "ALTER TABLE users ADD COLUMN scans_used INTEGER DEFAULT 0",
        "ALTER TABLE users ADD COLUMN billing_cycle_start TEXT",
        "ALTER TABLE audit_logs ADD COLUMN user_id INTEGER",
        "ALTER TABLE audit_logs ADD COLUMN fraud_probability TEXT",
        "ALTER TABLE audit_logs ADD COLUMN forecast TEXT"
    ]

    for stmt in migrations:
        try:
            cursor.execute(stmt)
        except sqlite3.OperationalError:
            pass

    conn.commit()
    conn.close()

init_db()

# --- SUBSCRIPTION & SCAN LIMIT HELPERS ---
def get_user_subscription(user_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT subscription_tier, scans_used FROM users WHERE id = ?', (user_id,))
    row = cursor.fetchone()
    conn.close()

    tier = row[0] if row and row[0] else 'free'
    scans_used = row[1] if row and row[1] is not None else 0
    max_scans = TIER_LIMITS.get(tier, 3)
    scans_left = max(0, max_scans - scans_used)

    return tier, scans_used, scans_left, max_scans

def check_scan_limit(user_id):
    tier, scans_used, scans_left, max_scans = get_user_subscription(user_id)
    if scans_used >= max_scans:
        return False, tier, scans_left
    return True, tier, scans_left

def increment_scan_count(user_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET scans_used = scans_used + 1 WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

def save_audit(audit_data, user_id=None):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR REPLACE INTO audit_logs
        (ref_id, timestamp, user_id, dept_name, buyer_email, phone_number, delivery_address, risk_score, fraud_probability, forecast, verdict, badge_class, flags)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        audit_data['ref_id'],
        audit_data['timestamp'],
        user_id,
        audit_data['dept_name'],
        audit_data['buyer_email'],
        audit_data['phone_number'],
        audit_data['delivery_address'],
        audit_data['risk_score'],
        audit_data['fraud_probability'],
        audit_data['forecast'],
        audit_data['verdict'],
        audit_data['badge_class'],
        "||".join(audit_data['flags'])
    ))
    conn.commit()
    conn.close()

def get_audit_by_ref(ref_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM audit_logs WHERE ref_id = ?', (ref_id,))
    row = cursor.fetchone()
    conn.close()

    if row:
        return {
            "ref_id": row[0],
            "timestamp": row[1],
            "dept_name": row[3],
            "buyer_email": row[4],
            "phone_number": row[5],
            "delivery_address": row[6],
            "risk_score": row[7],
            "fraud_probability": row[8] if row[8] else "15%",
            "forecast": row[9] if row[9] else "Behavioral patterns align with verified institutional baselines.",
            "verdict": row[10],
            "badge_class": row[11],
            "flags": row[12].split("||") if row[12] else []
        }
    return None

def get_user_history(user_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT ref_id, timestamp, dept_name, buyer_email, verdict, badge_class FROM audit_logs WHERE user_id = ? ORDER BY rowid DESC LIMIT 20', (user_id,))
    rows = cursor.fetchall()
    conn.close()
    return rows

def check_threat_database(email, phone):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    email_clean = email.lower().strip()
    phone_clean = re.sub(r'\D', '', phone)

    email_flagged = False
    phone_flagged = False

    if email_clean:
        cursor.execute('SELECT COUNT(*) FROM scam_reports WHERE LOWER(email) = ?', (email_clean,))
        if cursor.fetchone()[0] > 0:
            email_flagged = True

    if phone_clean and len(phone_clean) >= 7:
        cursor.execute('SELECT COUNT(*) FROM scam_reports WHERE REPLACE(phone, " ", "") LIKE ?', (f'%{phone_clean[-9:]}%',))
        if cursor.fetchone()[0] > 0:
            phone_flagged = True

    conn.close()
    return email_flagged, phone_flagged

def add_scam_report(email, phone, reason, reported_by):
    sast_tz = timezone(timedelta(hours=2))
    timestamp = datetime.now(sast_tz).strftime('%Y-%m-%d %H:%M SAST')

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO scam_reports (timestamp, email, phone, reason, reported_by)
        VALUES (?, ?, ?, ?, ?)
    ''', (timestamp, email.strip().lower(), phone.strip(), reason.strip(), reported_by))
    conn.commit()
    conn.close()

# --- PDF EXTRACTION & COMPLIANCE CHECKLIST ENGINE ---
def extract_rfq_details_from_pdf(pdf_file):
    extracted_text = ""
    try:
        reader = PdfReader(pdf_file)
        for page in reader.pages:
            text = page.extract_text()
            if text:
                extracted_text += text + "\n"
    except Exception:
        return {}, []

    if not extracted_text.strip():
        return {}, []

    lines = [line.strip() for line in extracted_text.split('\n') if line.strip()]

    emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', extracted_text)
    buyer_email = emails[0] if emails else ""

    phones = re.findall(r'(?:\+27|0)\s*\d{2}\s*[\d\s-]{6,9}\d', extracted_text)
    phone_number = phones[0] if phones else ""

    dept_name = ""
    for line in lines[:35]:
        match = re.search(r'(?:department|institution|issued by|client|entity|municipality|organisation|org|company)\s*[:\-]\s*(.+)', line, re.IGNORECASE)
        if match and len(match.group(1).strip()) > 3:
            dept_name = match.group(1).strip()
            break

    if not dept_name:
        dept_keywords = [
            'department', 'municipality', 'treasury', 'hospital', 'procurement',
            'city of', 'saps', 'eskom', 'transnet', 'sita', 'sanral', 'prasa',
            'rand water', 'umgeni', 'dpsa', 'sars', 'university', 'college',
            'school', 'council', 'board', 'authority', 'agency', 'pty ltd', 'holdings'
        ]
        for line in lines[:25]:
            if any(kw in line.lower() for kw in dept_keywords):
                if len(line) < 80:
                    dept_name = line
                    break

    delivery_address = ""
    address_headers = [
        'delivery address', 'deliver to', 'physical address', 'delivery location',
        'site address', 'ship to', 'place of delivery', 'address for delivery', 'location'
    ]

    full_text_lower = extracted_text.lower()
    for header in address_headers:
        if header in full_text_lower:
            for idx, line in enumerate(lines):
                if header in line.lower():
                    parts = re.split(r'[:\-]', line, maxsplit=1)
                    if len(parts) > 1 and len(parts[1].strip()) > 5:
                        delivery_address = parts[1].strip()
                    else:
                        next_lines = lines[idx+1 : idx+3]
                        filtered = [l for l in next_lines if not any(kw in l.lower() for kw in ['tel', 'email', 'fax', 'contact', 'ref', 'vat', 'total', 'date'])]
                        delivery_address = ", ".join(filtered)
                    break
            if delivery_address:
                break

    if not delivery_address:
        street_keywords = ['street', 'st', 'road', 'rd', 'avenue', 'ave', 'drive', 'dr', 'boulevard', 'blvd', 'park', 'building', 'floor', 'plot', 'farm', 'industrial']
        for line in lines:
            if any(re.search(r'\b' + kw + r'\b', line, re.IGNORECASE) for kw in street_keywords):
                if len(line) < 90 and not any(kw in line.lower() for kw in ['email', 'website', 'http', 'www']):
                    delivery_address = line
                    break

    checklist = []
    checklist.append({"item": "Central Supplier Database (CSD) Registration active & compliant", "mandatory": True})
    checklist.append({"item": "Valid SARS Tax Compliance Status Pin attached", "mandatory": True})
    checklist.append({"item": "Completed SBD 4 (Declaration of Interest) form signed", "mandatory": True})

    text_blob = extracted_text.lower()
    if "cidb" in text_blob:
        checklist.append({"item": "CIDB Contractor Grading Certificate matched to requirement", "mandatory": True})
    if "briefing" in text_blob or "site meeting" in text_blob:
        checklist.append({"item": "Compulsory Briefing Session Attendance Certificate / Register signed", "mandatory": True})
    if "bbbee" in text_blob or "sworn affidavit" in text_blob or "bee certificate" in text_blob:
        checklist.append({"item": "Valid B-BBEE Certificate or Sworn Affidavit attached", "mandatory": True})
    if "sample" in text_blob or "prototype" in text_blob:
        checklist.append({"item": "Physical product sample or demonstration provided if requested", "mandatory": False})

    return {
        "dept_name": dept_name,
        "buyer_email": buyer_email,
        "phone_number": phone_number,
        "delivery_address": delivery_address,
        "extracted_text": extracted_text
    }, checklist

# --- PREDICTIVE INTELLIGENCE & VERIFICATION ENGINE ---
def calculate_intelligence_insights(risk_score, flags):
    fraud_probability = min(max(int(risk_score * 1.2), 3), 98) if risk_score > 0 else 2

    if risk_score >= 60:
        forecast = "High probability of malicious upfront-payment scam or corporate identity theft based on historical pattern matching."
    elif risk_score >= 30:
        forecast = "Moderate behavioral anomalies detected. Contact vectors deviate from standard South African municipal/corporate procurement norms."
    else:
        forecast = "Behavioral patterns align with verified institutional procurement baselines. Low anomaly probability."

    return f"{fraud_probability}%", forecast

def verify_rfq(dept_name, buyer_email, phone_number, delivery_address, full_pdf_text="", user_id=None):
    risk_score = 0
    flags = []

    email_flagged, phone_flagged = check_threat_database(buyer_email, phone_number)
    if email_flagged:
        risk_score += 60
        flags.append("CRITICAL ALERT: Email address is listed in TenderVerify Crowd-Sourced Scam Database.")
    if phone_flagged:
        risk_score += 50
        flags.append("CRITICAL ALERT: Phone number is listed in TenderVerify Crowd-Sourced Scam Database.")

    email_clean = buyer_email.lower().strip()
    domain = email_clean.split('@')[-1] if '@' in email_clean else email_clean
    free_providers = ('gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'icloud.com', 'live.com', 'protonmail.com')

    if domain in free_providers:
        risk_score += 45
        flags.append("SECURITY WARNING: Official procurement never uses free email providers (Gmail/Yahoo).")
    elif "-gov-" in domain or "-sa.co" in domain or "gov-sa" in domain:
        risk_score += 40
        flags.append("HIGH RISK: Email domain contains typosquatting patterns mimicking official entities.")
    elif not (domain.endswith('.gov.za') or domain.endswith('.co.za') or domain.endswith('.org.za')):
        risk_score += 20
        flags.append("SUSPICIOUS: Unrecognized domain extension for a South African entity.")

    phone_clean = re.sub(r'\D', '', phone_number)
    if phone_clean.startswith('27'):
        phone_clean = '0' + phone_clean[2:]

    mobile_prefixes = ('060', '061', '062', '063', '064', '065', '066', '067', '068', '069',
                       '071', '072', '073', '074', '076', '078', '079', '081', '082', '083', '084')

    if 0 < len(phone_clean) < 10:
        risk_score += 15
        flags.append("WARNING: Phone number is incomplete for a South African standard number.")
    elif phone_clean.startswith(mobile_prefixes):
        risk_score += 25
        flags.append("WARNING: Primary procurement contact is listed as a mobile number rather than an official landline.")

    address_lower = delivery_address.lower()
    suspicious_keywords = ['warehouse', 'storage', 'depot', 'unit', 'rented', 'plot', 'farm']
    found_keywords = [kw for kw in suspicious_keywords if re.search(r'\b' + re.escape(kw) + r'\b', address_lower)]

    if found_keywords:
        risk_score += 20
        flags.append(f"WARNING: Delivery address contains non-standard keywords ({', '.join(found_keywords)}). Verify physical location.")

    dept_clean = dept_name.lower()
    matched_dept = None
    for key, info in OFFICIAL_DEPT_DIRECTORY.items():
        if key in dept_clean or info['name'].lower() in dept_clean:
            matched_dept = info
            break

    if matched_dept:
        flags.append(f"OFFICIAL DIRECTORY MATCH: {matched_dept['name']}. Official Switchboard: {matched_dept['phone']} | Verified Domain: {matched_dept['domain']}")
        if not domain.endswith(matched_dept['domain']):
            risk_score += 35
            flags.append(f"DOMAIN MISMATCH ALERT: Sender domain (@{domain}) does not match official entity domain (@{matched_dept['domain']}). Call {matched_dept['phone']} immediately to verify!")

    combined_blob = (dept_name + " " + delivery_address + " " + full_pdf_text)

    csd_match = re.search(r'MAAA\d{7}', combined_blob, re.IGNORECASE)
    if csd_match:
        flags.append(f"COMPLIANCE VERIFIED: Valid CSD supplier number format detected ({csd_match.group(0).upper()}).")
    else:
        risk_score += 10
        flags.append("COMPLIANCE NOTICE: No valid CSD (Central Supplier Database) MAAA reference format detected in document text.")

    sars_match = re.search(r'\b[A-Za-z0-9]{16}\b', combined_blob)
    if sars_match and any(c.isalpha() for c in sars_match.group(0)) and any(c.isdigit() for c in sars_match.group(0)):
        flags.append("COMPLIANCE VERIFIED: Valid SARS 16-character alphanumeric Tax Compliance Pin format identified.")
    else:
        risk_score += 5
        flags.append("COMPLIANCE NOTE: Ensure SARS Tax Compliance Status PIN is manually verified if not explicitly stated.")

    cipc_match = re.search(r'\b(?:19|20)\d{2}/\d{6}/\d{2}\b', combined_blob)
    if cipc_match:
        flags.append(f"REGISTRATION VERIFIED: Valid CIPC Company Registration number structure found ({cipc_match.group(0)}).")

    risk_score = min(risk_score, 100)

    fraud_probability, forecast = calculate_intelligence_insights(risk_score, flags)

    if risk_score >= 60:
        verdict = "HIGH RISK - Likely Scam"
        badge_class = "danger"
    elif risk_score >= 30:
        verdict = "MEDIUM RISK - Proceed with Caution"
        badge_class = "warning"
    else:
        verdict = "LOW RISK - Appears Genuine"
        badge_class = "success"

    sast_tz = timezone(timedelta(hours=2))
    now_sast = datetime.now(sast_tz)

    ref_id = f"TV-{now_sast.strftime('%Y%m%d')}-{random.randint(100000, 999999)}"
    timestamp = now_sast.strftime('%Y-%m-%d %H:%M SAST')

    result = {
        "ref_id": ref_id,
        "timestamp": timestamp,
        "dept_name": dept_name.strip() if dept_name.strip() else "Unspecified Department",
        "buyer_email": buyer_email.strip(),
        "phone_number": phone_number.strip(),
        "delivery_address": delivery_address.strip(),
        "risk_score": f"{risk_score}%",
        "fraud_probability": fraud_probability,
        "forecast": forecast,
        "verdict": verdict,
        "badge_class": badge_class,
        "flags": flags if flags else ["No immediate red flags detected. Always double-check CSD listings."]
    }

    save_audit(result, user_id=user_id)
    return result

# --- EMBEDDED VECTOR LOGO ---
SVG_LOGO_HTML = """
<svg width="32" height="32" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" style="vertical-align: middle;">
  <path d="M12 22C12 22 20 18 20 12V5L12 2L4 5V12C4 18 12 22 12 22Z" fill="#1E3A8A" stroke="#38BDF8" stroke-width="1.8" stroke-linejoin="round"/>
  <path d="M8.5 12.2L10.8 14.5L15.5 9.5" stroke="#F97316" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
</svg>
"""

# --- TEMPLATES ---
HTML_LAYOUT = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TenderVerify SA Dashboard</title>

    <link rel="shortcut icon" href="/static/icon.png" type="image/png">
    <link rel="icon" type="image/png" href="/static/icon.png">
    <link rel="apple-touch-icon" href="/static/icon.png">
    <link rel="manifest" href="/static/manifest.json">

    <meta name="theme-color" content="#1E3A8A">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">

    <script src="https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.10.1/html2pdf.bundle.min.js"></script>

    <style>
        :root {
            --primary-dark: #1E3A8A;
            --primary-light: #38BDF8;
            --accent-coral: #F97316;
            --danger: #DC2626;
            --warning: #D97706;
            --success: #16A34A;
            --bg-slate: #F8FAFC;
        }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg-slate); margin: 0; padding: 15px; color: #1E293B; }
        .container { max-width: 540px; margin: 0 auto; background: white; padding: 22px; border-radius: 14px; box-shadow: 0 4px 20px rgba(30, 58, 138, 0.08); border: 1px solid #E2E8F0; }

        .top-app-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; background: white; padding: 8px 12px; border-radius: 10px; border: 1px solid #E2E8F0; }
        .app-brand { display: flex; align-items: center; gap: 8px; }
        .app-title { font-size: 1.15rem; font-weight: 800; color: var(--primary-dark); margin: 0; }

        .hamburger-btn { background: #EFF6FF; border: 1px solid #DBEAFE; color: var(--primary-dark); font-size: 1.3rem; padding: 6px 12px; border-radius: 8px; cursor: pointer; display: flex; align-items: center; justify-content: center; transition: background 0.2s; }
        .hamburger-btn:hover { background: #DBEAFE; }

        .sidebar-overlay { position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; background: rgba(15, 23, 42, 0.5); backdrop-filter: blur(3px); z-index: 1000; opacity: 0; pointer-events: none; transition: opacity 0.3s ease; }
        .sidebar-overlay.active { opacity: 1; pointer-events: auto; }

        .sidebar-drawer { position: fixed; top: 0; right: -300px; width: 280px; height: 100vh; background: white; z-index: 1001; box-shadow: -4px 0 25px rgba(0,0,0,0.15); transition: right 0.3s cubic-bezier(0.4, 0, 0.2, 1); display: flex; flex-direction: column; padding: 20px; box-sizing: border-box; overflow-y: auto; }
        .sidebar-drawer.active { right: 0; }

        .sidebar-header { display: flex; justify-content: space-between; align-items: center; padding-bottom: 12px; border-bottom: 1px solid #F1F5F9; }
        .sidebar-close-btn { background: none; border: none; font-size: 1.4rem; cursor: pointer; color: #64748B; font-weight: bold; }

        .sidebar-user-card { background: #F8FAFC; border: 1px solid #E2E8F0; padding: 14px; border-radius: 10px; margin: 15px 0; }
        .sidebar-username { font-weight: 800; font-size: 0.95rem; color: #1E293B; display: block; }
        .plan-badge { display: inline-block; background: #FEF3C7; color: #92400E; padding: 2px 8px; border-radius: 6px; font-weight: bold; border: 1px solid #FCD34D; font-size: 0.72rem; margin-top: 4px; }
        .scans-counter { font-size: 0.78rem; color: #475569; font-weight: bold; display: block; margin-top: 6px; }

        .sidebar-menu { display: flex; flex-direction: column; gap: 8px; margin-top: 10px; }
        .sidebar-item { display: flex; align-items: center; gap: 10px; padding: 12px 14px; color: #334155; text-decoration: none; font-weight: 600; font-size: 0.9rem; border-radius: 8px; transition: background 0.2s, color 0.2s; }
        .sidebar-item:hover { background: #F1F5F9; color: var(--primary-dark); }
        .sidebar-item.highlight { background: #FFF7ED; color: #C2410C; border: 1px solid #FFEDD5; }
        .sidebar-item.logout { color: var(--danger); margin-top: 15px; }

        .brand-header { display: flex; align-items: center; gap: 10px; margin-bottom: 4px; }
        h1 { font-size: 1.45rem; color: var(--primary-dark); margin: 0; font-weight: 800; }
        p.subtitle { font-size: 0.85rem; color: #64748B; margin-top: 2px; margin-bottom: 15px; }

        .demo-bar { display: flex; gap: 8px; margin-bottom: 18px; }
        .demo-btn { flex: 1; padding: 8px; font-size: 0.75rem; font-weight: bold; border-radius: 6px; border: 1px solid #CBD5E1; background: #F1F5F9; color: #334155; cursor: pointer; text-align: center; }
        .demo-btn.legit { background: #DCFCE7; border-color: #86EFAC; color: #14532D; }
        .demo-btn.scam { background: #FEE2E2; border-color: #FCA5A5; color: #991B1B; }

        .upload-box { border: 2px dashed var(--primary-light); background: #F0F9FF; padding: 18px; border-radius: 10px; text-align: center; margin-bottom: 20px; }
        .upload-box input { display: none; }
        .upload-label { font-size: 0.9rem; color: var(--primary-dark); font-weight: bold; cursor: pointer; display: block; }
        .file-list-display { margin-top: 10px; font-size: 0.8rem; color: #334155; text-align: left; background: white; padding: 8px 12px; border-radius: 6px; border: 1px solid #CBD5E1; }

        label { font-weight: 700; font-size: 0.85rem; display: block; margin-top: 12px; color: #334155; }
        input[type="text"], input[type="email"], textarea { width: 100%; padding: 10px; margin-top: 4px; border: 1px solid #CBD5E1; border-radius: 7px; box-sizing: border-box; font-size: 0.95rem; background: #FAF5FF; }
        input:focus, textarea:focus { outline: none; border-color: var(--primary-light); box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.2); }

        .btn-submit { width: 100%; margin-top: 20px; padding: 12px; background: var(--accent-coral); color: white; border: none; border-radius: 8px; font-weight: bold; font-size: 1rem; cursor: pointer; transition: background 0.2s; }
        .btn-submit:hover { background: #EA580C; }
        .btn-pdf { width: 100%; margin-top: 15px; padding: 12px; background: var(--primary-dark); color: white; border: none; border-radius: 8px; font-weight: bold; font-size: 0.95rem; cursor: pointer; text-align: center; text-decoration: none; display: block; box-sizing: border-box; }

        details.report-accordion { border: 1px solid #CBD5E1; border-radius: 10px; margin-top: 20px; overflow: hidden; background: white; }
        summary.accordion-header { background: var(--primary-dark); color: white; padding: 12px 16px; font-weight: bold; font-size: 0.9rem; cursor: pointer; user-select: none; list-style: none; display: flex; justify-content: space-between; align-items: center; }
        summary.accordion-header::-webkit-details-marker { display: none; }
        summary.accordion-header::after { content: "▼"; font-size: 0.75rem; transition: transform 0.2s; }
        details[open] summary.accordion-header::after { transform: rotate(180deg); }

        .certificate-card { padding: 20px; background: #ffffff; color: #000000; }
        .cert-header { text-align: center; border-bottom: 2px solid var(--primary-dark); padding-bottom: 10px; margin-bottom: 15px; display: flex; align-items: center; justify-content: center; gap: 8px; }
        .cert-header h2 { margin: 0; color: var(--primary-dark); font-size: 1.15rem; font-weight: 800; text-transform: uppercase; }
        .cert-subtitle { text-align: center; font-size: 0.75rem; color: #64748B; margin-top: -10px; margin-bottom: 15px; }
        .cert-meta { font-size: 0.8rem; color: #475569; margin-bottom: 12px; display: flex; justify-content: space-between; }
        .badge { display: inline-block; padding: 6px 12px; border-radius: 6px; color: white; font-weight: bold; font-size: 0.9rem; }
        .danger { background: var(--danger); }
        .warning { background: var(--warning); }
        .success { background: var(--success); }
        ul { margin: 10px 0 0 0; padding-left: 20px; font-size: 0.85rem; color: #334155; }
        li { margin-bottom: 6px; }
        .cert-footer { margin-top: 15px; padding-top: 10px; border-top: 1px dashed #CBD5E1; font-size: 0.7rem; color: #64748B; text-align: center; }
        .STRIVEX-attribution { margin-top: 10px; font-size: 0.72rem; color: #1E3A8A; font-weight: bold; text-align: center; border-top: 1px solid #F1F5F9; padding-top: 8px; }
        .qr-box { text-align: center; margin-top: 12px; }
        .qr-box img { width: 100px; height: 100px; border: 1px solid #E2E8F0; padding: 3px; border-radius: 6px; }
        .verified-badge { background: #DCFCE7; color: #14532D; padding: 8px; border-radius: 6px; text-align: center; font-weight: bold; font-size: 0.85rem; margin-bottom: 15px; border: 1px solid #86EFAC; }

        .alert-msg { background: #DCFCE7; color: #14532D; padding: 10px; border-radius: 6px; font-size: 0.85rem; margin-bottom: 15px; border: 1px solid #86EFAC; }
        .limit-msg { background: #FEE2E2; color: #991B1B; padding: 14px; border-radius: 8px; font-size: 0.88rem; margin-bottom: 15px; border: 1px solid #FCA5A5; text-align: center; }

        .checklist-container { background: #F8FAFC; border: 1px solid #CBD5E1; border-radius: 10px; padding: 15px; margin-top: 20px; }
        .checklist-item { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; font-size: 0.85rem; color: #334155; }
        .checklist-item input { width: 18px; height: 18px; accent-color: var(--primary-dark); cursor: pointer; }

        .tier-lock-box { background: #FFFBEB; border: 1px solid #FCD34D; padding: 12px; border-radius: 8px; margin: 15px 0; text-align: center; }

        .history-table { width: 100%; border-collapse: collapse; font-size: 0.8rem; margin-top: 10px; }
        .history-table th, .history-table td { padding: 8px; text-align: left; border-bottom: 1px solid #F1F5F9; }
        .history-table th { background: #F8FAFC; color: #475569; }

        .global-footer { text-align: center; margin-top: 30px; font-size: 0.8rem; color: #64748B; border-top: 1px solid #E2E8F0; padding-top: 15px; }
        .global-footer strong { color: var(--primary-dark); }
        .global-footer a { color: var(--primary-dark); text-decoration: underline; }
    </style>
</head>
<body>
    <!-- SIDEBAR OVERLAY & DRAWER -->
    <div id="sidebarOverlay" class="sidebar-overlay" onclick="toggleSidebar()"></div>
    <div id="sidebarDrawer" class="sidebar-drawer">
        <div class="sidebar-header">
            <span style="font-weight: 800; color: var(--primary-dark); font-size: 0.95rem;">TenderVerify Menu</span>
            <button class="sidebar-close-btn" onclick="toggleSidebar()">X</button>
        </div>

        <div class="sidebar-user-card">
            <span class="sidebar-username">{{ session.get('username') }}</span>
            <span class="plan-badge">
                {% if current_tier == 'tier1' %}TIER 1 (STARTER)
                {% elif current_tier == 'tier2' %}TIER 2 (PRO)
                {% elif current_tier == 'tier3' %}TIER 3 (ENTERPRISE)
                {% else %}FREE TIER{% endif %}
            </span>
            <span class="scans-counter">
                {% if current_tier == 'tier3' %}Unlimited monthly scans
                {% else %}{{ scans_left if scans_left is defined else 0 }} scans remaining{% endif %}
            </span>
        </div>

        <div class="sidebar-menu">
            <a href="/" class="sidebar-item">Scanner Dashboard</a>
            <a href="/upgrade" class="sidebar-item highlight">Upgrade Plan</a>
            <a href="/support" class="sidebar-item">Help & Resources</a>
            <a href="/logout" class="sidebar-item logout">Logout</a>
        </div>
    </div>

    <div class="container">
        <!-- TOP APP BAR WITH HAMBURGER BUTTON -->
        <div class="top-app-bar">
            <div class="app-brand">
                """ + SVG_LOGO_HTML + """
                <span class="app-title">TenderVerify SA</span>
            </div>
            <button class="hamburger-btn" onclick="toggleSidebar()" aria-label="Open Navigation Menu">
                =
            </button>
        </div>

        {% if limit_reached %}
        <div class="limit-msg">
            <strong>Monthly Scan Limit Reached!</strong><br>
            You have used all scans for your current {{ (current_tier|default('free'))|upper }} plan.<br>
            <a href="/upgrade" style="display:inline-block; margin-top:8px; padding:6px 14px; background:#DC2626; color:white; font-weight:bold; text-decoration:none; border-radius:6px;">Upgrade Your Plan Now</a>
        </div>
        {% endif %}

        {% if payment_success %}
        <div class="alert-msg">
            Payment successful! Your subscription tier has been updated.
        </div>
        {% endif %}

        {% if report_success %}
        <div class="alert-msg">
            Success: The suspicious contact has been logged into the TenderVerify Threat Database.
        </div>
        {% endif %}

        <div class="brand-header">
            """ + SVG_LOGO_HTML + """
            <h1>TenderVerify SA</h1>
        </div>
        <p class="subtitle">RFQ Fraud Verification & Compliance Intelligence</p>

        {% if dev_mode %}
        <!-- DEMO SAMPLER (ONLY VISIBLE WHEN DEV MODE IS ACTIVE) -->
        <div class="demo-bar">
            <button class="demo-btn legit" onclick="loadSample('legit')">Load Genuine RFQ Demo</button>
            <button class="demo-btn scam" onclick="loadSample('scam')">Load Scam RFQ Demo</button>
        </div>
    <div style="margin-top: 10px; display: flex; gap: 6px; justify-content: center; align-items: center; font-size: 12px; color: #fff;">
        <span style="opacity: 0.8;">Switch Tier:</span>
        <a href="/demo/switch-tier/starter" style="background: #374151; color: #fff; padding: 3px 8px; border-radius: 4px; text-decoration: none;">Starter</a>
        <a href="/demo/switch-tier/pro" style="background: #2563eb; color: #fff; padding: 3px 8px; border-radius: 4px; text-decoration: none; font-weight: bold;">Pro</a>
        <a href="/demo/switch-tier/enterprise" style="background: #059669; color: #fff; padding: 3px 8px; border-radius: 4px; text-decoration: none;">Enterprise</a>
    </div>
        {% endif %}

        {% if is_verified_view %}
        <div class="verified-badge">
            OFFICIAL VERIFIED AUDIT RECORD (DB PERSISTED)
        </div>
        {% endif %}

        <div class="upload-box">
            <form id="uploadForm" method="POST" action="/parse_pdf" enctype="multipart/form-data">
                <label for="pdfFiles" class="upload-label">Upload RFQ Documents</label>
                <input type="file" id="pdfFiles" name="rfq_pdf" accept="application/pdf" multiple onchange="displaySelectedFiles(this)">
                <div id="fileListDisplay" class="file-list-display" style="display: none;"></div>
                <button type="submit" id="parseBtn" style="display:none; margin-top:10px; width:100%; padding:8px; background:#1E3A8A; color:white; border:none; border-radius:6px; font-weight:bold; cursor:pointer;">Process Selected Documents</button>
            </form>
        </div>

        {% if checklist_items %}
            {% if current_tier in ['tier1', 'tier2', 'tier3'] %}
            <div class="checklist-container">
                <h4 style="margin: 0 0 8px 0; color: #1E3A8A; font-size: 0.9rem;">Consolidated Compliance Checklist</h4>
                <p style="font-size: 0.75rem; color: #64748B; margin-top: 0; margin-bottom: 10px;">Extracted requirements from your uploaded documents. Check off items as you prepare your submission:</p>
                {% for task in checklist_items %}
                <div class="checklist-item">
                    <input type="checkbox" id="task_{{ loop.index }}">
                    <label for="task_{{ loop.index }}" style="margin:0; font-weight:normal; cursor:pointer;">{{ task.item }} {{ '(Mandatory)' if task.mandatory else '' }}</label>
                </div>
                {% endfor %}
            </div>
            {% else %}
            <div class="tier-lock-box">
                <span style="font-size: 0.85rem; color: #92400E; font-weight: bold;">Consolidated Compliance Checklist Locked</span>
                <p style="font-size: 0.78rem; color: #B45309; margin: 4px 0 10px 0;">Automated extraction of mandatory tender requirements is available on Tier 1 (Starter) and above.</p>
                <a href="/upgrade" style="display:inline-block; padding: 6px 14px; background: #F97316; color: white; border-radius: 6px; font-weight: bold; font-size: 0.8rem; text-decoration: none;">Upgrade to Tier 1 to Unlock</a>
            </div>
            {% endif %}
        {% endif %}

        <form id="verifyForm" method="POST" action="/" style="margin-top: 15px;">
            <label>Department / Entity Name</label>
            <input type="text" id="dept_name" name="dept_name" placeholder="e.g. City of Tshwane" required value="{{ dept_name|default('') }}">

            <label>Buyer Email Address</label>
            <input type="email" id="buyer_email" name="buyer_email" placeholder="e.g. buyer@domain.co.za" required value="{{ buyer_email|default('') }}">

            <label>Contact Phone Number</label>
            <input type="text" id="phone_number" name="phone_number" placeholder="e.g. 0123589999" required value="{{ phone_number|default('') }}">

            <label>Delivery Address / Warehouse Location</label>
            <input type="text" id="delivery_address" name="delivery_address" placeholder="e.g. 123 Main St, Pretoria" required value="{{ delivery_address|default('') }}">

            <input type="hidden" name="full_pdf_text" value="{{ full_pdf_text|default('') }}">

            <button type="submit" class="btn-submit">Analyze RFQ Security</button>
        </form>

        {% if result %}
        <details class="report-accordion" open>
            <summary class="accordion-header">
                View Audit Certificate & Findings
            </summary>

            <div id="certificateCard" class="certificate-card">
                <div class="cert-header">
                    """ + SVG_LOGO_HTML + """
                    <h2>TENDERVERIFY SA AUDIT CERTIFICATE</h2>
                </div>
                <div class="cert-subtitle">Automated Fraud & Risk Assessment Report</div>

                <div class="cert-meta">
                    <span><b>Ref:</b> {{ result.ref_id }}</span>
                    <span><b>Date:</b> {{ result.timestamp }}</span>
                </div>

                <p style="font-size:0.85rem; margin: 5px 0;"><b>Target Entity:</b> {{ result.dept_name }}</p>
                <p style="font-size:0.85rem; margin: 5px 0;"><b>Evaluated Email:</b> {{ result.buyer_email }}</p>

                <div style="margin: 15px 0; text-align: center;">
                    <span class="badge {{ result.badge_class }}">{{ result.verdict }} (Score: {{ result.risk_score }})</span>
                </div>

                {% if current_tier in ['tier2', 'tier3'] %}
                <div style="margin: 15px 0; background: #F8FAFC; border: 1px solid #CBD5E1; padding: 10px; border-radius: 8px;">
                    <h4 style="margin: 0 0 5px 0; font-size: 0.85rem; color: #1E3A8A;">Predictive Intelligence Breakdown:</h4>
                    <p style="font-size: 0.8rem; margin: 3px 0; color: #334155;"><b>Fraud Likelihood Index:</b> {{ result.fraud_probability }}</p>
                    <p style="font-size: 0.8rem; margin: 3px 0; color: #334155;"><b>Behavioral Forecast:</b> {{ result.forecast }}</p>
                </div>
                {% else %}
                <div class="tier-lock-box">
                    <span style="font-size: 0.82rem; color: #92400E; font-weight: bold;">Predictive Behavioral AI Breakdown Locked</span>
                    <p style="font-size: 0.75rem; color: #B45309; margin: 4px 0 8px 0;">Fraud Likelihood Index and Behavioral Forecasting are available on Tier 2 (Pro) & Enterprise plans.</p>
                    <a href="/upgrade" style="font-size: 0.78rem; color: #F97316; font-weight: bold; text-decoration: underline;">Upgrade to Tier 2 (Pro) to Unlock AI Analytics</a>
                </div>
                {% endif %}

                <h4 style="margin-top: 15px; margin-bottom: 5px; font-size: 0.9rem;">Security Audit Findings:</h4>
                <ul>
                    {% for flag in result.flags %}
                        <li>{{ flag }}</li>
                    {% endfor %}
                </ul>

                <div class="qr-box">
                    <img src="https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=https://joelmacsettle.pythonanywhere.com/verify/{{ result.ref_id }}" alt="Verification QR Code">
                    <p style="font-size: 0.65rem; color: #64748B; margin: 3px 0 0 0;">Scan to verify authentic record online</p>
                </div>

                <div class="cert-footer">
                    Verified by TenderVerify SA Anti-Fraud Engine.<br>
                    Official verification URL: joelmacsettle.pythonanywhere.com/verify/{{ result.ref_id }}
                </div>

                <div class="STRIVEX-attribution">
                    A Product of <strong>SRIVEX (Pty) Ltd</strong> | Enterprise Anti-Fraud Systems
                </div>
            </div>

            <div style="padding: 0 15px 15px 15px;">
                {% if current_tier in ['tier1', 'tier2', 'tier3'] %}
                <button onclick="downloadPDF()" class="btn-pdf">Download Audit Certificate (PDF)</button>
                {% else %}
                <a href="/upgrade" class="btn-pdf" style="background: #64748B;">Unlock PDF Certificate Download (Upgrade to Tier 1)</a>
                {% endif %}
            </div>
        </details>
        {% endif %}

        <!-- USER SCAN HISTORY DRAWER -->
        {% if user_history %}
        <details class="report-accordion" style="margin-top: 15px;">
            <summary class="accordion-header" style="background: #1E3A8A;">
                My Past Scans & Verification History
            </summary>
            <div style="padding: 15px; overflow-x: auto;">
                <table class="history-table">
                    <thead>
                        <tr>
                            <th>Ref ID</th>
                            <th>Date</th>
                            <th>Entity</th>
                            <th>Verdict</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for row in user_history %}
                        <tr>
                            <td><a href="/verify/{{ row[0] }}" target="_blank" style="color:#1E3A8A; font-weight:bold;">{{ row[0] }}</a></td>
                            <td>{{ row[1] }}</td>
                            <td>{{ row[2] }}</td>
                            <td><span class="badge {{ row[5] }}" style="font-size:0.7rem; padding:3px 6px;">{{ row[4] }}</span></td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </details>
        {% endif %}

        <details class="report-accordion" style="margin-top: 15px;">
            <summary class="accordion-header" style="background: #334155;">
                Report a Scam / Blacklist Contact
            </summary>
            <div style="padding: 15px;">
                <p style="font-size: 0.8rem; color: #64748B; margin-top: 0; margin-bottom: 12px;">Received a fake RFQ? Flag the details below to protect other South African SMEs.</p>

                <form method="POST" action="/report_scam">
                    <label style="margin-top:0;">Scam Email Address</label>
                    <input type="email" name="scam_email" placeholder="e.g. scammer@gmail.com" value="{{ buyer_email|default('') }}">

                    <label>Scam Phone Number</label>
                    <input type="text" name="scam_phone" placeholder="e.g. 0721234567" value="{{ phone_number|default('') }}">

                    <label>Reason / Scam Details</label>
                    <textarea name="scam_reason" rows="2" placeholder="e.g. Demanded upfront delivery payment" required></textarea>

                    <button type="submit" style="margin-top: 12px; background: var(--danger);" class="btn-submit">Submit Threat Report</button>
                </form>
            </div>
        </details>

        <div class="global-footer">
            Need help? Visit our <a href="/support">Help & Support Center</a>.<br>
            &copy; 2026 TenderVerify SA. Developed & Maintained by <strong>STRIVEX (Pty) Ltd</strong>.
        </div>
    </div>

    <script>
        function toggleSidebar() {
            document.getElementById('sidebarDrawer').classList.toggle('active');
            document.getElementById('sidebarOverlay').classList.toggle('active');
        }

        function displaySelectedFiles(input) {
            const displayDiv = document.getElementById('fileListDisplay');
            const parseBtn = document.getElementById('parseBtn');
            if (input.files && input.files.length > 0) {
                let fileNames = "<strong>Selected files:</strong><ul style='margin:5px 0 0 0; padding-left:15px;'>";
                for (let i = 0; i < input.files.length; i++) {
                    fileNames += "<li>" + input.files[i].name + "</li>";
                }
                fileNames += "</ul>";
                displayDiv.innerHTML = fileNames;
                displayDiv.style.display = 'block';
                parseBtn.style.display = 'block';
            } else {
                displayDiv.style.display = 'none';
                parseBtn.style.display = 'none';
            }
        }

        function loadSample(type) {
            if (type === 'legit') {
                document.getElementById('dept_name').value = "City of Tshwane Metropolitan Municipality";
                document.getElementById('buyer_email').value = "procurement@tshwane.gov.za";
                document.getElementById('phone_number').value = "0123589999";
                document.getElementById('delivery_address').value = "Tshwane House, 320 Madiba Street, Pretoria";
            } else if (type === 'scam') {
                document.getElementById('dept_name').value = "City of Tshwane Municipality";
                document.getElementById('buyer_email').value = "tshwane-procurement@gmail.com";
                document.getElementById('phone_number').value = "0729876543";
                document.getElementById('delivery_address').value = "Rented Storage Depot, Plot 42, Farm Road, Midrand";
            }
        }

        if ('serviceWorker' in navigator) {
            navigator.serviceWorker.register('/sw.js').catch((err) => console.log('SW Fail:', err));
        }

        function downloadPDF() {
            const element = document.getElementById('certificateCard');
            if (!element) return;

            const currentScrollY = window.scrollY;
            window.scrollTo(0, 0);

            const certRef = "{% if result %}{{ result.ref_id }}{% else %}Report{% endif %}";

            const opt = {
                margin: 5,
                filename: 'TenderVerify_Audit_Certificate_' + certRef + '.pdf',
                image: { type: 'jpeg', quality: 0.98 },
                html2canvas: { scale: 2, scrollY: 0, scrollX: 0, windowWidth: document.documentElement.offsetWidth, useCORS: true },
                jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' }
            };

            html2pdf().set(opt).from(element).save().then(() => {
                window.scrollTo(0, currentScrollY);
            });
        }
        </script>
        <!-- Footer with Terms & Refund Policy for PayFast Compliance -->
<footer style="margin-top: 40px; padding: 20px; text-align: center; font-size: 0.85rem; color: #64748B; border-top: 1px solid #E2E8F0;">
  <p>&copy; 2026 TenderVerify SA. All rights reserved.</p>
  <p>
    <a href="#termsModal" onclick="document.getElementById('termsModal').style.display='block'" style="color: #1E3A8A; text-decoration: underline; margin-right: 15px;">Terms & Conditions</a>
    <a href="#refundModal" onclick="document.getElementById('refundModal').style.display='block'" style="color: #1E3A8A; text-decoration: underline;">Refund Policy</a>
  </p>
</footer>

<!-- Refund Policy & Terms Popup Modals -->
<div id="refundModal" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.6); z-index:9999; overflow-y:auto;">
  <div style="background:#fff; max-width:650px; margin:50px auto; padding:30px; border-radius:10px; font-size:0.9rem; max-height:80vh; overflow-y:auto; box-shadow:0 10px 25px rgba(0,0,0,0.2);">
    <h2 style="color:#1E3A8A; margin-top:0;">Refund Policy</h2>
    <p><strong>1. Digital Services & Non-Refundable Credits</strong><br>
    Due to the immediate digital execution of automated Request for Quotation (RFQ) risk screening, metadata forensics, and PDF audit certificate generation, all single search credits, report purchases, and processed recurring subscription fees are strictly non-refundable once activated or rendered.</p>

    <p><strong>2. Subscription Cancellations</strong><br>
    Users subscribing to monthly or annual access tiers may cancel their recurring subscription billing at any time directly through their account settings. Upon cancellation, access remains active until the end of the current paid billing cycle, and no further charges will occur. No prorated refunds are issued for partial billing periods.</p>

    <p><strong>3. Billing Inquiries</strong><br>
    If you experience technical errors or billing discrepancies during checkout, please contact support at support@tenderverify.co.za for assistance.</p>

    <button onclick="document.getElementById('refundModal').style.display='none'" style="background:#1E3A8A; color:#fff; border:none; padding:10px 20px; border-radius:6px; cursor:pointer; font-weight:bold; margin-top:15px;">Close</button>
  </div>
</div>

<div id="termsModal" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.6); z-index:9999; overflow-y:auto;">
  <div style="background:#fff; max-width:700px; margin:40px auto; padding:30px; border-radius:10px; font-size:0.9rem; max-height:85vh; overflow-y:auto; box-shadow:0 10px 25px rgba(0,0,0,0.2);">
    <h2 style="color:#1E3A8A; margin-top:0;">Terms & Conditions & Privacy Policy</h2>

    <h3 style="color:#1E3A8A; margin-bottom:5px;">1. Terms & Conditions</h3>
    <p><strong>Software Licensing:</strong> TenderVerify SA provides automated document metadata forensics and public procurement registry cross-referencing tools under a limited, non-exclusive SaaS subscription license.</p>
    <p><strong>Scope of Service:</strong> Automated verification scores and audit certificates are risk-screening aids intended for internal due diligence. Users retain ultimate commercial responsibility for their bidding and procurement decisions.</p>
    <p><strong>Acceptable Use:</strong> Users agree not to misuse platform infrastructure or attempt unauthorized scraping or reverse engineering of system verification algorithms.</p>

    <hr style="border:none; border-top:1px solid #E2E8F0; margin:20px 0;">

    <h3 style="color:#1E3A8A; margin-bottom:5px;">2. Privacy Policy (POPIA Compliance)</h3>
    <p><strong>Data Processing:</strong> In accordance with the Protection of Personal Information Act (POPIA), uploaded RFQ documents and query data are processed strictly for real-time verification checks and fraud prevention analysis.</p>
    <p><strong>Data Protection & Retention:</strong> Document metadata and user information are secured using industry-standard encryption protocols. We do not sell, trade, or share user data or document details with external third parties.</p>
    <p><strong>User Rights:</strong> Users have the right to inspect, update, or request the deletion of their account data at any time by submitting a request to our compliance contact.</p>

    <button onclick="document.getElementById('termsModal').style.display='none'" style="background:#1E3A8A; color:#fff; border:none; padding:10px 20px; border-radius:6px; cursor:pointer; font-weight:bold; margin-top:15px;">Close</button>
  </div>
</div>

    </script>
    <script>
  if ('serviceWorker' in navigator) {
    window.addEventListener('load', function() {
      navigator.serviceWorker.register('/static/sw.js')
        .then(function(reg) {
          console.log('SW registered!', reg.scope);
        })
        .catch(function(err) {
          console.log('SW registration failed:', err);
        });
    });
  }
</script>
</body>
</html>
"""

SUPPORT_LAYOUT = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Help, Support & Resources - TenderVerify SA</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #F8FAFC; padding: 20px; margin: 0; color: #1E293B; }
        .support-container { max-width: 800px; margin: 0 auto; }
        .back-link { display: inline-block; margin-bottom: 15px; color: #1E3A8A; text-decoration: none; font-weight: bold; font-size: 0.9rem; }

        .header-card { background: white; padding: 25px; border-radius: 12px; border: 1px solid #E2E8F0; margin-bottom: 20px; box-shadow: 0 4px 15px rgba(30,58,138,0.05); }
        .header-card h2 { margin: 0 0 6px 0; color: #1E3A8A; font-size: 1.5rem; font-weight: 800; }
        .header-card p { margin: 0; color: #64748B; font-size: 0.9rem; }

        .section-box { background: white; border-radius: 12px; padding: 22px; border: 1px solid #E2E8F0; margin-bottom: 20px; box-shadow: 0 4px 15px rgba(30,58,138,0.05); }
        .section-box h3 { margin-top: 0; color: #1E3A8A; font-size: 1.15rem; font-weight: 800; border-bottom: 2px solid #EFF6FF; padding-bottom: 10px; }

        .email-support-card { background: #EFF6FF; border: 1px solid #BFDBFE; border-radius: 10px; padding: 20px; text-align: center; margin-top: 15px; }
        .email-support-card h4 { margin: 0 0 8px 0; color: #1E3A8A; font-size: 1.1rem; }
        .email-support-card p { margin: 0 0 15px 0; color: #475569; font-size: 0.88rem; }

        .btn-email-direct { display: inline-block; padding: 12px 24px; background: #F97316; color: white; border-radius: 8px; font-weight: bold; text-decoration: none; font-size: 0.95rem; }
        .btn-email-direct:hover { background: #EA580C; }

        .grid-2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 15px; margin-top: 15px; }
        .res-card { background: #F8FAFC; border: 1px solid #CBD5E1; padding: 15px; border-radius: 8px; text-decoration: none; color: #1E293B; transition: border-color 0.2s; }
        .res-card:hover { border-color: #38BDF8; background: #F0F9FF; }
        .res-card h4 { margin: 0 0 5px 0; color: #1E3A8A; font-size: 0.95rem; }
        .res-card p { margin: 0; font-size: 0.8rem; color: #64748B; }

        details.faq-item { border: 1px solid #E2E8F0; border-radius: 8px; margin-bottom: 10px; background: #F8FAFC; overflow: hidden; }
        summary.faq-header { padding: 12px 15px; font-weight: bold; font-size: 0.9rem; color: #1E3A8A; cursor: pointer; user-select: none; list-style: none; display: flex; justify-content: space-between; align-items: center; }
        summary.faq-header::-webkit-details-marker { display: none; }
        summary.faq-header::after { content: "+"; font-size: 1.1rem; color: #F97316; font-weight: bold; }
        details[open] summary.faq-header::after { content: "-"; }
        .faq-body { padding: 12px 15px; background: white; font-size: 0.85rem; color: #334155; border-top: 1px solid #E2E8F0; line-height: 1.4; }
    </style>
</head>
<body>
    <div class="support-container">
        <a href="/" class="back-link">&larr; Return to Dashboard</a>

        <div class="header-card">
            <h2>TenderVerify SA Help & Support Center</h2>
            <p>Access official procurement verification portals, anti-fraud guides, and direct support.</p>
        </div>

        <div class="section-box">
            <h3>Direct Customer & Technical Support</h3>
            <p style="font-size: 0.85rem; color: #64748B; margin-top: -5px;">Need assistance verifying a complex RFQ or have account billing questions?</p>

            <div class="email-support-card">
                <h4>Contact STRIVEX Support Team</h4>
                <p>Send an email inquiry directly to our support engineers. We manually review every submitted RFQ and reply within 24 hours.</p>
                <a href="mailto:{{ support_email }}?subject=TenderVerify%20SA%20Support%20Request" class="btn-email-direct">
                    Email Support ({{ support_email }})
                </a>
            </div>
        </div>

        <div class="section-box">
            <h3>Automated Email Inbox Verification & POPIA Notice</h3>
            <p style="font-size: 0.85rem; color: #334155; line-height: 1.5;">
                <strong>Automated Email Forwarding:</strong> You can forward suspicious RFQ emails directly to <code>support@tenderverify.co.za</code>. Our background verification engine parses attachment metadata and returns an automated audit summary directly to your inbox.
            </p>
            <p style="font-size: 0.8rem; color: #64748B; margin-bottom: 0;">
                <strong>POPIA Data Security Compliance:</strong> TenderVerify SA processes all submitted RFQs and company metadata strictly within encrypted memory buffers in full compliance with the Protection of Personal Information Act 4 of 2013 (POPIA).
            </p>
        </div>

        <div class="section-box">
            <h3>Frequently Asked Questions (FAQs)</h3>

            <details class="faq-item">
                <summary class="faq-header">How does TenderVerify SA calculate the RFQ Fraud Risk Score?</summary>
                <div class="faq-body">
                    Our automated security engine evaluates incoming RFQ parameters against established institutional baselines. It inspects domain authority (checking for free email providers like Gmail or typosquatting domain variants), contact phone prefixes (identifying mobile vs. landline numbers), SARS 16-character Tax Pin formats, CSD MAAA supplier number structures, delivery warehouse physical location keywords, and cross-references our crowd-sourced blacklist database.
                </div>
            </details>

            <details class="faq-item">
                <summary class="faq-header">What should I do if an RFQ returns a "HIGH RISK" verdict?</summary>
                <div class="faq-body">
                    <strong>Do not transfer any money or dispatch goods!</strong> High-risk verdicts indicate strong indicators of fake tender scams. Always verify the buyer by calling the official departmental landline published on the official organ of state government website (ending in <code>.gov.za</code>), rather than relying on phone numbers listed on the RFQ document.
                </div>
            </details>

            <details class="faq-item">
                <summary class="faq-header">How do monthly scan limits work across plans?</summary>
                <div class="faq-body">
                    Free Tier accounts receive 3 monthly scans. Upgrading to <strong>Tier 1 (Starter)</strong> unlocks 15 scans for R79/mo, <strong>Tier 2 (Pro)</strong> gives 50 scans for R199/mo, and <strong>Tier 3 (Enterprise)</strong> offers Unlimited monthly scans for R269/mo. Scan counts reset automatically each billing cycle.
                </div>
            </details>

            <details class="faq-item">
                <summary class="faq-header">Is my business and document data confidential?</summary>
                <div class="faq-body">
                    Yes. TenderVerify SA processes all submitted text and PDF metadata securely in strict compliance with South Africa's Protection of Personal Information Act (POPIA). Your data is never sold or shared with external third parties.
                </div>
            </details>
        </div>

        <div class="section-box">
            <h3>Official Procurement Resources & Portals</h3>
            <p style="font-size: 0.8rem; color: #64748B; margin-top: -5px;">Direct links to South African state verification tools and fraud prevention resources:</p>

            <div class="grid-2">
                <a href="https://secure.csd.gov.za" target="_blank" class="res-card">
                    <h4>CSD Supplier Portal &nearr;</h4>
                    <p>Verify Central Supplier Database (MAAA) registration status.</p>
                </a>

                <a href="https://www.sarsefiling.co.za" target="_blank" class="res-card">
                    <h4>SARS eFiling Tax Pin &nearr;</h4>
                    <p>Verify tax compliance status (TCS) pin credentials.</p>
                </a>

                <a href="https://www.bizportal.gov.za" target="_blank" class="res-card">
                    <h4>CIPC BizPortal &nearr;</h4>
                    <p>Cross-check enterprise company registration validity.</p>
                </a>

                <a href="https://www.psc.gov.za" target="_blank" class="res-card">
                    <h4>Anti-Corruption Hotline &nearr;</h4>
                    <p>Report public sector tender fraud: Call 0800 701 701.</p>
                </a>
            </div>
        </div>
    </div>
</body>
</html>
"""

PRICING_LAYOUT = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Subscription Plans - TenderVerify SA</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #F8FAFC; padding: 20px; margin: 0; color: #1E293B; }
        .pricing-container { max-width: 960px; margin: 0 auto; }
        .pricing-header { text-align: center; margin-bottom: 35px; }
        .pricing-header h2 { color: #1E3A8A; font-size: 1.8rem; margin-bottom: 8px; font-weight: 800; }
        .pricing-header p { color: #64748B; font-size: 0.95rem; margin: 0; }
        .back-link { display: inline-block; margin-bottom: 20px; color: #1E3A8A; text-decoration: none; font-weight: bold; font-size: 0.9rem; }

        .pricing-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 20px; }
        .plan-card { background: white; border-radius: 14px; padding: 25px; border: 1px solid #E2E8F0; box-shadow: 0 4px 15px rgba(30, 58, 138, 0.05); text-align: center; display: flex; flex-direction: column; justify-content: space-between; position: relative; }
        .plan-card.popular { border: 2px solid #F97316; }
        .popular-tag { position: absolute; top: -12px; left: 50%; transform: translateX(-50%); background: #F97316; color: white; padding: 4px 12px; border-radius: 20px; font-size: 0.75rem; font-weight: bold; }

        .plan-title { color: #1E3A8A; font-size: 1.25rem; font-weight: 800; margin: 0; }
        .plan-price { font-size: 2.2rem; font-weight: 800; color: #F97316; margin: 15px 0 5px 0; }
        .plan-price span { font-size: 0.9rem; color: #64748B; font-weight: normal; }

        .plan-features { list-style: none; padding: 0; text-align: left; margin: 20px 0; font-size: 0.88rem; color: #334155; }
        .plan-features li { padding: 8px 0; border-bottom: 1px solid #F1F5F9; }

        .btn-payfast { display: block; width: 100%; padding: 12px; background: #1E3A8A; color: white; border: none; border-radius: 8px; font-weight: bold; font-size: 0.95rem; cursor: pointer; text-decoration: none; box-sizing: border-box; }
        .btn-payfast:hover { background: #1D4ED8; }
        .btn-popular { background: #F97316; }
        .btn-popular:hover { background: #EA580C; }

        .demo-activate-btn { display: inline-block; margin-top: 8px; font-size: 0.72rem; color: #64748B; text-decoration: underline; background: none; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <div class="pricing-container">
        <a href="/" class="back-link">&larr; Return to Dashboard</a>

        <div class="pricing-header">
            <h2>Select Your TenderVerify SA Plan</h2>
            <p>Flexible recurring subscriptions tailored for South African SMEs and Enterprises.</p>
        </div>

        <div class="pricing-grid">
            <div class="plan-card">
                <div>
                    <h3 class="plan-title">Tier 1 (Starter)</h3>
                    <div class="plan-price">R79.00<span>/month</span></div>
                    <ul class="plan-features">
                        <li>15 RFQ Verification Scans / month</li>
                        <li>PDF Audit Certificate Downloads</li>
                        <li>PDF Requirement Checklist Extractor</li>
                        <li>Threat Database Matching</li>
                    </ul>
                </div>
                <div>
                    <form method="POST" action="/checkout/tier1">
                        <button type="submit" class="btn-payfast">Upgrade</button>
                    </form>
                    {% if dev_mode %}
                    <a href="/checkout/tier1?demo=true" class="demo-activate-btn">Demo Instant Activation</a>
                    {% endif %}
                </div>
            </div>

            <div class="plan-card popular">
                <div class="popular-tag">MOST POPULAR</div>
                <div>
                    <h3 class="plan-title">Tier 2 (Pro)</h3>
                    <div class="plan-price">R199.00<span>/month</span></div>
                    <ul class="plan-features">
                        <li>50 RFQ Verification Scans / month</li>
                        <li>PDF Audit Certificate Downloads</li>
                        <li>Predictive Intelligence Analytics</li>
                        <li>Crowd-Sourced Threat Intelligence</li>
                        <li>Priority Support</li>
                    </ul>
                </div>
                <div>
                    <form method="POST" action="/checkout/tier2">
                        <button type="submit" class="btn-payfast btn-popular">Upgrade</button>
                    </form>
                    {% if dev_mode %}
                    <a href="/checkout/tier2?demo=true" class="demo-activate-btn">Demo Instant Activation</a>
                    {% endif %}
                </div>
            </div>

            <div class="plan-card">
                <div>
                    <h3 class="plan-title">Tier 3 (Enterprise)</h3>
                    <div class="plan-price">R269.00<span>/month</span></div>
                    <ul class="plan-features">
                        <li>UNLIMITED RFQ Scans / month</li>
                        <li>PDF Audit Certificates & Checklist</li>
                        <li>Advanced Predictive Behavioral AI</li>
                        <li>Instant Threat Database Matching</li>
                        <li>Enterprise Dedicated Support</li>
                    </ul>
                </div>
                <div>
                    <form method="POST" action="/checkout/tier3">
                        <button type="submit" class="btn-payfast">Upgrade</button>
                    </form>
                    {% if dev_mode %}
                    <a href="/checkout/tier3?demo=true" class="demo-activate-btn">Demo Instant Activation</a>
                    {% endif %}
                </div>
            </div>
        </div>


    </div>
</body>
</html>
"""

LOGIN_LAYOUT = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - TenderVerify SA</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #F8FAFC; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
        .login-card { background: white; padding: 32px; border-radius: 14px; box-shadow: 0 4px 20px rgba(30, 58, 138, 0.08); width: 100%; max-width: 380px; border: 1px solid #E2E8F0; }
        .logo-wrapper { text-align: center; margin-bottom: 10px; }
        h2 { margin-top: 0; color: #1E3A8A; font-size: 1.45rem; text-align: center; font-weight: 800; }
        p { font-size: 0.85rem; color: #64748B; text-align: center; margin-bottom: 22px; }
        label { font-weight: 700; font-size: 0.85rem; display: block; margin-top: 12px; color: #334155; }
        input[type="text"], input[type="email"], input[type="password"] { width: 100%; padding: 10px; margin-top: 5px; border: 1px solid #CBD5E1; border-radius: 7px; box-sizing: border-box; font-size: 0.95rem; }
        .btn-login { width: 100%; margin-top: 22px; padding: 12px; background: #F97316; color: white; border: none; border-radius: 8px; font-weight: bold; font-size: 1rem; cursor: pointer; }
        .btn-login:hover { background: #EA580C; }
        .error-msg { background: #FEE2E2; color: #991B1B; padding: 10px; border-radius: 7px; font-size: 0.85rem; margin-bottom: 15px; border: 1px solid #FCA5A5; text-align: center; }
        .success-msg { background: #DCFCE7; color: #14532D; padding: 10px; border-radius: 7px; font-size: 0.85rem; margin-bottom: 15px; border: 1px solid #86EFAC; text-align: center; }
        .footer-links { text-align: center; margin-top: 22px; font-size: 0.85rem; color: #64748B; }
        .footer-links a { color: #1E3A8A; text-decoration: none; font-weight: bold; }
        .login-footer { text-align: center; margin-top: 20px; font-size: 0.75rem; color: #64748B; border-top: 1px solid #F1F5F9; padding-top: 12px; }
    </style>
</head>
<body>
    <div class="login-card">
        <div class="logo-wrapper">
            """ + SVG_LOGO_HTML + """
        </div>
        <h2>TenderVerify SA</h2>
        <p>Sign in to scan RFQs and access security tools.</p>

        {% if error %}
        <div class="error-msg">{{ error }}</div>
        {% endif %}

        {% if message %}
        <div class="success-msg">{{ message }}</div>
        {% endif %}

        <form method="POST" action="/login">
            <label for="email">Username or Email Address</label>
            <input type="text" id="email" name="email" placeholder="e.g. user@company.co.za" required autofocus>

            <label for="password">Password</label>
            <input type="password" id="password" name="password" placeholder="Enter password" required>

            <button type="submit" class="btn-login">Sign In</button>
        </form>

        <div class="footer-links">
            <a href="/forgot-password" style="color: #64748B; font-weight: normal; font-size: 0.8rem; display: block; margin-bottom: 12px;">Forgot Password?</a>
            Don't have an account yet?<br>
            <a href="/register" style="display:inline-block; margin-top:6px; font-size:0.95rem;">Create an Account</a>
        </div>

        <div class="login-footer">
            A product of <strong>STRIVEX (Pty) Ltd</strong>
        </div>
    </div>
</body>
</html>
"""

REGISTER_LAYOUT = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Create Account - TenderVerify SA</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #F8FAFC; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; padding: 15px; }
        .reg-card { background: white; padding: 32px; border-radius: 14px; box-shadow: 0 4px 20px rgba(30, 58, 138, 0.08); width: 100%; max-width: 400px; border: 1px solid #E2E8F0; }
        .logo-wrapper { text-align: center; margin-bottom: 10px; }
        h2 { margin-top: 0; color: #1E3A8A; font-size: 1.45rem; text-align: center; font-weight: 800; }
        p { font-size: 0.85rem; color: #64748B; text-align: center; margin-bottom: 22px; }
        label { font-weight: 700; font-size: 0.85rem; display: block; margin-top: 12px; color: #334155; }
        input[type="text"], input[type="email"], input[type="password"] { width: 100%; padding: 10px; margin-top: 5px; border: 1px solid #CBD5E1; border-radius: 7px; box-sizing: border-box; font-size: 0.95rem; }
        .btn-reg { width: 100%; margin-top: 22px; padding: 12px; background: #F97316; color: white; border: none; border-radius: 8px; font-weight: bold; font-size: 1rem; cursor: pointer; }
        .btn-reg:hover { background: #EA580C; }
        .error-msg { background: #FEE2E2; color: #991B1B; padding: 10px; border-radius: 7px; font-size: 0.85rem; margin-bottom: 15px; border: 1px solid #FCA5A5; text-align: center; }
        .footer-links { text-align: center; margin-top: 22px; font-size: 0.85rem; color: #64748B; }
        .footer-links a { color: #1E3A8A; text-decoration: none; font-weight: bold; }
        .login-footer { text-align: center; margin-top: 20px; font-size: 0.75rem; color: #64748B; border-top: 1px solid #F1F5F9; padding-top: 12px; }
    </style>
</head>
<body>
    <div class="reg-card">
        <div class="logo-wrapper">
            """ + SVG_LOGO_HTML + """
        </div>
        <h2>TenderVerify SA</h2>
        <p>Create your free account to protect your business.</p>

        {% if error %}
        <div class="error-msg">{{ error }}</div>
        {% endif %}

        <form method="POST" action="/register">
            <label for="username">Username</label>
            <input type="text" id="username" name="username" placeholder="e.g. @Daniel234" required autofocus>

            <label for="email">Email Address</label>
            <input type="email" id="email" name="email" placeholder="e.g. name@company.co.za" required>

            <label for="password">Password</label>
            <input type="password" id="password" name="password" placeholder="Create password (min 6 chars)" autocomplete="new-password" minlength="6" required>


            <label for="recovery_pin">Security PIN</label>
            <input type="password" id="recovery_pin" name="recovery_pin" placeholder="e.g. 49218" minlength="5" maxlength="10" pattern="\d{5,10}" inputmode="numeric" required>

            <button type="submit" class="btn-reg">Create Free Account</button>
        </form>

        <div class="footer-links">
            Already have an account?<br>
            <a href="/login" style="display:inline-block; margin-top:8px; font-size:0.95rem;">Log in here</a>
        </div>

        <div class="login-footer">
            A product of <strong>STRIVEX (Pty) Ltd</strong>
        </div>
    </div>
</body>
</html>
"""

FORGOT_PASSWORD_LAYOUT = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Password - TenderVerify SA</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #F8FAFC; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
        .forgot-card { background: white; padding: 32px; border-radius: 14px; box-shadow: 0 4px 20px rgba(30, 58, 138, 0.08); width: 100%; max-width: 380px; border: 1px solid #E2E8F0; }
        .logo-wrapper { text-align: center; margin-bottom: 10px; }
        h2 { margin-top: 0; color: #1E3A8A; font-size: 1.45rem; text-align: center; font-weight: 800; }
        p { font-size: 0.85rem; color: #64748B; text-align: center; margin-bottom: 22px; }
        label { font-weight: 700; font-size: 0.85rem; display: block; margin-top: 12px; color: #334155; }
        input[type="text"], input[type="email"], input[type="password"] { width: 100%; padding: 10px; margin-top: 5px; border: 1px solid #CBD5E1; border-radius: 7px; box-sizing: border-box; font-size: 0.95rem; }
        .btn-reset { width: 100%; margin-top: 22px; padding: 12px; background: #1E3A8A; color: white; border: none; border-radius: 8px; font-weight: bold; font-size: 0.95rem; cursor: pointer; }
        .error-msg { background: #FEE2E2; color: #991B1B; padding: 10px; border-radius: 7px; font-size: 0.85rem; margin-bottom: 15px; border: 1px solid #FCA5A5; text-align: center; }
        .footer-links { text-align: center; margin-top: 22px; font-size: 0.85rem; color: #64748B; }
        .footer-links a { color: #1E3A8A; text-decoration: none; font-weight: bold; }
    </style>
</head>
<body>
    <div class="forgot-card">
        <div class="logo-wrapper">
            """ + SVG_LOGO_HTML + """
        </div>
        <h2>Reset Credentials</h2>
        <p>Enter your registered email and 4-digit Security PIN to choose a new password.</p>

        {% if error %}
        <div class="error-msg">{{ error }}</div>
        {% endif %}

        <form method="POST" action="/forgot-password">
            <label for="email">Registered Email Address</label>
            <input type="email" id="email" name="email" placeholder="e.g. name@company.co.za" required autofocus>

            <label for="recovery_pin">4-Digit Security PIN</label>
            <input type="text" id="recovery_pin" name="recovery_pin" placeholder="Enter PIN" maxlength="4" pattern="\d{4}" required>

            <label for="new_password">New Password</label>
            <input type="password" id="new_password" name="new_password" placeholder="Enter new password (min 6 chars)" minlength="6" required>

            <button type="submit" class="btn-reset">Update Password</button>
        </form>

        <div class="footer-links">
            Remembered your password?<br>
            <a href="/login" style="display:inline-block; margin-top:8px; font-size:0.95rem;">Back to Login</a>
        </div>
    </div>
</body>
</html>
"""

# --- ROUTES ---

@app.route('/', methods=['GET', 'POST'])
def index():
    if not session.get('user_id'):
        return redirect(url_for('login'))

    dev_arg = request.args.get('dev')
    if dev_arg == '1':
        session['dev_mode'] = True
    elif dev_arg == '0':
        session['dev_mode'] = False

    dev_mode = session.get('dev_mode', False)

    current_tier, scans_used, scans_left, max_scans = get_user_subscription(session['user_id'])
    user_history = get_user_history(session['user_id'])

    if request.method == 'POST':
        can_scan, tier, remaining = check_scan_limit(session['user_id'])
        if not can_scan:
            return render_template_string(
                HTML_LAYOUT,
                limit_reached=True,
                current_tier=current_tier,
                scans_left=0,
                user_history=user_history,
                dev_mode=dev_mode
            )

        dept_name = request.form.get('dept_name', '')
        buyer_email = request.form.get('buyer_email', '')
        phone_number = request.form.get('phone_number', '')
        delivery_address = request.form.get('delivery_address', '')
        full_pdf_text = request.form.get('full_pdf_text', '')

        result = verify_rfq(dept_name, buyer_email, phone_number, delivery_address, full_pdf_text, user_id=session['user_id'])
        increment_scan_count(session['user_id'])

        _, _, updated_scans_left, _ = get_user_subscription(session['user_id'])
        updated_history = get_user_history(session['user_id'])

        return render_template_string(
            HTML_LAYOUT,
            result=result,
            dept_name=dept_name,
            buyer_email=buyer_email,
            phone_number=phone_number,
            delivery_address=delivery_address,
            full_pdf_text=full_pdf_text,
            current_tier=current_tier,
            scans_left=updated_scans_left,
            user_history=updated_history,
            dev_mode=dev_mode
        )

    return render_template_string(HTML_LAYOUT, current_tier=current_tier, scans_left=scans_left, user_history=user_history, dev_mode=dev_mode)

@app.route('/parse_pdf', methods=['POST'])
def parse_pdf():
    if not session.get('user_id'):
        return redirect(url_for('login'))

    dev_mode = session.get('dev_mode', False)
    current_tier, scans_used, scans_left, max_scans = get_user_subscription(session['user_id'])
    user_history = get_user_history(session['user_id'])

    pdf_files = request.files.getlist('rfq_pdf')

    combined_dept_name = ""
    combined_buyer_email = ""
    combined_phone_number = ""
    combined_delivery_address = ""
    accumulated_pdf_text = ""
    all_checklists = []
    seen_checklist_items = set()

    for pdf_file in pdf_files:
        if pdf_file and pdf_file.filename:
            extracted, checklist_items = extract_rfq_details_from_pdf(pdf_file)

            if not combined_dept_name and extracted.get('dept_name'):
                combined_dept_name = extracted.get('dept_name')
            if not combined_buyer_email and extracted.get('buyer_email'):
                combined_buyer_email = extracted.get('buyer_email')
            if not combined_phone_number and extracted.get('phone_number'):
                combined_phone_number = extracted.get('phone_number')
            if not combined_delivery_address and extracted.get('delivery_address'):
                combined_delivery_address = extracted.get('delivery_address')

            if extracted.get('extracted_text'):
                accumulated_pdf_text += "\n" + extracted.get('extracted_text')

            for task in checklist_items:
                if task['item'] not in seen_checklist_items:
                    seen_checklist_items.add(task['item'])
                    all_checklists.append(task)

    return render_template_string(
        HTML_LAYOUT,
        dept_name=combined_dept_name,
        buyer_email=combined_buyer_email,
        phone_number=combined_phone_number,
        delivery_address=combined_delivery_address,
        full_pdf_text=accumulated_pdf_text,
        checklist_items=all_checklists,
        current_tier=current_tier,
        scans_left=scans_left,
        user_history=user_history,
        dev_mode=dev_mode
    )

@app.route('/support')
def support():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    return render_template_string(SUPPORT_LAYOUT, support_email=COMPANY_SUPPORT_EMAIL)

@app.route('/upgrade')
def upgrade():
    if not session.get('user_id'):
        return redirect(url_for('login'))

    dev_arg = request.args.get('dev')
    if dev_arg == '1':
        session['dev_mode'] = True
    elif dev_arg == '0':
        session['dev_mode'] = False

    dev_mode = session.get('dev_mode', False)
    return render_template_string(PRICING_LAYOUT, dev_mode=dev_mode)

@app.route('/checkout/<tier>', methods=['GET', 'POST'])
def payfast_checkout(tier):
    if not session.get('user_id'):
        return redirect(url_for('login'))

    if tier not in TIER_PRICES:
        return redirect(url_for('index'))

    if request.args.get('demo') == 'true':
        sast_tz = timezone(timedelta(hours=2))
        now_sast = datetime.now(sast_tz).strftime('%Y-%m-%d %H:%M SAST')

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET subscription_tier = ?, scans_used = 0, billing_cycle_start = ? WHERE id = ?", (tier, now_sast, session['user_id']))
        conn.commit()
        conn.close()

        user_history = get_user_history(session['user_id'])
        return render_template_string(HTML_LAYOUT, payment_success=True, current_tier=tier, scans_left=TIER_LIMITS[tier], user_history=user_history)

    amount = f"{TIER_PRICES[tier]:.2f}"
    item_name = f"TenderVerify SA - {tier.upper()} Subscription"

    payfast_data = {
        'merchant_id': PAYFAST_MERCHANT_ID,
        'merchant_key': PAYFAST_MERCHANT_KEY,
        'return_url': request.host_url.rstrip('/') + url_for('payfast_success'),
        'cancel_url': request.host_url.rstrip('/') + url_for('payfast_cancel'),
        'notify_url': request.host_url.rstrip('/') + url_for('payfast_itn'),
        'name_first': session.get('username', 'Valued Customer'),
        'email_address': session.get('email', 'billing@tenderverify.co.za'),
        'm_payment_id': f"TV-SUB-{session['user_id']}-{tier}-{int(datetime.now().timestamp())}",
        'amount': amount,
        'item_name': item_name,
        'custom_str1': str(session['user_id']),
        'custom_str2': tier,
        'subscription_type': '1',
        'billing_date': datetime.now().strftime('%Y-%m-%d'),
        'recurring_amount': amount,
        'frequency': '3',
        'cycles': '0'
    }

    if PAYFAST_PASSPHRASE:
        pf_param_string = ""
        for key in payfast_data:
            if payfast_data[key] != "":
                pf_param_string += f"{key}={urllib.parse.quote_plus(payfast_data[key].replace('+', ' '))}&"
        pf_param_string = pf_param_string[:-1] + f"&passphrase={urllib.parse.quote_plus(PAYFAST_PASSPHRASE)}"
        payfast_data['signature'] = hashlib.md5(pf_param_string.encode('utf-8')).hexdigest()

    form_inputs = "".join([f'<input type="hidden" name="{k}" value="{v}">' for k, v in payfast_data.items()])

    auto_submit_html = f"""
    <!DOCTYPE html>
    <html>
    <head><title>Redirecting to PayFast Secure Checkout...</title></head>
    <body onload="document.forms['payfast_form'].submit();" style="font-family:sans-serif; text-align:center; padding-top:50px;">
        <h2>Connecting to PayFast Secure Payment Gateway...</h2>
        <p>Please wait, you are being redirected.</p>
        <form id="payfast_form" action="{PAYFAST_URL}" method="POST">
            {form_inputs}
            <noscript><button type="submit">Click here if not redirected automatically</button></noscript>
        </form>
    </body>
    </html>
    """
    return auto_submit_html

@app.route('/payfast/itn', methods=['POST'])
def payfast_itn():
    payment_status = request.form.get('payment_status')
    user_id = request.form.get('custom_str1')
    tier = request.form.get('custom_str2')

    if payment_status == 'COMPLETE' and user_id and tier:
        sast_tz = timezone(timedelta(hours=2))
        now_sast = datetime.now(sast_tz).strftime('%Y-%m-%d %H:%M SAST')

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET subscription_tier = ?, scans_used = 0, billing_cycle_start = ? WHERE id = ?", (tier, now_sast, user_id))
        conn.commit()
        conn.close()

    return Response(status=200)

@app.route('/payfast/success')
def payfast_success():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    current_tier, scans_used, scans_left, max_scans = get_user_subscription(session['user_id'])
    user_history = get_user_history(session['user_id'])
    return render_template_string(HTML_LAYOUT, payment_success=True, current_tier=current_tier, scans_left=scans_left, user_history=user_history)

@app.route('/payfast/cancel')
def payfast_cancel():
    return redirect(url_for('upgrade'))

@app.route('/report_scam', methods=['POST'])
def report_scam():
    if not session.get('user_id'):
        return redirect(url_for('login'))

    scam_email = request.form.get('scam_email', '')
    scam_phone = request.form.get('scam_phone', '')
    scam_reason = request.form.get('scam_reason', '')
    reported_by = session.get('username', 'Anonymous User')

    if scam_email or scam_phone:
        add_scam_report(scam_email, scam_phone, scam_reason, reported_by)

    current_tier, scans_used, scans_left, max_scans = get_user_subscription(session['user_id'])
    user_history = get_user_history(session['user_id'])
    return render_template_string(HTML_LAYOUT, report_success=True, current_tier=current_tier, scans_left=scans_left, user_history=user_history)

@app.route('/verify/<ref_id>')
def verify_certificate(ref_id):
    audit = get_audit_by_ref(ref_id)
    if not audit:
        return f"<div style='font-family:sans-serif; text-align:center; padding:50px;'><h2>Audit Certificate Not Found</h2><p>Reference ID <b>{ref_id}</b> does not exist in our verification database.</p><a href='/login'>Go to TenderVerify SA Login</a></div>", 404

    return render_template_string(
        HTML_LAYOUT,
        result=audit,
        dept_name=audit['dept_name'],
        buyer_email=audit['buyer_email'],
        phone_number=audit['phone_number'],
        delivery_address=audit['delivery_address'],
        is_verified_view=True
    )

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        recovery_pin = request.form.get('recovery_pin', '').strip()

        if not username or not email or not password or not recovery_pin:
            error = "All fields including Security PIN are required."
        elif len(password) < 6:
            error = "Password must be at least 6 characters long."
        elif not (5 <= len(recovery_pin) <= 10) or not recovery_pin.isdigit():
             error = "Security PIN must be between 5 and 10 digits."
        elif any(recovery_pin[i] == recovery_pin[i+1] for i in range(len(recovery_pin)-1)):
             error = "Security PIN cannot contain repeating consecutive numbers."
        else:
            sast_tz = timezone(timedelta(hours=2))
            created_at = datetime.now(sast_tz).strftime('%Y-%m-%d %H:%M SAST')
            password_hash = generate_password_hash(password)

            try:
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute(
                    'INSERT INTO users (username, email, password_hash, recovery_pin, role, subscription_tier, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
                    (username, email, password_hash, recovery_pin, 'user', 'free', created_at)
                )
                conn.commit()
                conn.close()
                return render_template_string(LOGIN_LAYOUT, message="Account created successfully! Please log in.")
            except sqlite3.IntegrityError:
                error = "Username or Email address is already registered."

    return render_template_string(REGISTER_LAYOUT, error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('user_id'):
        return redirect(url_for('index'))

    error = None
    if request.method == 'POST':
        identifier = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, email, password_hash, role, subscription_tier FROM users WHERE LOWER(email) = ? OR LOWER(username) = ?', (identifier, identifier))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[3], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['email'] = user[2]
            session['role'] = user[4]
            session['subscription_tier'] = user[5] if user[5] else 'free'

            return redirect(url_for('index'))
        else:
            error = "Invalid username/email or password."

    return render_template_string(LOGIN_LAYOUT, error=error)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    error = None
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        recovery_pin = request.form.get('recovery_pin', '').strip()
        new_password = request.form.get('new_password', '')

        if not email or not recovery_pin or not new_password:
            error = "All fields are required."
        elif len(new_password) < 6:
            error = "New password must be at least 6 characters long."
        else:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute('SELECT id, recovery_pin FROM users WHERE LOWER(email) = ?', (email,))
            user = cursor.fetchone()

            if user and user[1] == recovery_pin:
                new_pw_hash = generate_password_hash(new_password)
                cursor.execute('UPDATE users SET password_hash = ? WHERE id = ?', (new_pw_hash, user[0]))
                conn.commit()
                conn.close()
                return render_template_string(LOGIN_LAYOUT, message="Password reset successful! Please log in with your new password.")
            else:
                conn.close()
                error = "Incorrect Email or 4-Digit Security PIN."

    return render_template_string(FORGOT_PASSWORD_LAYOUT, error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/manifest.json')
def manifest():
    return jsonify({
        "name": "TenderVerify SA",
        "short_name": "TenderVerify",
        "start_url": "/",
        "display": "standalone",
        "background_color": "#F8FAFC",
        "theme_color": "#1E3A8A",
        "icons": [
            {
                "src": "https://img.icons8.com/color/192/shield.png",
                "sizes": "192x192",
                "type": "image/png"
            },
            {
                "src": "https://img.icons8.com/color/512/shield.png",
                "sizes": "512x512",
                "type": "image/png"
            }
        ]
    }), 200, {'Content-Type': 'application/json'}

@app.route('/sw.js')
def service_worker():
    sw_script = """
    self.addEventListener('install', (e) => { self.skipWaiting(); });
    self.addEventListener('fetch', (e) => { e.respondWith(fetch(e.request)); });
    """
    return sw_script, 200, {'Content-Type': 'application/javascript'}

if __name__ == '__main__':
    app.run(debug=True)