import streamlit as st
import numpy as np
import re
import sqlite3
import pandas as pd
import time
import os
from datetime import datetime

# PDF extraction
try:
    import pdfplumber
    PDF_SUPPORT = True
except:
    PDF_SUPPORT = False

# PDF report generation
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    PDF_REPORT = True
except:
    PDF_REPORT = False

from model_utils import (
    train_model,
    preprocess_text,
    risk_level_from_confidence,
    explain_prediction,
    trafficking_signals
)

# ============================================================
# PAGE SETUP
# ============================================================
st.set_page_config(
    page_title="JobShield AI",
    page_icon="🛡️",
    layout="wide"
)

# ============================================================
# BEST-IN-CLASS UI INJECTION (DARK/LIGHT MODE)
# ============================================================
if 'theme' not in st.session_state:
    st.session_state.theme = 'Dark'

def toggle_theme():
    st.session_state.theme = 'Light' if st.session_state.theme == 'Dark' else 'Dark'

is_dark = st.session_state.theme == 'Dark'
primary_color = "#64ffda" if is_dark else "#007bff"
bg_gradient = "radial-gradient(circle at top right, #0a192f, #020c1b)" if is_dark else "linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%)"
text_color = "#e6f1ff" if is_dark else "#2d3436"
card_bg = "rgba(17, 34, 64, 0.7)" if is_dark else "#ffffff"

st.markdown(f"""
    <style>
    .stApp {{ background: {bg_gradient}; color: {text_color}; }}
    [data-testid="stSidebar"] {{ 
        background-color: {"rgba(10, 25, 47, 0.95)" if is_dark else "#ffffff"} !important;
        border-right: 1px solid {primary_color};
    }}
    div[data-testid="stMetric"] {{
        background: {card_bg};
        border: 1px solid {primary_color}44;
        padding: 20px;
        border-radius: 15px;
        box-shadow: 0 4px 15px rgba(0,0,0,{"0.3" if is_dark else "0.1"});
    }}
    .stButton>button {{
        background-color: transparent;
        color: {primary_color};
        border: 2px solid {primary_color};
        border-radius: 8px;
        font-weight: bold;
        transition: 0.3s all ease;
    }}
    .stButton>button:hover {{
        background-color: {primary_color};
        color: {"#0a192f" if is_dark else "#ffffff"};
        box-shadow: 0 0 20px {primary_color};
    }}
    h1, h2, h3 {{ color: {primary_color} !important; font-family: 'Inter', sans-serif; }}
    </style>
""", unsafe_allow_html=True)

st.sidebar.button(f"🌓 Switch to { 'Light' if is_dark else 'Dark'} Mode", on_click=toggle_theme)

# ============================================================
# LOAD MODEL
# ============================================================
@st.cache_resource
def load_model():
    model, vectorizer, top_risk_words = train_model()
    return model, vectorizer, top_risk_words

with st.spinner("Initializing AI Guardians..."):
    model, vectorizer, top_risk_words = load_model()

# ============================================================
# DATABASE (SQLite)
# ============================================================
DB_PATH = "jobshield.db"
def get_conn(): return sqlite3.connect(DB_PATH, check_same_thread=False)

def init_db():
    conn = get_conn(); cur = conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, source TEXT, job_text TEXT, prediction INTEGER, confidence REAL, risk_level TEXT, threat_score INTEGER, ml_reasons TEXT, signals TEXT, contacts TEXT, locations TEXT)""")
    cur.execute("""CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, source TEXT, job_text TEXT, risk_level TEXT, confidence REAL, threat_score INTEGER, status TEXT DEFAULT 'OPEN')""")
    cur.execute("""CREATE TABLE IF NOT EXISTS reports (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, reporter_name TEXT, reporter_contact TEXT, job_text TEXT, risk_level TEXT, threat_score INTEGER, status TEXT DEFAULT 'SUBMITTED')""")
    # New table for NGO Registry
    cur.execute("""CREATE TABLE IF NOT EXISTS ngo_registry (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, specialty TEXT, contact TEXT, location TEXT)""")
    conn.commit()
    for tbl in ["scans", "alerts", "reports"]:
        cur.execute(f"PRAGMA table_info({tbl})")
        cols = [r[1] for r in cur.fetchall()]
        if "threat_score" not in cols:
            cur.execute(f"ALTER TABLE {tbl} ADD COLUMN threat_score INTEGER DEFAULT 0")
            conn.commit()
    conn.close()

init_db()

# DB Helpers (Unchanged)
def db_insert_scan(timestamp, source, job_text, prediction, confidence, risk_level, threat_score, ml_reasons, signals, contacts, locations):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("INSERT INTO scans (timestamp, source, job_text, prediction, confidence, risk_level, threat_score, ml_reasons, signals, contacts, locations) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", 
    (timestamp, source, job_text, int(prediction), float(confidence), risk_level, int(threat_score), ", ".join(ml_reasons) if ml_reasons else "", " || ".join(signals) if signals else "", " || ".join(contacts) if contacts else "", " || ".join(locations) if locations else ""))
    conn.commit(); conn.close()

def db_insert_alert(timestamp, source, job_text, risk_level, confidence, threat_score):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("INSERT INTO alerts (timestamp, source, job_text, risk_level, confidence, threat_score, status) VALUES (?, ?, ?, ?, ?, ?, 'OPEN')", (timestamp, source, job_text, risk_level, float(confidence), int(threat_score)))
    conn.commit(); conn.close()

def db_fetch_scans(limit=1000):
    conn = get_conn(); df = pd.read_sql_query(f"SELECT * FROM scans ORDER BY id DESC LIMIT {limit}", conn); conn.close(); return df

def db_fetch_alerts():
    conn = get_conn(); df = pd.read_sql_query("SELECT * FROM alerts ORDER BY id DESC", conn); conn.close(); return df

def db_update_alert_status(alert_id, new_status):
    conn = get_conn(); cur = conn.cursor(); cur.execute("UPDATE alerts SET status=? WHERE id=?", (new_status, alert_id)); conn.commit(); conn.close()

def db_insert_report(timestamp, name, contact, job_text, risk_level, threat_score):
    conn = get_conn(); cur = conn.cursor(); cur.execute("INSERT INTO reports (timestamp, reporter_name, reporter_contact, job_text, risk_level, threat_score, status) VALUES (?, ?, ?, ?, ?, ?, 'SUBMITTED')", (timestamp, name, contact, job_text, risk_level, int(threat_score))); conn.commit(); conn.close()

# ============================================================
# HELPERS
# ============================================================
def risk_color(level):
    level = (level or "").lower()
    if "low" in level: return "🟢"
    elif "medium" in level: return "🟡"
    elif "high" in level: return "🟠"
    else: return "🔴"

def highlight_keywords(text, keywords):
    if not keywords: return text
    highlighted = text
    for kw in keywords:
        if kw.strip():
            pattern = r"\b(" + re.escape(kw) + r")\b"
            highlighted = re.sub(pattern, r"**🟥\1**", highlighted, flags=re.IGNORECASE)
    return highlighted

def extract_contacts(text):
    emails = re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text)
    urls = re.findall(r"(https?://[^\s]+)", text)
    phones = re.findall(r"(\+?\d[\d\s-]{8,}\d)", text)
    return list(set(emails + urls + [p.strip() for p in phones if len(p.strip()) >= 10]))

def extract_locations(text):
    locs = []
    places = ["dubai", "uae", "qatar", "saudi", "singapore", "thailand", "malaysia", "delhi", "mumbai", "chandigarh", "mohali", "punjab", "bangalore", "hyderabad", "kolkata", "chennai"]
    t = text.lower()
    for p in places:
        if p in t: locs.append(p.title())
    return list(set(locs))

def rule_based_threat_score(text):
    t = text.lower(); score = 0
    rules = [("no interview", 15), ("urgent hiring", 10), ("limited seats", 8), ("passport", 15), ("visa", 10), ("ticket", 8), ("free visa", 15), ("registration fee", 18), ("pay", 10), ("training fee", 15), ("whatsapp", 10), ("telegram", 10), ("work from home", 5), ("no documents", 15), ("dubai", 10), ("qatar", 10), ("thailand", 10), ("agent", 8)]
    for key, w in rules:
        if key in t: score += w
    if len(extract_contacts(text)) > 0: score += 10
    return int(min(score, 100))

def combined_threat_score(pred, confidence, rule_score):
    ml_score = int(confidence * 100)
    final = int(0.65 * ml_score + 0.35 * rule_score) if pred == 1 else int(0.45 * ml_score + 0.55 * rule_score)
    return min(max(final, 0), 100)

def analyze_text(job_text):
    clean_text = preprocess_text(job_text)
    vec = vectorizer.transform([clean_text])
    prob = model.predict_proba(vec)[0]
    pred = model.predict(vec)[0]
    confidence = float(np.max(prob))
    risk_level = risk_level_from_confidence(pred, confidence)
    ml_reasons = explain_prediction(job_text, top_risk_words)
    signals = trafficking_signals(job_text)
    contacts = extract_contacts(job_text)
    locations = extract_locations(job_text)
    rule_score = rule_based_threat_score(job_text)
    threat_score = combined_threat_score(pred, confidence, rule_score)
    return pred, confidence, risk_level, threat_score, ml_reasons, signals, contacts, locations

def extract_text_from_pdf(file):
    if not PDF_SUPPORT: return ""
    text = ""
    with pdfplumber.open(file) as pdf:
        for page in pdf.pages:
            t = page.extract_text()
            if t: text += t + "\n"
    return text.strip()

def is_high_risk(risk_level):
    """Checks if the risk level is high or critical."""
    rl = (risk_level or "").lower()
    return ("high" in rl) or ("critical" in rl)

def generate_pdf_report(report_text):
    """Generates a simple PDF evidence report."""
    from io import BytesIO
    pdf_buffer = BytesIO()
    c = canvas.Canvas(pdf_buffer, pagesize=letter)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(100, 750, "JobShield AI - Evidence Report")
    c.setFont("Helvetica", 10)
    
    y = 720
    for line in report_text.split('\n'):
        if y < 50: # Simple page break logic
            c.showPage()
            y = 750
        c.drawString(70, y, line)
        y -= 15
        
    c.save()
    return pdf_buffer.getvalue()

def generate_report_text(job_text, pred, risk_level, confidence, threat_score, ml_reasons, signals, contacts, locations, source="Manual"):
    """Generates a structured text report for evidence downloading."""
    report = [
        "JobShield AI - Evidence Report",
        "=" * 65,
        f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Source: {source}",
        "",
        "JOB TEXT:",
        job_text,
        "",
        "RESULT:",
        f"Prediction: {'Fake Job' if pred == 1 else 'Real Job'}",
        f"Risk Level: {risk_level}",
        f"Confidence: {round(confidence, 2)}",
        f"Threat Score: {threat_score}/100",
        "",
        "CONTACTS DETECTED:",
        ", ".join(contacts) if contacts else "None",
        "",
        "LOCATIONS DETECTED:",
        ", ".join(locations) if locations else "None",
        "",
        "ML RISK INDICATORS:",
        ", ".join(ml_reasons) if ml_reasons else "Pattern-based detection",
        "",
        "TRAFFICKING SIGNALS:"
    ]
    if signals:
        for s in signals: report.append(f"- {s}")
    else:
        report.append("None detected")
    
    report.extend([
        "",
        "SAFETY GUIDANCE:",
        "- Do NOT share Aadhaar/Passport/Bank OTP",
        "- Do NOT pay registration/visa/training fees",
        "- Verify company on LinkedIn + official website",
        "- Report suspicious job to cybercrime portal"
    ])
    return "\n".join(report)

def generate_pdf_report(report_text):
    """Generates a simple PDF evidence report using ReportLab."""
    from io import BytesIO
    pdf_buffer = BytesIO()
    c = canvas.Canvas(pdf_buffer, pagesize=letter)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(100, 750, "JobShield AI - Evidence Report")
    c.setFont("Helvetica", 10)
    
    y = 720
    for line in report_text.split('\n'):
        if y < 50:
            c.showPage()
            y = 750
        c.drawString(70, y, line)
        y -= 15
        
    c.save()
    return pdf_buffer.getvalue()

# ============================================================
# SIDEBAR NAVIGATION
# ============================================================
st.sidebar.markdown(f"<h1 style='text-align: center;'>🛡️ COMMAND</h1>", unsafe_allow_html=True)
page = st.sidebar.radio("Navigation", ["🏠 Home", "🔍 Analyze Job Offer", "📄 Scan PDF Job Ad", "🔴 Live Monitoring", "🚨 Alerts", "🛡️ Guardian Connect", "📥 Batch Scan (CSV)", "📊 Admin Dashboard", "📢 Report to NGO", "📜 History", "ℹ️ About"])

# ============================================================
# FEATURES
# ============================================================
if page == "🏠 Home":
    # Hero Section with Title and Image
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("<h1 style='text-align: left; font-size: 3.5rem; margin-bottom: 0;'>🛡️ JobShield AI</h1>", unsafe_allow_html=True)
        st.markdown("<h3 style='color: #64ffda !important;'>Guardian of Professional Recruitment</h3>", unsafe_allow_html=True)
        st.write("""
            **JobShield AI** is an advanced, intelligence-driven monitoring system designed to protect job seekers 
            from fraudulent offers and human trafficking traps. By combining Machine Learning with a real-time 
            threat engine, we identify recruitment red flags before they lead to exploitation.
        """)
        
        # Action Buttons/Quick Stats
        st.markdown("---")
        st.markdown("#### 🛡️ Core Defense Layers")
        c1, c2, c3 = st.columns(3)
        c1.write(" **ML Analysis**\nPattern-based fraud detection.")
        c2.write(" **Threat Engine**\nReal-time risk scoring.")
        c3.write(" **Guardian Connect**\nDirect NGO support network.")

    with col2:
        # Generating a professional security themed image
        st.image("https://img.icons8.com/illustrations/official/400/security-shield.png", use_container_width=True)

    st.markdown("---")

    # Interactive Mission Section
    st.markdown("### 🚀 Our Mission")
    with st.container():
        st.markdown(f"""
        <div style="background: {card_bg}; padding: 25px; border-radius: 15px; border-left: 5px solid {primary_color};">
            <p style="font-size: 1.1rem; line-height: 1.6;">
                Most recruitment fraud platforms are reactive. <b>JobShield AI is proactive.</b> We believe that 
                prevention at the digital doorstep is the most effective way to combat human trafficking. 
                Our system doesn't just scan text; it analyzes the <i>intent</i> behind the offer.
            </p>
        </div>
        """, unsafe_allow_html=True)

    # "How It Works" Diagram Simulation
    st.markdown("### 🛠️ How It Works")
    step1, step2, step3, step4 = st.columns(4)
    
    with step1:
        st.info(" **Input**\nPaste text or upload a PDF job ad.")
    with step2:
        st.info(" **Scan**\nAI checks for trafficking signals.")
    with step3:
        st.info(" **Alert**\nHigh-risk threats are archived instantly.")
    with step4:
        st.info(" **Protect**\nConnect with NGOs for rescue/legal aid.")

    # Safety Tip of the Day
    st.sidebar.markdown("---")
    st.sidebar.subheader(" Safety Tip")
    st.sidebar.warning("Genuine companies will never ask for 'Visa Security Deposits' or 'Laptop Processing Fees' before you sign an official contract.")

elif page == "🔍 Analyze Job Offer":
    st.title("🔍 Analyze Job Offer")

    col1, col2 = st.columns([2, 1])

    with col1:
        job_text = st.text_area(
            "📄 Paste Job Description / WhatsApp / SMS / Telegram message",
            height=260,
            placeholder="Paste job description here..."
        )

    with col2:
        st.markdown("###  Options")
        show_highlight = st.checkbox("Highlight suspicious keywords", value=True)
        save_to_db = st.checkbox("Save to database", value=True)
        source = st.selectbox("Source Type", ["Manual", "WhatsApp", "SMS", "Telegram", "Email", "Social Media"])

        st.markdown("###  Tip")
        st.info("Include recruiter number, city, salary, and fees for best results.")

    if st.button(" Analyze Now", use_container_width=True):
        if job_text.strip() == "":
            st.warning("Please enter a job description.")
        else:
            # Running Analysis
            pred, confidence, risk_level, threat_score, ml_reasons, signals, contacts, locations = analyze_text(job_text)
            icon = risk_color(risk_level)

            st.markdown("---")
            st.markdown("## Final Result")
            
            # Metric Row
            a, b, c, d = st.columns(4)
            with a:
                st.metric("Prediction", "Fake Job" if pred == 1 else "Real Job")
            with b:
                st.metric("Risk Level", f"{icon} {risk_level}")
            with c:
                st.metric("Confidence", round(confidence, 2))
            with d:
                st.metric("Threat Score", f"{threat_score}/100")

            # Progress Bar
            st.progress(min(threat_score / 100, 1.0))

            # Extracted Intelligence Row
            st.markdown("##  Extracted Intelligence")
            i1, i2 = st.columns(2)
            with i1:
                st.markdown("**Contacts found:**")
                st.write(", ".join(contacts) if contacts else "None")
            with i2:
                st.markdown("**Locations found:**")
                st.write(", ".join(locations) if locations else "None")

            # Highlighted Text Section
            st.markdown("## Job Text")
            if show_highlight and ml_reasons:
                st.write(highlight_keywords(job_text, ml_reasons), unsafe_allow_html=True)
            else:
                st.write(job_text)

            # ML Indicators and Signals
            st.markdown("## ML Risk Indicators")
            st.write(", ".join(ml_reasons) if ml_reasons else "Pattern-based detection")

            st.markdown("## 🚨 Trafficking Signals")
            if signals:
                for s in signals:
                    st.error(f"- {s}")
            else:
                st.success("None detected")

            # Conditional Safety Guidance
            if is_high_risk(risk_level) or threat_score >= 70:
                st.markdown("## Safety Guidance (High Threat)")
                st.warning("""
- **Do NOT** share Aadhaar/Passport/Bank OTP  
- **Do NOT** pay registration/visa/training fees  
- **Verify** company on LinkedIn + official website  
- **Report** suspicious job to cybercrime portal  
                """)

            # Database Interaction
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if save_to_db:
                db_insert_scan(timestamp, source, job_text, pred, confidence, risk_level,
                               threat_score, ml_reasons, signals, contacts, locations)

                # Auto-generate alert for high risk
                if is_high_risk(risk_level) or threat_score >= 70:
                    db_insert_alert(timestamp, source, job_text, risk_level, confidence, threat_score)

                st.success("Saved to database (history + alerts).")

            # Report Generation
            report_text = generate_report_text(job_text, pred, risk_level, confidence, threat_score,
                                               ml_reasons, signals, contacts, locations, source=source)

            # Download Buttons
            st.markdown("### 📥 Export Evidence")
            btn_col1, btn_col2 = st.columns(2)
            
            with btn_col1:
                st.download_button(
                    label="📄 Download Report (TXT)",
                    data=report_text,
                    file_name=f"jobshield_report_{timestamp}.txt",
                    mime="text/plain",
                    use_container_width=True
                )

            with btn_col2:
                if PDF_REPORT:
                    # Logic assumes you have a generate_pdf_report(text) helper function
                    try:
                        from io import BytesIO
                        # Create a simple PDF buffer if generate_pdf_report isn't defined elsewhere
                        pdf_buffer = BytesIO()
                        c = canvas.Canvas(pdf_buffer, pagesize=letter)
                        c.drawString(100, 750, "JobShield AI Evidence Report")
                        c.drawString(100, 730, f"Date: {timestamp}")
                        c.drawString(100, 710, f"Threat Score: {threat_score}/100")
                        c.showPage()
                        c.save()
                        
                        st.download_button(
                            label="📕 Download Report (PDF)",
                            data=pdf_buffer.getvalue(),
                            file_name=f"jobshield_report_{timestamp}.pdf",
                            mime="application/pdf",
                            use_container_width=True
                        )
                    except Exception as e:
                        st.error(f"Error generating PDF: {e}")
                else:
                    st.info("Install 'reportlab' to enable PDF downloads.")

elif page == "📄 Scan PDF Job Ad":
    st.title("PDF Intelligence Scan")
    pdf = st.file_uploader("Upload Job PDF", type=["pdf"])
    if pdf:
        txt = extract_text_from_pdf(pdf)
        st.text_area("Extracted Text", txt, height=200)
        if st.button(" Analyze PDF"):
            p, conf, r, t, ml, sig, con, loc = analyze_text(txt)
            st.subheader(f"Risk: {r} | Threat: {t}/100")

elif page == "🔴 Live Monitoring":
    st.title("🔴 Live Intelligence Stream")
    col1, col2, col3 = st.columns(3)
    auto = col1.checkbox("Auto refresh", value=True)
    rate = col2.slider("Seconds", 2, 15, 5)
    gen = col3.checkbox("Generate Events", value=True)
    if "live_feed" not in st.session_state: st.session_state.live_feed = []
    
    if gen:
        samples = ["Dubai hiring. WhatsApp +971xxx. Pay fee.", "WFH Earn 5k. Join Telegram.", "Gulf Nurse. Passport needed immediately."]
        msg = np.random.choice(samples)
        p, conf, r, t, ml, sig, con, loc = analyze_text(msg)
        st.session_state.live_feed.insert(0, {"time": datetime.now().strftime("%H:%M:%S"), "text": msg, "risk": r, "threat": t})
    
    for item in st.session_state.live_feed[:10]:
        st.markdown(f"**[{item['time']}]** {risk_color(item['risk'])} Threat: {item['threat']} | {item['text']}")
        st.divider()
    if auto: time.sleep(rate); st.rerun()

elif page == "🚨 Alerts":  # Added emoji to match your sidebar
    st.title("🚨 Alerts (Persistent)")
    
    df = db_fetch_alerts()
    if df.empty:
        st.success("No alerts currently.")
    else:
        # Split alerts into Open and Closed categories
        open_df = df[df["status"] == "OPEN"]
        closed_df = df[df["status"] != "OPEN"]

        st.subheader(f"🔴 Open Alerts ({len(open_df)})")
        if open_df.empty: 
            st.info("No active open alerts.")
        else:
            for _, row in open_df.iterrows():
                # Card-style display for each alert
                st.markdown(f"### Alert #{row['id']} — {row['timestamp']}")
                st.write(f"*Source:* {row['source']} | *Risk:* {row['risk_level']} | *Threat:* {row['threat_score']}/100")
                st.write(row["job_text"])
                
                c1, c2 = st.columns(2)
                with c1:
                    if st.button(f"✅ Mark Resolved (#{row['id']})", key=f"res_{row['id']}"):
                        db_update_alert_status(row["id"], "RESOLVED")
                        st.rerun()
                with c2:
                    if st.button(f"🗑️ Mark False Positive (#{row['id']})", key=f"fp_{row['id']}"):
                        db_update_alert_status(row["id"], "FALSE_POSITIVE")
                        st.rerun()
                st.markdown("---")

        st.subheader(f"🟢 Closed Alerts ({len(closed_df)})")
        if not closed_df.empty:
            st.dataframe(closed_df[["id", "timestamp", "source", "risk_level", "threat_score", "status"]], use_container_width=True)

# ============================================================
# NEW FEATURE: GUARDIAN CONNECT (NGO LINKAGE)
# ============================================================
elif page == "🛡️ Guardian Connect":
    st.title("🛡️ Guardian Connect: Women's Safety Network")
    st.markdown("### Emergency Support & NGO Coordination")
    
    col1, col2, col3 = st.columns(3)
    with col1: st.error("📞 **Women's Helpline** \n**1091 / 181**")
    with col2: st.error("🚨 **Cyber Crime** \n**1930**")
    with col3: st.error("🆘 **Emergency** \n**112**")

    st.divider()
    t1, t2 = st.tabs(["Find NGO Support", " Safety Checklist"])
    
    with t1:
        st.subheader("Locate Women-Focused NGOs")
        search_loc = st.text_input("Enter City (e.g., Delhi, Mumbai, Punjab)")
        # Sample NGO Data
        ngos = [
        {"name": "Sakti Shalini", "city": "Delhi", "specialty": "Gender Violence & Shelter", "phone": "011-24373737"},
        {"name": "Majlis Legal Centre", "city": "Mumbai", "specialty": "Legal Aid & Rights", "phone": "022-26661254"},
        {"name": "Sayodhya", "city": "Hyderabad", "specialty": "Shelter & Rehab", "phone": "040-2700000"},
        {"name": "Vimochana", "city": "Bangalore", "specialty": "Women's Rights & Crisis", "phone": "080-25492783"},
        {"name": "Swayam", "city": "Kolkata", "specialty": "Violence Against Women", "phone": "033-24863367"},
        {"name": "PCVC (International Foundation for Crime Prevention and Victim Care)", "city": "Chennai", "specialty": "Domestic Violence Support", "phone": "044-43111143"},
        {"name": "Astitva", "city": "Pune", "specialty": "Women's Empowerment & Legal Support", "phone": "020-26120531"},
        {"name": "Sewa", "city": "Ahmedabad", "specialty": "Economic Empowerment & Support", "phone": "079-25506444"},
        {"name": "Saheli", "city": "Delhi", "specialty": "Crisis Intervention", "phone": "011-24616429"},
        {"name": "Vaanaprastha", "city": "Chandigarh", "specialty": "Women & Child Care", "phone": "0172-2741112"}
        ]
        if search_loc:
            filtered = [n for n in ngos if search_loc.lower() in n['city'].lower()]
            if filtered:
                for n in filtered:
                    with st.expander(f" {n['name']} ({n['city']})"):
                        st.write(f"**Specialty:** {n['specialty']} | **Contact:** {n['phone']}")
            else: st.warning("No specific NGO found in our database for that location.")

    with t2:
        st.info("💡 **Job Seeker Safety for Women**\n"
                "* Avoid interviews in private homes or isolated areas.\n"
                "* Share recruiter LinkedIn profiles with a trusted friend.\n"
                "* Never provide personal photos or home addresses early.\n"
                "* If a job requires 'immediate travel' without a contract, it is a RED FLAG.")

elif page == "📥 Batch Scan (CSV)":
    st.title("📥 Bulk Processing")
    up = st.file_uploader("Upload CSV", type="csv")
    if up:
        df = pd.read_csv(up)
        if "job_text" in df.columns:
            if st.button("🚀 Run Batch Scan"):
                for text in df["job_text"].fillna("").astype(str): analyze_text(text)
                st.success(f"Processed {len(df)} records.")

# elif page == "📊 Admin Dashboard":
#     st.title("📊 Admin Dashboard")
#     df = db_fetch_scans(limit=2000)

#     if df.empty:
#         st.info("No scans saved yet.")
#     else:
#         # DATA CLEANING: Ensure threat_score is numeric to prevent the TypeError
#         df["threat_score"] = pd.to_numeric(df["threat_score"], errors='coerce').fillna(0).astype(int)
#         df["prediction"] = pd.to_numeric(df["prediction"], errors='coerce').fillna(0).astype(int)

#         total = len(df)
#         fake = int((df["prediction"] == 1).sum())
#         real = total - fake

#         a, b, c, d = st.columns(4)
#         with a:
#             st.metric("Total Scans", total)
#         with b:
#             st.metric("Fake Detected", fake)
#         with c:
#             st.metric("Real Detected", real)
#         with d:
#             st.metric("Avg Threat Score", int(df["threat_score"].mean()))

#         st.subheader("📈 Risk Distribution")
#         st.bar_chart(df["risk_level"].value_counts())

#         st.subheader("🔥 Threat Score Distribution")
#         st.bar_chart(df["threat_score"].value_counts().sort_index())

#         st.subheader("🛰️ Source Distribution")
#         st.bar_chart(df["source"].value_counts())

#         st.subheader("📍 Top Scam Locations (Extracted)")
#         loc_series = df["locations"].fillna("").str.split(" \\|\\| ")
#         all_locs = []
#         for lst in loc_series:
#             for x in lst:
#                 if x.strip():
#                     all_locs.append(x.strip())
#         if all_locs:
#             loc_counts = pd.Series(all_locs).value_counts().head(15)
#             st.bar_chart(loc_counts)
#         else:
#             st.info("No locations extracted yet.")

#         st.subheader("🕒 Latest Scans")
#         st.dataframe(df[["id", "timestamp", "source", "risk_level", "threat_score", "confidence"]].head(40),
#                      use_container_width=True)

# ============================================================
# ADMIN DASHBOARD - CORRECTED LOCATION EXTRACTION
# ============================================================
elif page == "📊 Admin Dashboard":
    st.title("📊 Admin Dashboard")
    df = db_fetch_scans(limit=2000)

    if df.empty:
        st.info("No scans saved yet.")
    else:
        # DATA CLEANING: Ensure threat_score and prediction are numeric
        df["threat_score"] = pd.to_numeric(df["threat_score"], errors='coerce').fillna(0).astype(int)
        df["prediction"] = pd.to_numeric(df["prediction"], errors='coerce').fillna(0).astype(int)

        total = len(df)
        fake = int((df["prediction"] == 1).sum())
        real = total - fake

        a, b, c, d = st.columns(4)
        with a:
            st.metric("Total Scans", total)
        with b:
            st.metric("Fake Detected", fake)
        with c:
            st.metric("Real Detected", real)
        with d:
            st.metric("Avg Threat Score", int(df["threat_score"].mean()))

        st.subheader(" Risk Distribution")
        st.bar_chart(df["risk_level"].value_counts())

        st.subheader(" Threat Score Distribution")
        st.bar_chart(df["threat_score"].value_counts().sort_index())

        st.subheader(" Source Distribution")
        st.bar_chart(df["source"].value_counts())

        # --- CORRECTED LOCATION LOGIC ---
        st.subheader("📍 Top Scam Locations (Extracted)")
        
        # We use a more robust regex split to handle varied spacing around the pipes
        all_locs = []
        if "locations" in df.columns:
            # Fill NaN with empty string, then split by the separator used in your DB insert
            loc_data = df["locations"].fillna("").astype(str)
            
            for entry in loc_data:
                # Split by your custom separator ' || '
                parts = entry.split(" || ")
                for p in parts:
                    clean_p = p.strip()
                    if clean_p and clean_p.lower() != "none":
                        all_locs.append(clean_p)

        if all_locs:
            loc_counts = pd.Series(all_locs).value_counts().head(15)
            # Use bar_chart for the clean UI seen in your screenshots
            st.bar_chart(loc_counts)
        else:
            st.info("No locations extracted yet. Ensure 'Analyze Job Offer' is extracting city names like Dubai, Mumbai, etc.")

        st.subheader("🕒 Latest Scans")
        # Displaying the last 40 scans as requested
        st.dataframe(df[["id", "timestamp", "source", "risk_level", "threat_score", "confidence"]].head(40),
                     use_container_width=True)

elif page == "📢 Report to NGO":
    st.title("📢 NGO Case Submission")
    name = st.text_input("Name")
    contact = st.text_input("Contact")
    text = st.text_area("Suspicious Offer")
    if st.button("🚨 Transmit Intelligence"):
        if text:
            p, conf, r, t, ml, sig, con, loc = analyze_text(text)
            db_insert_report(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), name, contact, text, r, t)
            st.success("Report transmitted to NGO network.")

elif page == "📜 History":
    st.title("📜 Intelligence History")
    st.dataframe(db_fetch_scans(), use_container_width=True)

elif page == "ℹ️ About":
    st.title("ℹ️ System Specifications")
    
    # Hero Section with Project Identity
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown(f"""
        ### 🛡️ JobShield AI v3.5
        **Intelligence-Driven Security for the Modern Workforce**
        
        JobShield AI is a proactive defense system designed to dismantle recruitment fraud and human trafficking networks. 
        Developed as a specialized tool for **Women's Safety Guardianship**, it analyzes linguistic patterns, 
        metadata, and behavioral signals to provide a digital shield for job seekers.
        """)
        st.info("🛰️ Active Status: **Defense Layer Engaged & Monitoring**")
    
    with col2:
        # A professional security/shield illustration
        st.image("https://img.icons8.com/illustrations/official/400/security-configuration.png")

    st.markdown("---")

    # Three Pillar Strategy
    st.markdown("### 🛠️ Core Defense Architecture")
    p1, p2, p3 = st.columns(3)
    
    with p1:
        st.markdown("#### 🧠 ML Intelligence")
        st.write("Utilizes advanced pattern-based fraud detection to analyze the *intent* behind job descriptions.")
    
    with p2:
        st.markdown("#### 🔥 Threat Engine")
        st.write("A rule-based heuristic system that assigns a real-time **Threat Score** based on trafficking red flags.")
    
    with p3:
        st.markdown("#### 🚺 Guardian Connect")
        st.write("Integrated support network linking potential victims directly to verified Women-focused NGOs.")

    st.markdown("---")

    # Technical Specifications for the "Admin" Feel
    st.markdown("### ⚙️ Technical Stack")
    st.code("""
    - Language: Python 3.10+
    - Framework: Streamlit (Advanced UI Layer)
    - Database: SQLite (Persistent Intelligence Archive)
    - AI Models: Multinomial Naive Bayes / Pattern Matching
    - Forensics: PDF/TXT Evidence Generation
    """, language="markdown")

    st.markdown("---")
    st.caption(" B.Tech CSE (AI & ML) | Amity University Punjab")