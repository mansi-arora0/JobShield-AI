# JobShield AI  
**AI-Powered Fake Job Detection & Women Safety Support System**

JobShield AI is an intelligence-driven platform designed to detect fraudulent job offers and prevent human trafficking at the recruitment stage. It combines Machine Learning, rule-based threat scoring, and a real-time monitoring dashboard to provide explainable risk insights and connect users with verified safety resources.

---

## Key Features

### AI Job Analysis
- ML-based fake vs real job classification  
- Explainable risk indicators  
- Confidence scoring  
- Suspicious keyword highlighting  

### Threat Intelligence Engine
- Rule-based trafficking signal detection  
- Combined threat score (ML + heuristics)  
- Contact and location extraction  
- Automatic high-risk alert generation  

### Guardian Connect (Women Safety Network)
- Women helpline integration (1091 / 181)  
- Cybercrime support (1930)  
- Emergency support (112)  
- City-based women-focused NGO lookup  
- Safety checklist for job seekers  

### Monitoring & Operations
- Live monitoring simulation  
- Persistent alerts management  
- NGO reporting workflow  
- Scan history tracking  
- Admin analytics dashboard  

### Evidence & Forensics
- TXT evidence report generation  
- PDF report export (optional)  
- PDF job ad scanning  
- Batch CSV processing  

---

## Tech Stack

- **Language:** Python 3.10+  
- **Framework:** Streamlit  
- **ML Model:** TF-IDF + Logistic Regression  
- **Database:** SQLite  
- **Visualization:** Streamlit native charts  
- **PDF Processing:** pdfplumber, reportlab  

---

## Project Structure
JobShield-AI/
│
├── app.py                 # Main Streamlit application
├── model_utils.py         # ML training and NLP utilities
├── fake_job_postings.csv  # Training dataset
├── jobshield.db           # SQLite database (auto-created)
├── requirements.txt       # Python dependencies
└── README.md              # Project documentation

---

## Installation & Setup

### 1. Clone the repository

```bash
git clone https://github.com/your-username/jobshield-ai.git
cd jobshield-ai

2. Create virtual environment (recommended)
python -m venv env
source env/bin/activate      # Mac/Linux
env\Scripts\activate         # Windows

3. Install dependencies
 pip install -r requirements.txt

4. Run the application
 streamlit run app.py

---

How It Works
User pastes job text or uploads a PDF

Text is preprocessed and vectorized

ML model predicts fraud probability

Rule engine computes trafficking signals

Combined threat score is generated

High-risk cases trigger alerts

Users are guided to helplines and NGOs

---

Use Cases
Job seekers verifying suspicious offers

Women safety and anti-trafficking initiatives

Cybercrime awareness platforms

NGO support systems

Academic research on recruitment fraud

---
⚠️ Disclaimer
JobShield AI is a decision-support tool intended for educational and research purposes. It should not be used as the sole basis for legal or employment decisions.

Future Enhancements

Real WhatsApp/Telegram ingestion

Multilingual job analysis

Advanced deep learning models

Geo-intelligence risk mapping

API deployment




