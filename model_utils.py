import re
import string
import pandas as pd
import numpy as np
import streamlit as st


from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split


# -------------------- TEXT PREPROCESSING --------------------
def preprocess_text(text):
    text = str(text).lower()
    text = re.sub(r'\d+', ' ', text)
    text = re.sub(r'http\S+', ' ', text)
    text = text.translate(str.maketrans('', '', string.punctuation))
    text = re.sub(r'\s+', ' ', text)
    return text.strip()


# -------------------- LOAD & TRAIN MODEL --------------------
@st.cache_resource
def train_model():
    df = pd.read_csv("fake_job_postings.csv")

    df["clean_text"] = df["description"].apply(preprocess_text)

    X = df["clean_text"]
    y = df["fraudulent"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    vectorizer = TfidfVectorizer(max_features=10000)
    X_train_vec = vectorizer.fit_transform(X_train)

    model = LogisticRegression(
        max_iter=1000,
        class_weight="balanced"
    )
    model.fit(X_train_vec, y_train)

    feature_names = vectorizer.get_feature_names_out()
    coefficients = model.coef_[0]

    top_risk_words = sorted(
        zip(feature_names, coefficients),
        key=lambda x: x[1],
        reverse=True
    )[:30]

    return model, vectorizer, top_risk_words


# -------------------- RISK LEVEL --------------------
def risk_level_from_confidence(prediction, confidence):
    if prediction == 1 and confidence >= 0.65:
        return "🟥 HIGH RISK"
    elif prediction == 1 and confidence >= 0.45:
        return "🟧 MEDIUM RISK"
    else:
        return "🟩 LOW RISK"


# -------------------- EXPLANATION --------------------
EXPLANATION_STOPWORDS = {
    "no", "from", "to", "and", "or", "for", "of", "in", "on",
    "work", "time", "information", "perform", "assistant"
}

def explain_prediction(text, top_features, top_n=5):
    text = preprocess_text(text)
    explanation = []

    for word, weight in top_features:
        if word in EXPLANATION_STOPWORDS:
            continue
        if word in text:
            explanation.append(word)
        if len(explanation) >= top_n:
            break

    return explanation


# -------------------- TRAFFICKING SIGNALS --------------------
def trafficking_signals(text):
    signals = []
    text = text.lower()

    if "girls" in text or "women" in text or "female" in text:
        signals.append("Gender-targeted recruitment")

    if "abroad" in text:
        signals.append("Overseas recruitment risk")

    if "agent" in text and "interview" not in text:
        signals.append("Agent-controlled hiring")

    return signals
