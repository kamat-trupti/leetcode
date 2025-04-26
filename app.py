from flask import Flask, request, jsonify, render_template
import joblib
import pandas as pd
import re
import math

app = Flask(__name__)

# Load trained model
model = joblib.load("xgboost_model.pkl")

# Feature Engineering Functions
def url_length(url):
    return len(url)

def count_dots(url):
    return url.count('.')

def count_special_chars(url):
    return sum(url.count(c) for c in ['@', '-', '_', '?', '=', '&'])

def has_https(url):
    return 1 if url.startswith("https") else 0

def has_ip_address(url):
    return 1 if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', url) else 0

def calculate_entropy(url):
    prob = [float(url.count(c)) / len(url) for c in dict.fromkeys(list(url))]
    entropy = -sum([p * math.log(p, 2) for p in prob])
    return entropy

def contains_phishing_keywords(url):
    phishing_keywords = ['secure', 'account', 'login', 'update', 'verify', 'webscr']
    return sum(1 for word in phishing_keywords if word in url.lower())

# **Route to Load HTML Page**
@app.route("/")
def home():
    return render_template("index.html")  # This will load index.html from 'templates' folder

# **API Endpoint**
@app.route("/predict", methods=["POST"])
def predict():
    data = request.json
    url = data.get("url")

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    # Extract Features
    features = pd.DataFrame([{
        "url_length": url_length(url),
        "num_dots": count_dots(url),
        "num_special_chars": count_special_chars(url),
        "https_flag": has_https(url),
        "has_ip": has_ip_address(url),
        "entropy": calculate_entropy(url),
        "phishing_keywords": contains_phishing_keywords(url),
    }])

    # Predict
    prediction = model.predict(features)[0]
    result = "phishing" if prediction == 1 else "legitimate"

    return jsonify({"url": url, "prediction": result})

if __name__ == "__main__":
    app.run(debug=True)
