from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd
import tldextract
import re
from urllib.parse import urlparse
import requests
from datetime import datetime
import socket
import ssl

app = Flask(__name__)
CORS(app)  # Enable CORS for cross-origin requests

# Load the trained phishing detection model
model = joblib.load("phishing_model.pkl")

# Get the expected feature names from the model
expected_features = model.feature_names_in_

# Whitelisted domains that should never be classified as phishing
WHITELIST = [
    "google.com", "youtube.com", "facebook.com", "wikipedia.org", "twitter.com", 
    "linkedin.com", "amazon.com", "github.com", "microsoft.com", "apple.com",
    "cnn.com", "nytimes.com", "bbc.com", "reddit.com", "instagram.com"
]

def is_domain_in_whitelist(domain, subdomain, suffix):
    """Check if the domain is in the whitelist."""
    full_domain = f"{domain}.{suffix}"
    return any(d == full_domain or full_domain.endswith(f".{d}") for d in WHITELIST)

def check_ssl_cert(url):
    """Check if the domain has a valid SSL certificate."""
    try:
        if not url.startswith('http'):
            url = f"https://{url}"
        
        hostname = urlparse(url).netloc
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                # Check if certificate is valid
                if cert and 'notAfter' in cert:
                    return 1
        return 0
    except:
        return 0

def extract_enhanced_features(url):
    """Extract features from the URL for phishing detection with additional security checks"""
    # Parse the URL
    parsed_url = urlparse(url)
    path = parsed_url.path
    query = parsed_url.query
    fragment = parsed_url.fragment
    
    # Extract using tldextract
    extracted = tldextract.extract(url)
    domain = extracted.domain
    suffix = extracted.suffix
    subdomain = extracted.subdomain
    
    # Initialize features dictionary with zeros for all expected features
    features = {feature: 0 for feature in expected_features}
    
    # Basic URL features
    features.update({
        "length_url": len(url),
        "qty_dot_url": url.count("."),
        "qty_hyphen_url": url.count("-"),
        "qty_underline_url": url.count("_"),
        "qty_slash_url": url.count("/"),
        "qty_questionmark_url": url.count("?"),
        "qty_equal_url": url.count("="),
        "qty_at_url": url.count("@"),
        "qty_and_url": url.count("&"),
        "qty_exclamation_url": url.count("!"),
        "qty_space_url": url.count(" "),
        "qty_tilde_url": url.count("~"),
        "qty_comma_url": url.count(","),
        "qty_plus_url": url.count("+"),
        "qty_asterisk_url": url.count("*"),
        "qty_hashtag_url": url.count("#"),
        "qty_dollar_url": url.count("$"),
        "qty_percent_url": url.count("%"),
    })
    
    # Domain features
    features.update({
        "domain_length": len(domain),
        "qty_dot_domain": domain.count("."),
        "qty_hyphen_domain": domain.count("-"),
        "qty_underline_domain": domain.count("_"),
        "qty_slash_domain": domain.count("/"),
        "qty_questionmark_domain": domain.count("?"),
        "qty_equal_domain": domain.count("="),
        "qty_at_domain": domain.count("@"),
        "qty_and_domain": domain.count("&"),
        "qty_exclamation_domain": domain.count("!"),
        "qty_space_domain": domain.count(" "),
        "qty_tilde_domain": domain.count("~"),
        "qty_comma_domain": domain.count(","),
        "qty_plus_domain": domain.count("+"),
        "qty_asterisk_domain": domain.count("*"),
        "qty_hashtag_domain": domain.count("#"),
        "qty_dollar_domain": domain.count("$"),
        "qty_percent_domain": domain.count("%"),
    })
    
    # Path/directory features
    directory = path
    features.update({
        "directory_length": len(directory),
        "qty_dot_directory": directory.count("."),
        "qty_hyphen_directory": directory.count("-"),
        "qty_underline_directory": directory.count("_"),
        "qty_slash_directory": directory.count("/"),
        "qty_questionmark_directory": directory.count("?"),
        "qty_equal_directory": directory.count("="),
        "qty_at_directory": directory.count("@"),
        "qty_and_directory": directory.count("&"),
        "qty_exclamation_directory": directory.count("!"),
        "qty_space_directory": directory.count(" "),
        "qty_tilde_directory": directory.count("~"),
        "qty_comma_directory": directory.count(","),
        "qty_plus_directory": directory.count("+"),
        "qty_asterisk_directory": directory.count("*"),
        "qty_hashtag_directory": directory.count("#"),
        "qty_dollar_directory": directory.count("$"),
        "qty_percent_directory": directory.count("%"),
    })
    
    # File features
    filename = path.split("/")[-1] if "/" in path else ""
    features.update({
        "file_length": len(filename),
        "qty_dot_file": filename.count("."),
        "qty_hyphen_file": filename.count("-"),
        "qty_underline_file": filename.count("_"),
        "qty_slash_file": filename.count("/"),
        "qty_questionmark_file": filename.count("?"),
        "qty_equal_file": filename.count("="),
        "qty_at_file": filename.count("@"),
        "qty_and_file": filename.count("&"),
        "qty_exclamation_file": filename.count("!"),
        "qty_space_file": filename.count(" "),
        "qty_tilde_file": filename.count("~"),
        "qty_comma_file": filename.count(","),
        "qty_plus_file": filename.count("+"),
        "qty_asterisk_file": filename.count("*"),
        "qty_hashtag_file": filename.count("#"),
        "qty_dollar_file": filename.count("$"),
        "qty_percent_file": filename.count("%"),
    })
    
    # Parameters features
    params = query
    features.update({
        "params_length": len(params),
        "qty_dot_params": params.count("."),
        "qty_hyphen_params": params.count("-"),
        "qty_underline_params": params.count("_"),
        "qty_slash_params": params.count("/"),
        "qty_questionmark_params": params.count("?"),
        "qty_equal_params": params.count("="),
        "qty_at_params": params.count("@"),
        "qty_and_params": params.count("&"),
        "qty_exclamation_params": params.count("!"),
        "qty_space_params": params.count(" "),
        "qty_tilde_params": params.count("~"),
        "qty_comma_params": params.count(","),
        "qty_plus_params": params.count("+"),
        "qty_asterisk_params": params.count("*"),
        "qty_hashtag_params": params.count("#"),
        "qty_dollar_params": params.count("$"),
        "qty_percent_params": params.count("%"),
    })
    
    # TLD features
    features.update({
        "qty_tld_url": 1 if suffix else 0,
    })
    
    # Email detection
    features.update({
        "email_in_url": 1 if "@" in url and "." in url.split("@")[1] else 0,
    })
    
    # IP detection
    features.update({
        "domain_in_ip": 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain) else 0,
    })
    
    # Check for SSL
    has_ssl = check_ssl_cert(url)
    
    # Set default values for features that require external checks
    features.update({
        "asn_ip": -1,
        "domain_google_index": 1 if is_domain_in_whitelist(domain, subdomain, suffix) else 0,
        "domain_spf": 0,
        "time_domain_activation": -1,
        "time_domain_expiration": -1,
        "qty_redirects": 0,
        "url_google_index": 1 if is_domain_in_whitelist(domain, subdomain, suffix) else 0,
        "domain_whois_registered": 1 if is_domain_in_whitelist(domain, subdomain, suffix) else 0,
        "domain_whois_updated": 0,
        "domain_whois_expires": 0,
        "url_shortened": 1 if len(url) < 20 else 0,
    })
    
    # Ensure all expected features are present
    for feature in expected_features:
        if feature not in features:
            features[feature] = 0
    
    return features, is_domain_in_whitelist(domain, subdomain, suffix)

@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "Phishing Detection API is running!"})

@app.route('/predict', methods=['POST'])
def predict():
    data = request.json
    url = data.get("url")

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    # Extract features from the URL
    features, is_whitelisted = extract_enhanced_features(url)

    # If the domain is in our whitelist, override the model
    if is_whitelisted:
        return jsonify({
            "url": url, 
            "prediction": "Legitimate",
            "phishing_probability": 0.0,
            "note": "This is a known legitimate website."
        })

    # Debugging: Print extracted features
    print("Extracted Features:", features)

    # Convert to DataFrame for model input
    features_df = pd.DataFrame([features])
    
    # Ensure only expected features are included and in the correct order
    features_df = features_df[expected_features]

    # Make prediction with probability
    prediction = model.predict(features_df)[0]
    
    # Get probability scores
    prob_scores = model.predict_proba(features_df)[0]
    phishing_probability = prob_scores[1] * 100  # Get probability for class 1 (phishing)
    
    # Apply heuristics to detect likely false positives
    note = None
    
    # If domain is short and has common TLD, lower confidence
    extracted = tldextract.extract(url)
    common_tlds = ['com', 'org', 'net', 'edu', 'gov']
    if len(extracted.domain) <= 5 and extracted.suffix in common_tlds:
        if phishing_probability < 70:  # Only flip the prediction if not very high confidence
            prediction = 0
            phishing_probability = 100 - phishing_probability
            note = "The short domain with common TLD suggests this may be legitimate."
    
    # Debugging: Print model output
    print("Model Prediction:", prediction)
    print("Phishing Probability:", phishing_probability)

    result = "Phishing" if prediction == 1 else "Legitimate"
    
    response_data = {
        "url": url, 
        "prediction": result,
        "phishing_probability": round(phishing_probability, 2)  # Round to 2 decimal places
    }
    
    if note:
        response_data["note"] = note
        
    return jsonify(response_data)

if __name__ == "__main__":
    app.run(debug=True)