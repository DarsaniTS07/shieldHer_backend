from flask import Flask, request, jsonify
import google.generativeai as genai
import os
import cred as key  # Ensure you have this file with API_KEY

app = Flask(__name__)

API_KEY = key.API_KEY  # Load API key

genai.configure(api_key=API_KEY)

MODEL_NAME = "gemini-2.0-flash"

PROMPT_TEMPLATE = """
You are an expert cybersecurity analyst specializing in phishing link detection.
The URL to analyze is: {url}

Perform the following checks:
- Typosquatting detection (compare the domain to a list of common, legitimate domains).
- HTTPS presence check.
- Shortened URL expansion (if applicable).
- Basic domain age check.
- IP Address Reputation check (if possible).

Generate a detailed report that:
- Clearly states the results of each check (PASS or FAIL).
- Provides a brief explanation for each result, highlighting potential risks.
- If needed, improve the analysis and remove redundant information.

Conclude with: **Phishing Site or Safe?**
"""

@app.route('/check', methods=['GET'])
def check_phishing():
    url = request.args.get('url')
    if not url:
        return jsonify({"error": "URL parameter is required"}), 400
    
    prompt = PROMPT_TEMPLATE.format(url=url)
    try:
        model = genai.GenerativeModel(MODEL_NAME)
        response = model.generate_content(prompt)
        report = response.text
        return jsonify({"report": report})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
