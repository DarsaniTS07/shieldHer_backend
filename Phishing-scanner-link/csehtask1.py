import streamlit as st
import google.generativeai as genai
import os
import cred as key

PAGE_TITLE = "Gemini-Powered Phishing Link Scanner"
PAGE_ICON = "🔒"
LAYOUT = "centered"
MODEL_NAME = "gemini-2.0-flash"

#API_KEY_ENV_VAR = "GOOGLE_API_KEY"
#API_KEY = os.getenv(API_KEY_ENV_VAR)

API_KEY=key.API_KEY

st.set_page_config(page_title=PAGE_TITLE, page_icon=PAGE_ICON, layout=LAYOUT)

if not API_KEY:
    st.error(f"API Key not found. Set {API_KEY} as an environment variable.")
    st.stop()

genai.configure(api_key=API_KEY)

PROMPT_TEMPLATE = """
You are an expert cybersecurity analyst specializing in phishing link detection.
Your task is to analyze the following URL and identify potential phishing indicators.
The goal is to provide a clear and concise report of your findings, mimicking the analysis of a seasoned cybersecurity professional.
and make sure report looks beautiful.

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
- Maintains a professional and technical tone.
- Focuses on identifying and explaining potential phishing indicators.
- If needed, improve the analysis, and remove any unneeded or redundant information.

Generate final phishing site or not with emoji's as required.
"""

def generate_report(url):
    prompt = PROMPT_TEMPLATE.format(url=url)
    try:
        model = genai.GenerativeModel(MODEL_NAME)
        response = model.generate_content(prompt)
        report = response.text
        return report
    except Exception as e:
        st.error(f"An error occurred: {e}")
        return None

st.title(PAGE_TITLE)
st.markdown("This tool uses LLMs Google's Genai via Googles generative Model to analyze URLs for potential phishing risks.")
st.markdown("---")

st.markdown("### Enter the URL to check:")
url = st.text_input("URL:")

if st.button("Analyze URL"):
    if url:
        with st.spinner("Analyzing... Please wait."):
            report = generate_report(url)
            if report:
                st.markdown("### Detailed Analysis Report:")
                st.markdown(report)
    else:
        st.warning("Please enter a URL.")

st.markdown("---")
st.markdown("<h3 style='text-align: center; color: orange;'>Developed by Vijay Vadapalli 🤠</h3>",unsafe_allow_html=True)
st.markdown("<h2 style='text-align: center;'>Developed with Streamlit | Gemini-Powered Phishing Detection</h2>",unsafe_allow_html=True)