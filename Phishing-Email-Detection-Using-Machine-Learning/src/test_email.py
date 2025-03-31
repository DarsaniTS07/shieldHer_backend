import joblib

# Load saved model and vectorizer
model = joblib.load("phishing_model.pkl")
vectorizer = joblib.load("tfidf_vectorizer.pkl")

def predict_email(text):
    text_tfidf = vectorizer.transform([text])  # Convert text to TF-IDF
    prediction = model.predict(text_tfidf)[0]  # Predict (0 = Not Phishing, 1 = Phishing)
    return "🚨 Phishing Email Detected!" if prediction == 1 else "✅ Safe Email"

# Example: Change this text to test different emails
email_text = "Your PayPal account has been compromised. Click here to secure it."
print(predict_email(email_text))
