from flask import Flask, request, jsonify
import imaplib
import email
from email.header import decode_header
import pickle
import os
import re
from flask_cors import CORS  # Import CORS

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Rest of your Flask code remains the same
# Load the phishing detection model
def load_model():
    model_file = "./models/phishing_detector.pkl"
    vectorizer_file = "./data/vectorizer.pkl"
    
    # Load the trained model
    with open(model_file, "rb") as f:
        model = pickle.load(f)

    # Load the vectorizer
    with open(vectorizer_file, "rb") as f:
        vectorizer = pickle.load(f)
        
    return model, vectorizer

# Predict if an email is phishing
def predict_phishing(model, vectorizer, email_text, threshold=0.6):
    # Vectorize the input email
    email_vector = vectorizer.transform([email_text])

    # Get prediction probability
    probability = model.predict_proba(email_vector)[0][1]  # Probability of being phishing

    # Adjust threshold
    is_phishing = probability >= threshold
    
    return {
        "is_phishing": is_phishing,
        "probability": float(probability)
    }

# Clean email text for processing
def clean_email_text(email_content):
    # Convert bytes to string if needed
    if isinstance(email_content, bytes):
        email_content = email_content.decode('utf-8', errors='ignore')
    
    # Remove HTML tags
    email_content = re.sub(r'<[^>]+>', ' ', email_content)
    
    # Remove extra whitespace
    email_content = re.sub(r'\s+', ' ', email_content).strip()
    
    return email_content

@app.route('/api/authenticate-email', methods=['POST'])
def authenticate_email():
    data = request.json
    email_address = data.get('email')
    password = data.get('password')
    
    # For Gmail, you'd use:
    mail_server = "imap.gmail.com"
    
    try:
        # Connect to the mail server
        mail = imaplib.IMAP4_SSL(mail_server)
        
        try:
            mail.login(email_address, password)
        except imaplib.IMAP4.error as e:
            print(f"IMAP error: {e}")
            return jsonify({"success": False, "message": str(e)}), 401
        except Exception as e:
            print(f"Error: {e}")
            return jsonify({"success": False, "message": str(e)}), 401
        
        # Return a success token
        return jsonify({"success": True, "message": "Authentication successful"})
        
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        if 'mail' in locals():
            mail.logout()

@app.route('/api/scan-emails', methods=['POST'])
def scan_emails():
    data = request.json
    email_address = data.get('email')
    password = data.get('password')
    
    # For Gmail, you'd use:
    mail_server = "imap.gmail.com"
    
    try:
        # Load model
        model, vectorizer = load_model()
        
        # Connect to the mail server
        mail = imaplib.IMAP4_SSL(mail_server)
        mail.login(email_address, password)
        
        # Select the inbox
        mail.select("INBOX")
        
        # Search for all emails (you might want to limit this)
        status, data = mail.search(None, "ALL")
        mail_ids = data[0].split()
        
        # Get the 30 most recent emails
        recent_ids = mail_ids[-30:] if len(mail_ids) > 30 else mail_ids
        
        phishing_emails = []
        
        for email_id in recent_ids:
            status, data = mail.fetch(email_id, "(RFC822)")
            raw_email = data[0][1]
            
            # Parse the email
            msg = email.message_from_bytes(raw_email)
            
            # Get subject
            subject = decode_header(msg["Subject"])[0][0]
            if isinstance(subject, bytes):
                subject = subject.decode()
                
            # Get sender
            from_ = msg.get("From", "")
            
            # Get email body
            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    if content_type == "text/plain" or content_type == "text/html":
                        try:
                            body += part.get_payload(decode=True).decode()
                        except:
                            body += str(part.get_payload())
            else:
                body = msg.get_payload(decode=True).decode()
            
            # Clean and combine email text for prediction
            email_text = f"{subject} {from_} {body}"
            cleaned_text = clean_email_text(email_text)
            
            # Predict if phishing
            prediction = predict_phishing(model, vectorizer, cleaned_text)
            
            if prediction["is_phishing"]:
                # Get date
                date = msg.get("Date", "")
                
                phishing_emails.append({
                    "id": email_id.decode(),
                    "subject": subject,
                    "sender": from_,
                    "date": date,
                    "probability": prediction["probability"],
                    "description": f"Suspicious email from {from_}: {subject}",
                    "risk": "High" if prediction["probability"] > 0.8 else "Medium",
                    "type": "phishing"
                })
                
                # Limit to 10 phishing emails
                if len(phishing_emails) >= 10:
                    break
        
        return jsonify({
            "success": True,
            "threats": phishing_emails
        })
        
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        if 'mail' in locals():
            mail.logout()

if __name__ == '__main__':
    app.run(debug=True)