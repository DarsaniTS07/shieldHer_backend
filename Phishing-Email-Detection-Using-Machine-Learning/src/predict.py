import pickle

def predict_email(model_file, vectorizer_file, email_text, threshold=0.5):
    # Load the trained model
    with open(model_file, "rb") as f:
        model = pickle.load(f)

    # Load the vectorizer
    with open(vectorizer_file, "rb") as f:
        vectorizer = pickle.load(f)

    # Vectorize the input email
    email_vector = vectorizer.transform([email_text])

    # Get prediction probability
    probability = model.predict_proba(email_vector)[0][1]  # Probability of being phishing

    # Adjust threshold
    prediction = "Phishing" if probability >= threshold else "Not Phishing"

    print(f"🔍 Probability: {probability:.2f}")
    return prediction

if __name__ == "__main__":
    email_text = input("📧 Enter email text to check: ")
    result = predict_email("../models/phishing_detector.pkl", "../data/vectorizer.pkl", email_text, threshold=0.6)
    print(f"🔍 Prediction: {result}")
