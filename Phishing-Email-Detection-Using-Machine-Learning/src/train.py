import pickle
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from imblearn.over_sampling import RandomOverSampler

def train_model(data_file, vectorizer_file, model_file):
    # Load preprocessed data
    with open(data_file, "rb") as f:
        X, y = pickle.load(f)

    # Load the vectorizer
    with open(vectorizer_file, "rb") as f:
        vectorizer = pickle.load(f)

    # Balance dataset using oversampling
    ros = RandomOverSampler(random_state=42)
    X, y = ros.fit_resample(X, y)

    # Split data into training/testing sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Train Random Forest model
    model = RandomForestClassifier(n_estimators=200, max_depth=15, random_state=42)
    model.fit(X_train, y_train)

    # Evaluate the model
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"✅ Model Accuracy: {accuracy:.2f}")

    # Save the trained model
    with open(model_file, "wb") as f:
        pickle.dump(model, f)

    print(f"✅ Model saved to {model_file}")

if __name__ == "__main__":
    train_model("../data/preprocessed_data.pkl", "../data/vectorizer.pkl", "../models/phishing_detector.pkl")
