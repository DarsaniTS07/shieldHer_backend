import os
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score
import joblib  # For saving and loading the model

# ✅ Step 1: Load the dataset
data_path = "../data/archive/phishing_email.csv"  # Adjust if needed

# Check if file exists
if not os.path.exists(data_path):
    print(f"❌ Error: File not found at {data_path}")
    exit()

df = pd.read_csv(data_path)

# ✅ Step 2: Convert email text into numerical features using TF-IDF
vectorizer = TfidfVectorizer(stop_words="english", max_features=5000)  
X = vectorizer.fit_transform(df["text_combined"])  
y = df["label"]  # Target labels (0 = Not Phishing, 1 = Phishing)

print("\n✅ Text converted to numerical features!")
print("X shape:", X.shape)  # (num_samples, num_features)
print("y shape:", y.shape)

# ✅ Step 3: Split data for training and testing
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print("\n✅ Dataset Split:")
print("Training data shape:", X_train.shape)
print("Testing data shape:", X_test.shape)

# ✅ Step 4: Train a Logistic Regression model
model = LogisticRegression(max_iter=500)  # Increased iterations for stability
model.fit(X_train, y_train)

print("\n✅ Model Training Completed!")

# ✅ Step 5: Test the model and check accuracy
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

print(f"\n🎯 Model Accuracy: {accuracy:.2f}")

# ✅ Step 6: Save the model and vectorizer for future use
joblib.dump(model, "phishing_model.pkl")
joblib.dump(vectorizer, "tfidf_vectorizer.pkl")

print("\n💾 Model and vectorizer saved successfully!")
