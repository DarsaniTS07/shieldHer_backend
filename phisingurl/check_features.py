import joblib
import pandas as pd

# Load dataset
df = pd.read_csv("dataset/dataset_full.csv")

# Load trained model
model = joblib.load("phishing_model.pkl")

# Get the features the model expects
model_features = model.feature_names_in_

# Get dataset features (excluding target column)
dataset_features = df.drop(columns=["phishing"]).columns

print("Features used in model training:", model_features)
print("\nFeatures in dataset:", dataset_features)

# Check missing features
missing_features = set(model_features) - set(dataset_features)
if missing_features:
    print("\n⚠ Missing features in dataset:", missing_features)