import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
import pickle

def preprocess_data(input_file, output_data_file, output_vectorizer_file):
    # Load the CSV file
    df = pd.read_csv(input_file)

    # Rename column if needed
    df.rename(columns={'text_combined': 'text'}, inplace=True)

    # Ensure the dataset has 'text' and 'label' columns
    if 'text' not in df.columns or 'label' not in df.columns:
        raise ValueError("Input CSV must have 'text' and 'label' columns.")

    # Vectorize the text using TF-IDF (limiting to 5000 features to avoid memory issues)
    vectorizer = TfidfVectorizer(max_features=5000)
    X = vectorizer.fit_transform(df['text']).toarray()

    # Extract labels
    y = df['label'].values

    # Save preprocessed data
    with open(output_data_file, "wb") as f:
        pickle.dump((X, y), f)

    # Save vectorizer separately
    with open(output_vectorizer_file, "wb") as f:
        pickle.dump(vectorizer, f)

    print(f"✅ Preprocessed data saved to {output_data_file}")
    print(f"✅ Vectorizer saved to {output_vectorizer_file}")

if __name__ == "__main__":
    preprocess_data("../data/archive/phishing_email.csv", "../data/preprocessed_data.pkl", "../data/vectorizer.pkl")
