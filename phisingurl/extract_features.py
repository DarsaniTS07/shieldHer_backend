import pandas as pd

# Load the dataset
df = pd.read_csv("dataset/dataset_full.csv")

# Drop the last column (assuming it's the target)
feature_names = df.columns[:-1].tolist()

# Print feature names
print(feature_names)