import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib

# Load the SDN dataset (replace with the actual path to your dataset)
dataset_path = '/home/dhawal/Downloads/dataset_sdn.csv'  # Update this with the correct path if needed
data = pd.read_csv(dataset_path)

# Display the columns in the dataset for verification
print("Columns in dataset:", data.columns)

# Drop non-numeric and irrelevant columns, assuming 'label' is the target column
drop_cols = ['dt', 'src', 'dst', 'switch', 'Protocol']  # Drop irrelevant columns
X = data.drop(columns=drop_cols, errors='ignore')  # Features
y = data['label']  # Target labels

# Replace missing values with 0 (optional, based on the dataset)
X.fillna(0, inplace=True)

# Standardize the features (scaling to mean=0, variance=1)
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Split the data into training and testing sets (80-20 split)
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42, stratify=y
)

# Save the scaler object for future use in the model
joblib.dump(scaler, '/home/dhawal/pox/pox/customids/scaler.pkl')
print("Scaler saved successfully!")

# Train a RandomForest model (you can change this to any model you prefer)
model = RandomForestClassifier(random_state=42)
model.fit(X_train, y_train)

# Save the trained model
joblib.dump(model, '/home/dhawal/pox/pox/customids/ids_model.pkl')
print("IDS Model saved successfully!")

# You can also save the processed data if necessary for future reference:
# pd.DataFrame(X_train).to_csv('/home/dhawal/pox/pox/customids/X_train.csv', index=False)
# pd.DataFrame(X_test).to_csv('/home/dhawal/pox/pox/customids/X_test.csv', index=False)
# pd.DataFrame(y_train).to_csv('/home/dhawal/pox/pox/customids/y_train.csv', index=False)
# pd.DataFrame(y_test).to_csv('/home/dhawal/pox/pox/customids/y_test.csv', index=False)

print("Data preprocessing and model training completed successfully!")