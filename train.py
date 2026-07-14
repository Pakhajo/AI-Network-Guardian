"""
=========================================
AI Network Guardian
train.py
Machine Learning Model Training
=========================================
"""

import os
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score


# -----------------------------------------
# Load Dataset
# -----------------------------------------
def load_data():

    file_path = "dataset/network_dataset.csv"

    if not os.path.exists(file_path):
        print(f"\nError: Dataset not found!\nExpected location: {file_path}")
        return None

    print("Loading Dataset...")

    return pd.read_csv(file_path)


# -----------------------------------------
# Prepare Dataset
# -----------------------------------------
def prepare_data(data):

    protocol_map = {
        "TCP": 0,
        "UDP": 1,
        "ICMP": 2
    }

    label_map = {
        "Normal": 0,
        "Threat": 1
    }

    data["protocol"] = data["protocol"].map(protocol_map)
    data["label"] = data["label"].map(label_map)

    X = data[
        [
            "protocol",
            "packet_length",
            "ttl",
            "source_port",
            "destination_port"
        ]
    ]

    y = data["label"]

    return X, y


# -----------------------------------------
# Train Model
# -----------------------------------------
def train_model(X, y):

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42
    )

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42
    )

    print("\nTraining Model...")

    model.fit(X_train, y_train)

    prediction = model.predict(X_test)

    accuracy = accuracy_score(y_test, prediction)

    print(f"Model Accuracy : {accuracy * 100:.2f}%")

    return model


# -----------------------------------------
# Save Model
# -----------------------------------------
def save_model(model):

    os.makedirs("models", exist_ok=True)

    model_path = "models/random_forest.pkl"

    joblib.dump(model, model_path)

    print(f"Model Saved Successfully: {model_path}")


# -----------------------------------------
# Main Function
# -----------------------------------------
def main():

    print("=" * 50)
    print("AI NETWORK GUARDIAN")
    print("Machine Learning Training")
    print("=" * 50)

    data = load_data()

    if data is None:
        return

    X, y = prepare_data(data)

    model = train_model(X, y)

    save_model(model)

    print("\nTraining Completed Successfully!")


# -----------------------------------------
# Run Program
# -----------------------------------------
if __name__ == "__main__":
    main()