"""
=========================================
AI Network Guardian
predict.py
Machine Learning Prediction Module
=========================================
"""

import os
import joblib


# -----------------------------------------
# Load Trained Model
# -----------------------------------------
MODEL_PATH = "models/random_forest.pkl"


def load_model():
    """
    Load the trained Random Forest model.
    """

    if not os.path.exists(MODEL_PATH):
        print("Error: Model file not found!")
        print("Run train.py first.")
        return None

    print("Loading Trained Model...")

    return joblib.load(MODEL_PATH)


# -----------------------------------------
# Protocol Encoding
# -----------------------------------------
def encode_protocol(protocol):

    protocol = protocol.upper()

    if protocol == "TCP":
        return 0

    elif protocol == "UDP":
        return 1

    elif protocol == "ICMP":
        return 2

    else:
        return 0


# -----------------------------------------
# Predict Packet
# -----------------------------------------
def predict_packet(model,
                   protocol,
                   packet_length,
                   ttl,
                   source_port,
                   destination_port):
    """
    Predict whether packet is Normal or Threat.
    """

    protocol = encode_protocol(protocol)

    features = [[
        protocol,
        packet_length,
        ttl,
        source_port,
        destination_port
    ]]

    prediction = model.predict(features)[0]

    if prediction == 0:
        return "Normal"
    else:
        return "Threat"


# -----------------------------------------
# Test Module
# -----------------------------------------
if __name__ == "__main__":

    model = load_model()

    if model:

        result = predict_packet(
            model=model,
            protocol="TCP",
            packet_length=150,
            ttl=64,
            source_port=443,
            destination_port=50000
        )

        print("\nPrediction :", result)