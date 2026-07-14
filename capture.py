"""
=========================================
AI Network Guardian
capture.py
Integrated Packet Capture Module
=========================================
"""

from scapy.all import sniff, IP

from database import create_database, save_packet
from feature import extract_features
from predict import load_model, predict_packet


# -----------------------------------------
# Load Machine Learning Model
# -----------------------------------------
model = load_model()

if model is None:
    print("Please train the model first using train.py")
    exit()


# -----------------------------------------
# Process Packet
# -----------------------------------------
def process_packet(packet):
    """
    Capture, extract features, predict and save.
    """

    if not packet.haslayer(IP):
        return

    try:

        # Basic packet information
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        packet_length = len(packet)

        # Extract features
        features = extract_features(packet)

        protocol = features["Protocol"]
        ttl = features["TTL"]

        source_port = features["Source Port"]
        destination_port = features["Destination Port"]

        # Convert "-" into 0
        if source_port == "-":
            source_port = 0

        if destination_port == "-":
            destination_port = 0

        # Predict
        prediction = predict_packet(
            model,
            protocol,
            packet_length,
            ttl,
            source_port,
            destination_port
        )

        # Save into database
        save_packet(
            protocol,
            source_ip,
            destination_ip,
            packet_length,
            prediction
        )

        # Display
        print("=" * 60)
        print("Packet Captured")
        print("=" * 60)

        print(f"Protocol         : {protocol}")
        print(f"Source IP        : {source_ip}")
        print(f"Destination IP   : {destination_ip}")
        print(f"Packet Length    : {packet_length}")
        print(f"TTL              : {ttl}")
        print(f"Source Port      : {source_port}")
        print(f"Destination Port : {destination_port}")
        print(f"Prediction       : {prediction}")

    except Exception as error:
        print("Packet Error:", error)


# -----------------------------------------
# Start Capture
# -----------------------------------------
def start_capture(count=20):

    create_database()

    print("=" * 60)
    print("AI NETWORK GUARDIAN")
    print("=" * 60)
    print(f"Capturing {count} packets...\n")

    sniff(
        prn=process_packet,
        store=False,
        count=count
    )

    print("\nCapture Finished Successfully.")


# -----------------------------------------
# Main
# -----------------------------------------
if __name__ == "__main__":
    start_capture()