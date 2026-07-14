"""
=========================================
AI Network Guardian
feature.py
Feature Extraction Module
=========================================
"""

from scapy.all import IP, TCP, UDP, ICMP


# -----------------------------------------
# Extract Packet Features
# -----------------------------------------
def extract_features(packet):
    """
    Extract useful features from a network packet.
    Returns a dictionary containing packet details.
    """

    features = {
        "Protocol": "Unknown",
        "Source IP": "N/A",
        "Destination IP": "N/A",
        "Packet Length": len(packet),
        "TTL": 0,
        "Source Port": "-",
        "Destination Port": "-"
    }

    # Check IP Layer
    if packet.haslayer(IP):
        features["Source IP"] = packet[IP].src
        features["Destination IP"] = packet[IP].dst
        features["TTL"] = packet[IP].ttl

    # Check TCP Layer
    if packet.haslayer(TCP):
        features["Protocol"] = "TCP"
        features["Source Port"] = packet[TCP].sport
        features["Destination Port"] = packet[TCP].dport

    # Check UDP Layer
    elif packet.haslayer(UDP):
        features["Protocol"] = "UDP"
        features["Source Port"] = packet[UDP].sport
        features["Destination Port"] = packet[UDP].dport

    # Check ICMP Layer
    elif packet.haslayer(ICMP):
        features["Protocol"] = "ICMP"

    return features


# -----------------------------------------
# Display Packet Features
# -----------------------------------------
def display_features(features):
    """
    Display extracted packet features.
    """

    print("\n========== PACKET FEATURES ==========")

    for key, value in features.items():
        print(f"{key:<20}: {value}")

    print("=====================================")


# -----------------------------------------
# Test Feature Extraction
# -----------------------------------------
if __name__ == "__main__":

    from scapy.all import sniff

    print("=" * 45)
    print("AI NETWORK GUARDIAN")
    print("Waiting for a network packet...")
    print("=" * 45)

    packet = sniff(count=1, store=True)[0]

    features = extract_features(packet)

    display_features(features)

    print("\nFeature Extraction Completed Successfully!")