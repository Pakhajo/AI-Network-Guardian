"""
=========================================
AI Network Guardian
main.py
Main Controller
=========================================
"""

from scapy.all import sniff

from database import create_database
from capture import process_packet
from feature import extract_features, display_features


# -----------------------------------------
# Process and Display Packet
# -----------------------------------------
def handle_packet(packet):
    """
    Process each captured packet.
    """

    # Save packet to database
    process_packet(packet)

    # Extract features
    features = extract_features(packet)

    # Display features
    display_features(features)


# -----------------------------------------
# Start AI Network Guardian
# -----------------------------------------
def start_network_guardian():

    print("=" * 55)
    print("        AI NETWORK GUARDIAN")
    print("=" * 55)

    print("Creating Database...")
    create_database()

    print("Database Ready.")
    print("Capturing Network Packets...")
    print("Press Ctrl + C to Stop.\n")

    try:
        sniff(
            prn=handle_packet,
            store=False
        )

    except KeyboardInterrupt:
        print("\nPacket Capture Stopped Successfully.")

    except Exception as error:
        print("\nError:", error)


# -----------------------------------------
# Main Program
# -----------------------------------------
if __name__ == "__main__":
    start_network_guardian()