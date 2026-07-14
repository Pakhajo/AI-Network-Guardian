"""
=========================================
AI Network Guardian
database.py
SQLite Database Module
=========================================
"""

import sqlite3

DB_NAME = "network_guardian.db"


# -----------------------------
# Connect to Database
# -----------------------------
def connect():
    return sqlite3.connect(DB_NAME)


# -----------------------------
# Create Table
# -----------------------------
def create_database():
    conn = connect()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            protocol TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            packet_length INTEGER,
            prediction TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()


# -----------------------------
# Insert Packet
# -----------------------------
def save_packet(protocol, source_ip, destination_ip, packet_length, prediction):
    conn = connect()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO packets
        (protocol, source_ip, destination_ip, packet_length, prediction)
        VALUES (?, ?, ?, ?, ?)
    """, (protocol, source_ip, destination_ip, packet_length, prediction))

    conn.commit()
    conn.close()


# -----------------------------
# Get All Packets
# -----------------------------
def get_packets():
    conn = connect()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM packets ORDER BY id DESC")

    data = cursor.fetchall()

    conn.close()

    return data


# -----------------------------
# Total Packets
# -----------------------------
def packet_count():
    conn = connect()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM packets")

    total = cursor.fetchone()[0]

    conn.close()

    return total


# -----------------------------
# Threat Packets
# -----------------------------
def threat_count():
    conn = connect()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM packets WHERE prediction='Threat'")

    total = cursor.fetchone()[0]

    conn.close()

    return total


# -----------------------------
# Delete All Records
# -----------------------------
def clear_database():
    conn = connect()
    cursor = conn.cursor()

    cursor.execute("DELETE FROM packets")

    conn.commit()
    conn.close()


# -----------------------------
# Main Function (Testing)
# -----------------------------
if __name__ == "__main__":

    create_database()

    save_packet(
        "TCP",
        "192.168.1.5",
        "8.8.8.8",
        120,
        "Normal"
    )

    save_packet(
        "UDP",
        "192.168.1.15",
        "1.1.1.1",
        250,
        "Threat"
    )

    print("Total Packets :", packet_count())
    print("Threat Packets:", threat_count())

    print("\nStored Packets:\n")

    for row in get_packets():
        print(row)