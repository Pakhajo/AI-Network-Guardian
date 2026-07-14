"""
=========================================
AI Network Guardian
app.py
Streamlit Dashboard
=========================================
"""

import streamlit as st
import pandas as pd
import sqlite3

from database import create_database


# =========================================
# Database Configuration
# =========================================

DATABASE = "network_guardian.db"


def connect_database():
    """Connect to SQLite database."""
    return sqlite3.connect(DATABASE)


# =========================================
# Load Packet Data
# =========================================

def load_packets():

    conn = connect_database()

    try:
        df = pd.read_sql_query(
            "SELECT * FROM packets ORDER BY id DESC",
            conn
        )

    except Exception:
        df = pd.DataFrame()

    conn.close()

    return df


# =========================================
# Dashboard Statistics
# =========================================

def total_packets():

    conn = connect_database()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM packets")

    total = cursor.fetchone()[0]

    conn.close()

    return total


def threat_packets():

    conn = connect_database()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT COUNT(*) FROM packets WHERE prediction='Threat'"
    )

    total = cursor.fetchone()[0]

    conn.close()

    return total


def normal_packets():

    conn = connect_database()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT COUNT(*) FROM packets WHERE prediction='Normal'"
    )

    total = cursor.fetchone()[0]

    conn.close()

    return total


# =========================================
# Clear Database
# =========================================

def clear_database():

    conn = connect_database()

    cursor = conn.cursor()

    cursor.execute("DELETE FROM packets")

    conn.commit()

    conn.close()


# =========================================
# Main Dashboard
# =========================================

def main():

    create_database()

    st.set_page_config(
        page_title="AI Network Guardian",
        page_icon="🛡",
        layout="wide"
    )

    st.title("🛡 AI Network Guardian")

    st.markdown(
        "### Real-Time Network Intrusion Detection Dashboard"
    )

    st.divider()

    # -------------------------------------
    # Metrics
    # -------------------------------------

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric(
            "📦 Total Packets",
            total_packets()
        )

    with col2:
        st.metric(
            "🟢 Normal Packets",
            normal_packets()
        )

    with col3:
        st.metric(
            "🔴 Threat Packets",
            threat_packets()
        )

    st.divider()

    # -------------------------------------
    # Packet Table
    # -------------------------------------

    st.subheader("Captured Packets")

    df = load_packets()

    if df.empty:

        st.warning("No packets found in database.")

    else:

        st.dataframe(
            df,
            use_container_width=True,
            height=350
        )

    st.divider()

    # -------------------------------------
    # Charts
    # -------------------------------------

    if not df.empty:

        col1, col2 = st.columns(2)

        with col1:

            st.subheader("Protocol Distribution")

            protocol = df["protocol"].value_counts()

            st.bar_chart(protocol)

        with col2:

            st.subheader("Prediction Distribution")

            prediction = df["prediction"].value_counts()

            st.bar_chart(prediction)

    st.divider()

    # -------------------------------------
    # Buttons
    # -------------------------------------

    col1, col2 = st.columns(2)

    with col1:

        if st.button("🔄 Refresh Dashboard"):
            st.rerun()

    with col2:

        if st.button("🗑 Clear Database"):

            clear_database()

            st.success("Database Cleared Successfully")

            st.rerun()

    st.divider()

    st.caption(
        "AI Network Guardian | Final Year Project | Streamlit Dashboard"
    )


# =========================================
# Run Application
# =========================================

if __name__ == "__main__":
    main()