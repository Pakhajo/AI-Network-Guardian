"""
=========================================
AI Network Guardian
app.py
Streamlit Dashboard
Part 1
=========================================
"""

# =========================================
# Import Libraries
# =========================================

import sqlite3
import pandas as pd
import streamlit as st
import plotly.express as px

try:
    from streamlit_autorefresh import st_autorefresh # type: ignore
except Exception:
    # Fallback: define a no-op st_autorefresh if the package is not available
    def st_autorefresh(interval=0, limit=None, key=None):
        return None
import database


# =========================================
# Database Configuration
# =========================================

DATABASE = "network_guardian.db"


# =========================================
# Connect Database
# =========================================

def connect_database():
    """
    Connect to SQLite database.
    """
    return sqlite3.connect(DATABASE)


# =========================================
# Load Packet Data
# =========================================

def load_packets():
    """
    Load all packets from database.
    """

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

    cursor.execute(
        "SELECT COUNT(*) FROM packets"
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


def threat_packets():

    conn = connect_database()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT COUNT(*) FROM packets WHERE prediction='Threat'"
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

    cursor.execute(
        "DELETE FROM packets"
    )

    conn.commit()

    conn.close()


# =========================================
# Main Dashboard
# =========================================

def main():

    # Create database if needed
    database.create_database()

    # -------------------------------------
    # Streamlit Configuration
    # -------------------------------------

    st.set_page_config(
        page_title="AI Network Guardian",
        page_icon="🛡",
        layout="wide"
    )

    # Auto Refresh Every 5 Seconds
    st_autorefresh(
        interval=5000,
        key="refresh"
    )

    # -------------------------------------
    # Dashboard Title
    # -------------------------------------

    st.title("🛡 AI Network Guardian")

    st.markdown(
        "### Real-Time Network Intrusion Detection Dashboard"
    )

    st.divider()

    # -------------------------------------
    # Sidebar
    # -------------------------------------

    st.sidebar.title("🛡 AI Network Guardian")

    st.sidebar.info(
        """
### Project Information

**AI Network Guardian**

Real-Time Network Intrusion Detection System

### Technologies

- Python
- Streamlit
- SQLite
- Scapy
- Random Forest
- Plotly
"""
    )

    st.sidebar.markdown("---")

    st.sidebar.success(
        "Dashboard Auto Refresh: Every 5 Seconds"
    )

    st.sidebar.markdown("---")

    st.sidebar.write("Developed by Final Year Student")

    # =====================================
    # Continue in Part 2...
    # =====================================


# =========================================
# Run Application
# =========================================

if __name__ == "__main__":
    main()
        # =====================================
    # Dashboard Metrics
    # =====================================

    st.subheader("📊 Network Statistics")

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

    # =====================================
    # Threat Alert
    # =====================================

    if threat_packets() > 0:

        st.error("🚨 ALERT: Threat Packets Detected!")

    else:

        st.success("✅ Network Status: Safe")

    st.divider()

    # =====================================
    # Load Data
    # =====================================

    df = load_packets()

    # =====================================
    # Search and Filter
    # =====================================

    st.subheader("🔍 Search & Filter Packets")

    col1, col2 = st.columns(2)

    with col1:

        search_ip = st.text_input(
            "Search Source/Destination IP"
        )

    with col2:

        protocol_filter = st.selectbox(
            "Filter by Protocol",
            ["All", "TCP", "UDP", "ICMP"]
        )

    # Search Filter

    if not df.empty and search_ip:

        df = df[
            df["source_ip"].astype(str).str.contains(
                search_ip,
                case=False,
                na=False
            )
            |
            df["destination_ip"].astype(str).str.contains(
                search_ip,
                case=False,
                na=False
            )
        ]

    # Protocol Filter

    if not df.empty and protocol_filter != "All":

        df = df[
            df["protocol"] == protocol_filter
        ]

    st.divider()

    # =====================================
    # Packet Table
    # =====================================

    st.subheader("📋 Captured Packets")

    if df.empty:

        st.warning("No packets found in the database.")

    else:

        st.dataframe(
            df,
            use_container_width=True,
            height=400
        )

    st.divider()

    # =====================================
    # Download CSV
    # =====================================

    if not df.empty:

        csv = df.to_csv(index=False)

        st.download_button(
            label="📥 Download Packet Report",
            data=csv,
            file_name="network_packets.csv",
            mime="text/csv"
        )

    st.divider()

    # =====================================
    # Continue in Part 3...
    # =====================================
        # =====================================
    # Charts
    # =====================================

    if not df.empty:

        st.subheader("📊 Network Analytics")

        col1, col2 = st.columns(2)

        # -----------------------------
        # Protocol Pie Chart
        # -----------------------------
        with col1:

            protocol_data = (
                df["protocol"]
                .value_counts()
                .reset_index()
            )

            protocol_data.columns = [
                "Protocol",
                "Packets"
            ]

            fig1 = px.pie(
                protocol_data,
                names="Protocol",
                values="Packets",
                title="Protocol Distribution",
                hole=0.4
            )

            st.plotly_chart(
                fig1,
                use_container_width=True
            )

        # -----------------------------
        # Prediction Pie Chart
        # -----------------------------
        with col2:

            prediction_data = (
                df["prediction"]
                .value_counts()
                .reset_index()
            )

            prediction_data.columns = [
                "Prediction",
                "Count"
            ]

            fig2 = px.pie(
                prediction_data,
                names="Prediction",
                values="Count",
                title="Prediction Distribution",
                hole=0.4
            )

            st.plotly_chart(
                fig2,
                use_container_width=True
            )

    st.divider()

    # =====================================
    # Packet Traffic Line Chart
    # =====================================

    if not df.empty and "created_at" in df.columns:

        st.subheader("📈 Packet Traffic Over Time")

        df["created_at"] = pd.to_datetime(df["created_at"])

        traffic = (
            df.groupby(
                df["created_at"].dt.floor("min")
            )
            .size()
            .reset_index(name="Packets")
        )

        st.line_chart(
            traffic.set_index("created_at")
        )

    st.divider()

    # =====================================
    # Buttons
    # =====================================

    col1, col2 = st.columns(2)

    with col1:

        if st.button("🔄 Refresh Dashboard"):
            st.rerun()

    with col2:

        if st.button("🗑 Clear Database"):

            clear_database()

            st.success(
                "Database Cleared Successfully!"
            )

            st.rerun()

    st.divider()

    # =====================================
    # Footer
    # =====================================

    st.markdown("---")

    st.caption(
        "🛡 AI Network Guardian | Final Year Project"
    )

    st.caption(
        "Developed using Python • Streamlit • SQLite • Scapy • Random Forest"
    )