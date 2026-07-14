import sqlite3

conn = sqlite3.connect("network_guardian.db")
cursor = conn.cursor()

cursor.execute("PRAGMA table_info(packets)")

for row in cursor.fetchall():
    print(row)

conn.close()