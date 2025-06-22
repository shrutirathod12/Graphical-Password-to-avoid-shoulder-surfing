import sqlite3
import matplotlib.pyplot as plt
import numpy as np

# Connect to SQLite database
db_path = "mydatabase11.db"  # Ensure this file is in the same folder as graphs.py
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Fetch data
cursor.execute("SELECT user_id, login_attempt, login_time, failed_attempts FROM evaluation_matrix")
data = cursor.fetchall()

# Close connection
conn.close()

# Extract data into separate lists
user_ids = [row[0] for row in data]
login_attempts = [row[1] for row in data]
login_times = [row[2] for row in data]
failed_attempts = [row[3] for row in data]

# Plot 1: Bar Chart - Login Attempts per User
plt.figure(figsize=(8, 5))
plt.bar(user_ids, login_attempts, color='blue', alpha=0.7)
plt.xlabel("User ID")
plt.ylabel("Login Attempts")
plt.title("Login Attempts per User")
plt.xticks(user_ids)
plt.grid(axis='y', linestyle='--', alpha=0.7)
plt.show()

# Plot 2: Line Graph - Login Time per User
plt.figure(figsize=(8, 5))
plt.plot(user_ids, login_times, marker='o', linestyle='-', color='red', label="Login Time")
plt.xlabel("User ID")
plt.ylabel("Login Time (seconds)")
plt.title("Login Time per User")
plt.xticks(user_ids)
plt.legend()
plt.grid(True, linestyle='--', alpha=0.7)
plt.show()

# Plot 3: Scatter Plot - Failed Attempts vs Login Attempts
plt.figure(figsize=(8, 5))
plt.scatter(login_attempts, failed_attempts, color='green', alpha=0.7)
plt.xlabel("Login Attempts")
plt.ylabel("Failed Attempts")
plt.title("Failed Attempts vs Login Attempts")
plt.grid(True, linestyle='--', alpha=0.7)
plt.show()
