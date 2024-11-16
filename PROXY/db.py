import mariadb
import sys



# Connect to MariaDB Platform
try:
    conn = mariadb.connect(
        user="nuklearniuser",
        password="P7x5kMScw",
        host="10.128.40.94",
        port=12345,
        database="nuklearni_okurky"
    )
    print("Connection to MariaDB successful!")
except mariadb.Error as e:
    print(f"Error connecting to MariaDB Platform: {e}")
    sys.exit(1)

# Get Cursor
try:
    cur = conn.cursor()
    print("Cursor initialized successfully!")
except mariadb.Error as e:
    print(f"Error initializing cursor: {e}")
    conn.close()
    sys.exit(1)
