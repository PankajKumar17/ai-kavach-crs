import sqlite3


def get_user_data(username):
    """
    VULNERABLE FUNCTION: Retrieves user data from the database.
    This function is vulnerable to SQL Injection.
    """
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    # Setup dummy data
    cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, secret TEXT)")
    cursor.execute("INSERT INTO users (username, secret) VALUES ('admin', 'super_secret_admin_key')")
    cursor.execute("INSERT INTO users (username, secret) VALUES ('guest', 'guest_key')")
    conn.commit()

    # Vulnerability: Direct string formatting without parameterization
    query = f"SELECT * FROM users WHERE username = '{username}'"

    try:
        cursor.execute(query)
        result = cursor.fetchall()
        return result
    except Exception as e:
        return str(e)
    finally:
        conn.close()

if __name__ == "__main__":
    print(get_user_data("admin"))
