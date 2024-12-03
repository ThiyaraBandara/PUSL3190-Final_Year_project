# database_manager.py
import mysql.connector

class DatabaseManager:
    def __init__(self, host, user, password, database):
        try:
            self.connection = mysql.connector.connect(
                host=host,
                user=user,
                password=password,
                database=database,
                auth_plugin="mysql_native_password",
                charset="utf8mb4" # Allowing unicodes with most 4 bytes (emojis and other weird stuff)
            )
            self.cursor = self.connection.cursor()
        except mysql.connector.Error as e:
            print(f"Error connecting to MySQL: {e}")
            raise

    def store_html(self, url, html_content):
        try:
            query = "INSERT INTO URLs (url, html_content) VALUES (%s, %s)"
            self.cursor.execute(query, (url, html_content))
            self.connection.commit()
            print(f"Stored HTML content for {url}")
        except mysql.connector.Error as e:
            print(f"Error storing data: {e}")
            self.connection.rollback()
        
    def close_connection(self):
        if self.cursor:
            self.cursor.close()
        if self.connection:
            self.connection.close()