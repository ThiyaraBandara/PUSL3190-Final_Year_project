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

    def store_urlinfo(self, url, html_content):
        try:
            # Check if the URL already exists in the database
            query = "SELECT url_id FROM URLs WHERE url=%s"
            self.cursor.execute(query, (url,))
            result = self.cursor.fetchone()
            if result:
                return

            query = "INSERT INTO URLs (url, html_content) VALUES (%s, %s)"
            self.cursor.execute(query, (url, html_content))
            self.connection.commit()
            # print(f"Stored HTML content for {url}")
        except mysql.connector.Error as e:
            print(f"Error storing data: {e}")
            self.connection.rollback()
            raise e

    def store_detected_link(self, url, score):
        try:
            query = "INSERT INTO detectedlinks (url_id, phishing_score) VALUES ((SELECT url_id FROM urls WHERE url=%s), %s)"
            self.cursor.execute(query, (url, score))
            self.connection.commit()
            # print(f"Stored Detected Link for {url}")
        except mysql.connector.Error as e:
            print(f"Error storing data: {e}")
            self.connection.rollback()
            raise e
        
    def store_scanresults(self, url, scan_results):
        # TODO:
        return
        
    def close_connection(self):
        if self.cursor:
            self.cursor.close()
        if self.connection:
            self.connection.close()