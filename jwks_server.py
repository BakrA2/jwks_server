#JWKS server 
#By: Bakr Alkhalid 
#Bma0152
#csce 3550.001

from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import sqlite3
import base64
import json
import jwt
import datetime

# Server configuration
hostName = "localhost"
serverPort = 8080

# SQLite DB file
db_file = "totally_not_my_privateKeys.db"

# Create SQLite table if not exists
def init_db():
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# Save a private key to the database
def save_key_to_db(key_pem, exp_timestamp):
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    c.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (key_pem, exp_timestamp))
    conn.commit()
    conn.close()

# Get a key from the database (expired or valid)
def get_key_from_db(expired=False):
    conn = sqlite3.connect(db_file)
    c = conn.cursor()

    # Retrieve expired or valid key based on the flag
    current_time = int(datetime.datetime.utcnow().timestamp())
    if expired:
        c.execute('SELECT key FROM keys WHERE exp <= ? ORDER BY exp LIMIT 1', (current_time,))
        print(f"Querying for expired keys before: {current_time}")
    else:
        c.execute('SELECT key FROM keys WHERE exp > ? ORDER BY exp LIMIT 1', (current_time,))
        print(f"Querying for valid keys after: {current_time}")

    row = c.fetchone()
    conn.close()

    # Return the key if found, otherwise None
    return row[0] if row else None

# Get all valid keys (for JWKS)
def get_all_valid_keys():
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    c.execute('SELECT key FROM keys WHERE exp > ?', (int(datetime.datetime.utcnow().timestamp()),))
    rows = c.fetchall()
    conn.close()
    return [row[0] for row in rows]

# Convert an integer to a Base64URL-encoded string
def int_to_base64(value):
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

# Serialize the private key to PEM format
def serialize_key(key):
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

# Deserialize a private key from PEM format
def deserialize_key(key_pem):
    return serialization.load_pem_private_key(key_pem, password=None)

# Initialize the database and add keys
def initialize_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    # Save valid key (expires in 1 hour)
    valid_key_expiration = int((datetime.datetime.utcnow() + datetime.timedelta(hours=1)).timestamp())
    save_key_to_db(serialize_key(private_key), valid_key_expiration)
    
    # Save expired key (expired 1 hour ago)
    expired_key_expiration = int((datetime.datetime.utcnow() - datetime.timedelta(hours=1)).timestamp())
    save_key_to_db(serialize_key(expired_key), expired_key_expiration)
    
    # Debugging prints to verify correct insertion of keys
    print("Inserted valid key with exp:", valid_key_expiration)
    print("Inserted expired key with exp:", expired_key_expiration)

# Define server and request handlers
class MyServer(BaseHTTPRequestHandler):
    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        
        # If the request is to the "/auth" endpoint, generate a JWT token
        if parsed_path.path == "/auth":
            expired = 'expired' in params
            key_pem = get_key_from_db(expired)
            
            if key_pem:
                private_key = deserialize_key(key_pem)
                numbers = private_key.private_numbers()

                headers = {
                    "kid": "expiredKID" if expired else "goodKID"
                }
                token_payload = {
                    "user": "username",
                    "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1) if not expired else datetime.datetime.utcnow() - datetime.timedelta(hours=1)
                }
                encoded_jwt = jwt.encode(token_payload, private_key, algorithm="RS256", headers=headers)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(bytes(encoded_jwt, "utf-8"))
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"No valid key found.")
            return
        
        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            valid_keys = get_all_valid_keys()
            keys = []

            for key_pem in valid_keys:
                private_key = deserialize_key(key_pem)
                numbers = private_key.private_numbers()
                jwk = {
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "goodKID",
                    "n": int_to_base64(numbers.public_numbers.n),
                    "e": int_to_base64(numbers.public_numbers.e),
                }
                keys.append(jwk)

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(json.dumps({"keys": keys}), "utf-8"))
            return
        
        self.send_response(405)
        self.end_headers()
        return

# Main execution to start the server
if __name__ == "__main__":
    init_db()  # Initialize the SQLite database
    initialize_keys()  # Insert initial keys
    
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
