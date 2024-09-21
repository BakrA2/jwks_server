# import jwt
# import datetime
# import uuid
# from flask import Flask, jsonify, request
# from cryptography.hazmat.primitives.asymmetric import rsa
# from cryptography.hazmat.primitives import serialization

# # Initialize Flask app
# app = Flask(__name__)

# # Store keys with expiration
# keys = []

# def generate_rsa_key():
#     key = rsa.generate_private_key(
#         public_exponent=65537,
#         key_size=2048,
#     )
#     private_key = key.private_bytes(
#         encoding=serialization.Encoding.PEM,
#         format=serialization.PrivateFormat.PKCS8,
#         encryption_algorithm=serialization.NoEncryption()
#     )
#     public_key = key.public_key().public_bytes(
#         encoding=serialization.Encoding.PEM,
#         format=serialization.PublicFormat.SubjectPublicKeyInfo
#     )
#     return private_key, public_key

# def generate_key_pair():
#     private_key, public_key = generate_rsa_key()
#     kid = str(uuid.uuid4())
#     expiry = datetime.datetime.utcnow() + datetime.timedelta(days=7)
    
#     keys.append({
#         "kid": kid,
#         "private_key": private_key,
#         "public_key": public_key,
#         "expiry": expiry
#     })
    
#     return kid, public_key, expiry

# def get_jwks():
#     jwks = {
#         "keys": [
#             {
#                 "kty": "RSA",
#                 "kid": key["kid"],
#                 "use": "sig",
#                 "alg": "RS256",
#                 "n": jwt.utils.base64url_encode(key["public_key"]),
#                 "e": "AQAB"
#             }
#             for key in keys if key["expiry"] > datetime.datetime.utcnow()
#         ]
#     }
#     return jwks

# def create_jwt(kid, expired=False):
#     key_data = next((k for k in keys if k["kid"] == kid), None)
#     if not key_data:
#         return None
    
#     expiry = datetime.datetime.utcnow() - datetime.timedelta(days=1) if expired else datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    
#     payload = {
#         "sub": "1234567890",
#         "name": "John Doe",
#         "iat": datetime.datetime.utcnow(),
#         "exp": expiry,
#         "kid": kid
#     }
    
#     token = jwt.encode(payload, key_data["private_key"], algorithm="RS256", headers={"kid": kid})
#     return token

# # Generate initial keys
# generate_key_pair()

# @app.route('/.well-known/jwks.json', methods=['GET'])
# def jwks():
#     return jsonify(get_jwks())

# @app.route('/auth', methods=['POST'])
# def auth():
#     expired = request.args.get('expired', 'false').lower() == 'true'
#     kid, _, _ = generate_key_pair()
#     token = create_jwt(kid, expired)
#     return jsonify({"token": token})

# if __name__ == '__main__':
#     app.run(host='0.0.0.0', port=8080)
# #rsa key generation and formating 


# # add a test file


from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime

hostName = "localhost"
serverPort = 8080

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

numbers = private_key.private_numbers()


def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            headers = {
                "kid": "goodKID"
            }
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }
            if 'expired' in params:
                headers["kid"] = "expiredKID"
                token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
            encoded_jwt = jwt.encode(token_payload, pem, algorithm="RS256", headers=headers)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            keys = {
                "keys": [
                    {
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": "goodKID",
                        "n": int_to_base64(numbers.public_numbers.n),
                        "e": int_to_base64(numbers.public_numbers.e),
                    }
                ]
            }
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return


if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
