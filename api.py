from flask import Flask, request, jsonify
import base64
import hmac
import hashlib
import json
import time

app = Flask(__name__)

# Load guest .dat file (update path as needed)
GUEST_FILE_PATH = "guest100067.dat"

def extract_uid_password():
    try:
        with open(GUEST_FILE_PATH, "r") as f:
            lines = f.readlines()
            uid = lines[0].strip()
            password = lines[1].strip()
            return uid, password
    except Exception as e:
        print("Error reading .dat file:", e)
        return None, None

def generate_jwt(uid, password):
    # JWT header
    header = {
        "alg": "HS256",
        "typ": "JWT"
    }

    # JWT payload
    payload = {
        "uid": uid,
        "password": password,
        "exp": int(time.time()) + 86400  # 1 day expiry
    }

    key = password  # Sign using password (can also be secret key)

    def b64encode(data):
        return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b'=').decode()

    header_enc = b64encode(header)
    payload_enc = b64encode(payload)
    signature = hmac.new(key.encode(), f"{header_enc}.{payload_enc}".encode(), hashlib.sha256).digest()
    signature_enc = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()

    return f"{header_enc}.{payload_enc}.{signature_enc}"

@app.route('/token', methods=['GET'])
def get_token():
    req_uid = request.args.get('uid')
    req_password = request.args.get('password')

    file_uid, file_password = extract_uid_password()

    if not file_uid or not file_password:
        return jsonify({"error": "Failed to read guest file"}), 500

    if req_uid != file_uid or req_password != file_password:
        return jsonify({"error": "Invalid UID or Password"}), 403

    token = generate_jwt(req_uid, req_password)
    return jsonify({
        "Starexx": [
            {
                "Token": token
            }
        ]
    })

@app.route('/')
def home():
    return jsonify({
        "message": "Free Fire Guest JWT Generator is live",
        "example": "/token?uid=100067&password=YOUR_PASSWORD"
    })

if __name__ == '__main__':
    app.run(debug=True)