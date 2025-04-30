from flask import Flask, request, jsonify
import jwt
import datetime

app = Flask(__name__)

SECRET_KEY = "Ujjaiwal"

@app.route('/token', methods=['GET'])
def generate_token():
    uid = request.args.get('uid')
    password = request.args.get('password')

    if not uid or not password:
        return jsonify({'error': 'UID and password required'}), 400

    payload = {
        'uid': uid,
        'password': password,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return jsonify({'token': token})