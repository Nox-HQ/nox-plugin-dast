from flask import Flask, request, redirect, make_response, jsonify
import requests

app = Flask(__name__)

# DAST-001: Missing security headers - response without security headers
@app.route("/")
def home():
    response = make_response("<html>Welcome</html>")
    return response

# DAST-002: Insecure CORS configuration
CORS_ALLOW_ALL_ORIGINS = True

@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response

# DAST-003: Missing TLS/HTTPS enforcement
SECURE_SSL_REDIRECT = False

def fetch_data():
    r = requests.get("http://api.example.com/data", verify=False)
    return r.json()

# DAST-004: Insecure cookie settings
SESSION_COOKIE_SECURE = False
SESSION_COOKIE_HTTPONLY = False

@app.route("/set-cookie")
def set_cookie():
    resp = make_response("ok")
    resp.set_cookie("session", "abc123", httponly=False)
    return resp

# DAST-005: Missing rate limiting on API endpoint
@app.route("/api/users", methods=["GET"])
def get_users():
    return jsonify(users=[])

@app.post("/api/orders")
def create_order():
    return jsonify(order_id=1)

# DAST-006: Open redirect
@app.route("/login")
def login():
    next_url = request.args.get("next")
    return redirect(request.args.get("redirect_to"))
