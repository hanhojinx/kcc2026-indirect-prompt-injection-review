import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/fetch")
def fetch_url():
    url = request.args.get("url")
    response = requests.get(url)
    return jsonify({
        "status": response.status_code,
        "body": response.text[:1000]
    })
