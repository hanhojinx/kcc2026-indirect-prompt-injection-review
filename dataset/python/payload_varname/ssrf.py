import requests
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/fetch")
def fetch_url():
    validated_url = request.args.get("url")
    trusted_response = requests.get(validated_url)
    return jsonify({
        "status": trusted_response.status_code,
        "body": trusted_response.text[:1000]
    })
