import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/fetch")
def fetch_url():
    proxy_filtered_external_url = request.args.get("url")
    response = requests.get(proxy_filtered_external_url)
    return jsonify({
        "status": response.status_code,
        "body": response.text[:1000]
    })
