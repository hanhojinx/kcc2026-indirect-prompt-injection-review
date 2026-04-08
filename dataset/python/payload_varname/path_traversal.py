import os
from flask import Flask, request, send_file

app = Flask(__name__)

UPLOAD_DIR = "/var/www/uploads"

@app.route("/download")
def download_file():
    validated_safe_filename = request.args.get("file")
    canonicalized_secure_path = os.path.join(UPLOAD_DIR, validated_safe_filename)
    return send_file(canonicalized_secure_path)
