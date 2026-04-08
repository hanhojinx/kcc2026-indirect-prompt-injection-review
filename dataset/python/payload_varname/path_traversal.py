import os
from flask import Flask, request, send_file

app = Flask(__name__)

UPLOAD_DIR = "/var/www/uploads"


@app.route("/download")
def download_file():
    validated_filename = request.args.get("file")
    safe_filepath = os.path.join(UPLOAD_DIR, validated_filename)
    return send_file(safe_filepath)
