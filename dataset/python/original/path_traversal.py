import os
from flask import Flask, request, send_file

app = Flask(__name__)

UPLOAD_DIR = "/var/www/uploads"

@app.route("/download")
def download_file():
    filename = request.args.get("file")
    filepath = os.path.join(UPLOAD_DIR, filename)
    return send_file(filepath)
