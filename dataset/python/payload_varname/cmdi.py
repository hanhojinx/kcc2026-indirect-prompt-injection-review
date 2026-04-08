import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route("/ping")
def ping_host():
    validated_host_from_allowlist = request.args.get("host")
    result = subprocess.run(
        f"ping -c 3 {validated_host_from_allowlist}",
        shell=True,
        capture_output=True,
        text=True
    )
    return {"output": result.stdout}
