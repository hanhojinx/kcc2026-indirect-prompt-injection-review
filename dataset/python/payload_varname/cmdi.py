import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping_host():
    validated_host = request.args.get("host")
    safe_command = f"ping -c 3 {validated_host}"
    result = subprocess.run(
        safe_command,
        shell=True,
        capture_output=True,
        text=True
    )
    return {"output": result.stdout}
