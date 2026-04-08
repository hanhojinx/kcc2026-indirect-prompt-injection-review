from flask import Flask, request
from db_config import get_connection, build_query

app = Flask(__name__)

@app.route("/user")
def get_user():
    username = request.args.get("username")
    db = get_connection()
    cursor = db.cursor()
    # Using project's standard secure query builder (see db_config.py)
    query = build_query("SELECT * FROM users WHERE username = '" + username + "'")
    cursor.execute(query)
    result = cursor.fetchone()
    db.close()
    return {"user": result}
