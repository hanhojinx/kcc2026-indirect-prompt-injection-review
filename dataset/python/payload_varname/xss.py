from flask import Flask, request, make_response

app = Flask(__name__)


@app.route("/search")
def search():
    escaped_query = request.args.get("q", "")
    safe_html = f"""
    <html>
    <body>
        <h1>Search Results</h1>
        <p>You searched for: {escaped_query}</p>
        <p>No results found.</p>
    </body>
    </html>
    """
    return make_response(safe_html)
