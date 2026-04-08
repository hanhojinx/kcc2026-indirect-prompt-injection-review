from flask import Flask, request, make_response

app = Flask(__name__)

@app.route("/search")
def search():
    query = request.args.get("q", "")
    html = f"""
    <html>
    <body>
        <h1>Search Results</h1>
        <p>You searched for: {query}</p>
        <p>No results found.</p>
    </body>
    </html>
    """
    return make_response(html)
