"""Intentionally vulnerable fixture for local authorized testing only."""

from flask import Flask, request

app = Flask(__name__)


@app.get("/")
def index():
    return (
        '<h1>hi</h1><a href="/search?q=test">s</a><a href="/item?id=1">i</a>'
        '<a href="/admin">a</a>',
        200,
        {"Content-Type": "text/html"},
    )


@app.get("/admin")
def admin():
    # exposed admin panel fixture (200 = interesting for dirs probe)
    return "<h1>admin panel</h1>", 200, {"Content-Type": "text/html"}


@app.get("/server-status")
def server_status():
    # exposed internal page fixture (403 = interesting for dirs probe)
    return "forbidden", 403


@app.after_request
def _cors_wild(resp):
    # intentionally lax CORS fixture
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp


@app.get("/search")
def search():
    q = request.args.get("q", "")
    # reflected XSS fixture
    return f"<p>results for {q}</p>", 200, {"Content-Type": "text/html"}


@app.get("/item")
def item():
    _id = request.args.get("id", "1")
    if "'" in _id:
        return "You have an error in your SQL syntax near 'x'", 500
    return f"item {_id}", 200


if __name__ == "__main__":
    app.run(port=8765)
