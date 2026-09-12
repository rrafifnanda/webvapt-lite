"""Intentionally vulnerable fixture for local authorized testing only."""

from flask import Flask, request

app = Flask(__name__)


@app.get("/")
def index():
    return "<h1>hi</h1>", 200, {"Content-Type": "text/html"}


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
