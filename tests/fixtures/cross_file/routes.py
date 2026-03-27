"""Flask route handlers — user input enters here."""
from flask import Flask, request
from .utils import process_query, safe_process

app = Flask(__name__)


@app.route("/search")
def search():
    query = request.args.get("q")
    results = process_query(query)
    return {"results": results}


@app.route("/safe")
def safe_search():
    query = request.args.get("q")
    results = safe_process(query)
    return {"results": results}
