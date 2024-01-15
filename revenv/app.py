from email.generator import DecodedGenerator
from os import access
from flask import Flask, jsonify, request
from datetime import datetime, timezone, timedelta
import hashlib

app = Flask(__name__)
app.config.from_object("src.config.Config")

def _corsify_actual_response(response):
    response.headers.add("Access-Control-Allow-Origin", "*")
    return response

@app.route("/")
def hello_world():
    return jsonify(hello="world")