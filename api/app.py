from flask import Flask, jsonify, request
from flask_pymongo import PyMongo

app = Flask(__name__)
app.config.from_object("src.config.Config")

mongo = PyMongo(app)
db = mongo.db

@app.route("/")
def hello_world():
    return jsonify(hello="world");

