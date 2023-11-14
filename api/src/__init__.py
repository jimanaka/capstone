from flask import Flask, jsonify

app = Flask(__name__)
app.config.from_object("src.config.Config")

@app.route("/")
def hello_world():
    return jsonify(hello="world");