from email.generator import DecodedGenerator
from flask import Flask, jsonify, request
from flask_pymongo import PyMongo
from flask_jwt_extended import JWTManager, create_access_token, get_jwt, get_jwt_identity, jwt_required, decode_token, get_jwt_header
from flask_cors import CORS, cross_origin
import datetime
import hashlib
import urllib
import hashlib
import os

app = Flask(__name__)
app.config.from_object("src.config.Config")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = datetime.timedelta(days=1)
app.config["CORS_HEADERS"] = "Content-Type"

jwt = JWTManager(app)
mongo = PyMongo(app)
CORS(app)
db = mongo.db

users_collection = db.users
templates_collection= db.templates

def _corsify_actual_response(response):
    response.headers.add("Access-Control-Allow-Origin", "*")
    return response

@app.route("/")
def hello_world():
    return jsonify(hello="world")

@app.route("/test")
def hello_world2():
    return jsonify(hello="world2"), 201

@app.route("/auth/register", methods=["POST"])
def register():
    new_user = request.get_json()
    new_user["password"] = hashlib.sha256(new_user["password"].encode("utf-8")).hexdigest()

    print(new_user)

    # check if user exist
    doc = users_collection.find_one({"username": new_user["username"]})

    # if it exists, return error
    if (doc):
        return jsonify({"msg": "Username exists"}), 409

    # create user
    users_collection.insert_one(new_user)

    return jsonify({"msg": "User created successfully"}), 201

@app.route("/auth/login", methods=["POST"])
def login():
    login_details = request.get_json()
    db_user = users_collection.find_one({"username": login_details["username"]})
    login_password = hashlib.sha256(login_details["password"].encode("utf-8")).hexdigest()

    if not db_user:
        return jsonify({"msg": "Username or password is incorrect"}), 401
    
    if login_password != db_user["password"]:
        return jsonify({"msg": "Username or password is incorrect"}), 401

    access_token = create_access_token(identity=db_user["username"])

    response = jsonify(access_token=access_token)
    response = _corsify_actual_response(response)
    return response, 200

@app.route("/auth/verify-user")
@jwt_required(optional=True)
def verify_user():
    current_user = get_jwt_identity()
    if not current_user:
        response = jsonify({"logged_in_as": "anonymous"})
    else:
        response = jsonify({"logged_in_as": current_user})
    return response, 200

@app.route("/auth/create", methods=["POST"])
@jwt_required()
def create_template():
    current_user = get_jwt_identity()
    db_user = users_collection.find_one({"username": current_user})

    if not db_user:
        return jsonify({"msg": "Access Token Expired"}), 404

    template_details = request.get_json()
    user_template = {"profile": db_user["username"], "template": template_details["template"]}
    doc = templates_collection.find_one(user_template)

    if doc:
        return jsonify({"msg": "Template already exists on your profile"}), 404

    templates_collection.insert_one(user_template)
    print("user_template: ", user_template)
    return jsonify({"msg": "Template created successfully"}), 200

@app.route("/v1/templates", methods=["GET"])
@jwt_required()
def get_templates():
    current_user = get_jwt_identity()
    db_user = users_collection.find_one({"username": current_user})

    if not db_user:
        return jsonify({"msg": "Access token expired"}), 404

    user_template = {"profile": db_user["username"]}
    return jsonify({"docs": list(templates_collection.find(user_template, {"_id": 0}))}), 200

@app.route("/v1/update_template", methods=["POST"])
@jwt_required()
def update_template():
    current_user = get_jwt_identity()
    db_user = users_collection.find_one({"username": current_user})
    if not db_user:
        return jsonify({"msg": "Access token expired"}), 404
    
    template_details = request.get_json()
    user_template = {"profile": db_user["username"], "template": template_details["old_template"]}
    doc = templates_collection.find_one(user_template)
    print("template details: ", template_details)
    print("user template: ", user_template)
    print(doc)

    if not doc:
        return jsonify({"msg": "Template does not exist on your profile"}), 404
    
    doc["template"] = template_details["new_template"]
    templates_collection.update_one(user_template, {"$set": {"template": doc["template"]}}, upsert=False)
    return jsonify({"msg": "Template updated successfully"}), 200

@app.route("/v1/delete_template", methods=["POST"])
@jwt_required()
def delete_template():
    current_user = get_jwt_identity()
    db_user = users_collection.find_one({"username": current_user})

    if not db_user:
        return jsonify({"msg": "Access token expired"}), 404

    template_details = request.get_json()
    user_template = {"profile": db_user["username"], "template": template_details["template"]}
    doc = templates_collection.find_one(user_template)

    if not doc:
        return jsonify({"msg": "Template does not exist on your profile"}), 404
    
    templates_collection.delete_one(user_template)
    return jsonify({"msg": "Template deleted successfully"}), 200
