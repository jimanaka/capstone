from email.generator import DecodedGenerator
from os import access
from flask import Flask, jsonify, request
from flask_pymongo import PyMongo
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required, create_refresh_token, set_access_cookies, set_refresh_cookies, get_jwt, unset_access_cookies, unset_refresh_cookies, get_jti
from flask_cors import CORS, cross_origin
from datetime import datetime, timezone, timedelta
import hashlib
import hashlib

app = Flask(__name__)
app.config.from_object("src.config.Config")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=1)
app.config['JWT_ACCESS_COOKIE_PATH'] = "/api/auth/"
app.config['JWT_REFRESH_COOKIE_PATH'] = "/api/token/"
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_SECURE"] = False
app.config["CORS_HEADERS"] = "Content-Type"

jwt = JWTManager(app)
mongo = PyMongo(app)
CORS(app)
db = mongo.db

users_collection = db.users
templates_collection= db.templates
token_blacklist = db.tokenBlacklist
token_blacklist.create_index("expirationDate", expireAfterSeconds=0)

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
    refresh_token = create_refresh_token(identity=db_user["username"])

    response = jsonify({"msg": "Login successfull"})
    response = _corsify_actual_response(response)
    set_access_cookies(response, access_token)
    set_refresh_cookies(response, refresh_token)
    return response, 200

@app.route("/auth/verify-user")
@jwt_required(optional=True)
def verify_user():
    current_user = get_jwt_identity()
    print(current_user)
    if not current_user:
        response = jsonify({"logged_in_as": None})
    else:
        response = jsonify({"logged_in_as": current_user})
    return response, 200

@app.route("/token/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    current_jti = get_jwt()["jti"]
    response_token = token_blacklist.find_one({ "token": current_jti })
    if response_token is not None:
        response = jsonify({"error": "invalid JWT token"})
        response = _corsify_actual_response(response)
        return response, 401
    access_token = create_access_token(identity=current_user)
    response = jsonify({"msg": "access token refreshed"})
    response = _corsify_actual_response(response)
    set_access_cookies(response, access_token)
    return response, 200

@app.route("/token/logout", methods=["POST"])
@jwt_required(refresh=True)
def logout():
    current_user = get_jwt()
    exp = datetime.fromtimestamp(current_user["exp"], tz=timezone.utc)
    token_blacklist.insert_one({"token": current_user["jti"], "expirationDate": exp})
    response = jsonify({"msg": "logout successfull"})
    unset_access_cookies(response)
    unset_refresh_cookies(response)
    response = _corsify_actual_response(response)
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
