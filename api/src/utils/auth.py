import logging
from flask import jsonify
from flask_jwt_extended import create_access_token, create_refresh_token, set_access_cookies, set_refresh_cookies, unset_access_cookies, unset_refresh_cookies
from hashlib import sha256
from typing import Dict, Tuple
from http import HTTPStatus as HTTP
from datetime import datetime, timezone
from src.utils.mongo_context import MongoContext
from src.constants import USERS_COLLECTION, TOKEN_BLACKLIST_COLLECTION
from src.utils.request_util import corsify_response


def _get_db(ctx: MongoContext):
    return ctx.mongo.db


def register_user(user: Dict, db_ctx: MongoContext) -> Tuple[Dict, int]:
    user["password"] = sha256(user["password"].encode("utf-8")).hexdigest()
    # check if user exists
    db = _get_db(db_ctx)
    users_col = db[USERS_COLLECTION]
    doc = users_col.find_one({"username": user["username"]})
    # if doc exists, error
    if (doc):
        logging.info(
            f'attempted to register an already existing username: {user["username"]}')
        return jsonify({"msg": "User already exists"}), HTTP.CONFLICT.value
    # else create the user
    try:
        user["courses"] = {}
        users_col.insert_one(user)
        logging.info(f'successfully registered user: {user["username"]}')
        return jsonify({"msg": "User registered successfully"}), HTTP.CREATED.value
    except Exception:
        logging.error(f'failed to insert user: {user["username"]} to database')
        return jsonify({"msg": "failed to register user. Please try again"})


def login_user(user: Dict, db_ctx: MongoContext) -> Tuple[Dict, int]:
    db = _get_db(db_ctx)
    users_col = db[USERS_COLLECTION]
    db_user = users_col.find_one({"username": user["username"]})
    login_password = sha256(user["password"].encode("utf-8")).hexdigest()

    if not db_user:
        logging.info(f"unsucessful login for user: {user}")
        return jsonify({"msg": "Username or Password is incorrect"}), HTTP.UNAUTHORIZED.value
    if login_password != db_user["password"]:
        logging.info(f"unsucessful login for user: {user}")
        return jsonify({"msg": "Username or Password is incorrect"}), HTTP.UNAUTHORIZED.value

    access_token = create_access_token(identity=db_user["username"])
    refresh_token = create_refresh_token(identity=db_user["username"])
    response = jsonify(msg="Login successfull")
    response = corsify_response(response)
    set_access_cookies(response, access_token)
    set_refresh_cookies(response, refresh_token)
    return response, HTTP.OK.value


def verify_user(user: str) -> Tuple[Dict, int]:
    response = None
    if not user:
        response = jsonify({"logged_in_as": None})
    else:
        response = jsonify({"logged_in_as": user})
    return response, HTTP.OK.value


def refresh_token(user: str, jti: str, db_ctx: MongoContext) -> Tuple[Dict, int]:
    db = _get_db(db_ctx)
    token_blacklist_col = db[TOKEN_BLACKLIST_COLLECTION]
    response_token = token_blacklist_col.find_one({"token": jti})
    if response_token is not None:
        response = jsonify({"error": "invalid JWT token"})
        response = corsify_response(response)
        return response, HTTP.UNAUTHORIZED.value
    access_token = create_access_token(identity=user)
    response = jsonify({"msg": "access token refreshed"})
    response = corsify_response(response)
    set_access_cookies(response, access_token)
    return response, HTTP.OK.value


def logout_user(user: Dict, db_ctx: MongoContext) -> Tuple[Dict, int]:
    token_blacklist_col = _get_db(db_ctx)[TOKEN_BLACKLIST_COLLECTION]
    exp = datetime.fromtimestamp(user["exp"], tz=timezone.utc)
    token_blacklist_col.insert_one(
        {"token": user["jti"], "expirationDate": exp})
    response = jsonify({"msg": "logout successfull"})
    unset_access_cookies(response)
    unset_refresh_cookies(response)
    response = corsify_response(response)
    return response, HTTP.OK.value
