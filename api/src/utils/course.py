from flask import jsonify
from typing import Dict, Tuple
from http import HTTPStatus as HTTP
from datetime import datetime, timezone
from bson.json_util import dumps
from bson.objectid import ObjectId
from src.utils.mongo_context import MongoContext
from src.constants import COURSES_COLLECTION, USERS_COLLECTION
from src.utils.request_util import corsify_response


def _get_db(ctx: MongoContext):
    return ctx.mongo.db


def get_registered_course(username: str, course_id: str, db_ctx: MongoContext) -> Tuple[Dict, int]:
    users_col = _get_db(db_ctx)[USERS_COLLECTION]
    courses_col = _get_db(db_ctx)[COURSES_COLLECTION]

    user_doc = users_col.find_one({"username": username})
    if user_doc is None:
        response = corsify_response(
            jsonify(msg="Unable to get course; user not found"))
        return response, HTTP.UNAUTHORIZED.value

    course_doc = courses_col.find_one({"_id": ObjectId(course_id)})
    if course_doc is None:
        response = corsify_response(
            jsonify(msg="Unable to get course; course not found"))
        return response, HTTP.NOT_FOUND.value
    response = jsonify(course=dumps(course_doc))
    response = corsify_response(response)
    return response, HTTP.OK.value


def get_registered_courses(username: str, db_ctx: MongoContext) -> Tuple[Dict, int]:
    users_col = _get_db(db_ctx)[USERS_COLLECTION]
    doc = users_col.find_one({"username": username})

    if doc is None:
        response = jsonify(msg="Unable to get courses; user not found")
        response = corsify_response(response)
        return response, HTTP.UNAUTHORIZED.value
    if "registered_courses" not in doc:
        response = corsify_response(jsonify(courses="[]")), HTTP.OK.value
        return response

    courses = doc["registered_courses"]
    response = jsonify(courses=dumps(courses))
    response = corsify_response(response)
    return response, HTTP.OK.value


def get_available_courses(db_ctx: MongoContext, next_cursor: str = None) -> Tuple[Dict, int]:
    # this has been setup to use cursor pagination for infinite scrolling effects. This has not been fully implemented yet, but can be in the future
    courses_col = _get_db(db_ctx)[COURSES_COLLECTION]
    if next_cursor is None:
        query = {"private": False}
    else:
        query = {"private": False, "_id": {"$gt": next_cursor}}
    # commented out because the limit is for cursor pagination
    # cursor = courses_col.find(query, limit=10, sort={"date": -1})
    cursor = courses_col.find(query, sort={"date": -1})

    if cursor is None:
        response = corsify_response(
            jsonify(msg="Unable to get available courses"))
        return response, HTTP.SERVICE_UNAVAILABLE.value

    courses = list(cursor)
    courses = dumps(courses)
    response = corsify_response(jsonify(courses=courses))
    return response, HTTP.OK.value


def insert_course(username: str, course: Dict, db_ctx: MongoContext) -> Tuple[Dict, int]:
    courses_col = _get_db(db_ctx)[COURSES_COLLECTION]
    course["author"] = username
    course["date"] = datetime.now(tz=timezone.utc)
    doc = courses_col.insert_one(course)

    if doc is None:
        response = corsify_response(jsonify(msg="unable to insert course"))
        return response, HTTP.SERVICE_UNAVAILABLE.value

    response = corsify_response(jsonify(msg="course inserted"))
    return response, HTTP.OK.value


def register_course(username: str, course_id: str, db_ctx: MongoContext) -> Tuple[Dict, int]:
    users_col = _get_db(db_ctx)[USERS_COLLECTION]
    courses_col = _get_db(db_ctx)[COURSES_COLLECTION]
    user_doc = users_col.find_one({"username": username})
    course_doc = courses_col.find_one({"_id": ObjectId(course_id)}, {
                                      "_id": 1, "name": 1, "binary": 1})

    if user_doc is None:
        result = corsify_response(jsonify(
            msg="Could not find user account")), HTTP.NETWORK_AUTHENTICATION_REQUIRED.value
        return result
    if course_doc is None:
        result = corsify_response(
            jsonify(msg="Could not find course to register")), HTTP.NOT_FOUND.value
        return result

    if "registered_courses" in user_doc:
        if course_id in user_doc["registered_courses"]:
            result = corsify_response(
                jsonify(msg="Already registered for course")), HTTP.OK.value
            return result

    result = users_col.update_one(
        {"username": username},
        {"$push": {"registered_courses": course_doc}}
    )

    if result.modified_count > 0:
        result = corsify_response(
            jsonify(msg="Successfully registered course")), HTTP.OK.value
    else:
        result = corsify_response(
            jsonify(msg="Failed to register course")), HTTP.SERVICE_UNAVAILABLE.value
    return result
