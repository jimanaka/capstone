import logging
from flask import jsonify
from http import HTTPStatus as HTTP
from typing import Dict, Tuple
from src.utils.request_util import corsify_response


def test_func(request_details: Dict) -> Tuple[Dict, int]:
    logging.info("testing api")
    response = jsonify(msg="this is a test")
    response = corsify_response(response)
    return response, HTTP.OK.value
