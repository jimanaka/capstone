import logging
import r2pipe
from flask import jsonify
from http import HTTPStatus as HTTP
from typing import Dict, Tuple
from src.utils.request_util import corsify_response
from pprint import pprint


def test_func(request_details: Dict) -> Tuple[Dict, int]:
    filename = request_details["filename"]
    r = r2pipe.open(filename)
    payload = r.cmd("iaj")
    response = jsonify(msg="r2response", payload=payload)
    response = corsify_response(response)
    return response, HTTP.OK.value
