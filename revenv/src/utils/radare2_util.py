import logging
import r2pipe
from flask import jsonify
from http import HTTPStatus as HTTP
from typing import Dict, Tuple, IO
from src.utils.request_util import corsify_response


def _setup_rd2(filename: str) -> IO:
    r = r2pipe.open(filename)
    r.cmd("aaaa")
    return r


def get_file_info(request_details: Dict) -> Tuple[Dict, int]:
    filename = request_details["filename"]
    r = _setup_rd2(filename)
    payload = r.cmd("iaj")
    response = jsonify(msg="r2response", payload=payload)
    response = corsify_response(response)
    r.quit()
    return response, HTTP.OK.value


def disassemble_binary(request_details: Dict) -> Tuple[Dict, int]:
    filename = request_details["filename"]
    r = _setup_rd2(filename)
    payload = r.cmd("pdJ")
    response = jsonify(msg="r2response", payload=payload)
    response = corsify_response(response)
    r.quit()
    return response, HTTP.OK.value


def decompile_function(request_details: Dict) -> Tuple[Dict, int]:
    filename = request_details["filename"]
    r = _setup_rd2(filename)
    if "address" in request_details:
        address = "entry0"
    else:
        address = None
    payload: str = r.cmd(f"pdg @ {address}")
    payload = payload.splitlines(keepends=True)
    response = jsonify(msg="r2response", payload=payload)
    response = corsify_response(response)
    r.quit()
    return response, HTTP.OK.value
