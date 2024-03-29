import r2pipe
from flask import jsonify
from http import HTTPStatus as HTTP
from typing import Dict, Tuple, IO
from src.utils.request_util import corsify_response
from pprint import pprint


def _setup_rd2(filename: str) -> IO:
    r = r2pipe.open(filename)
    r.cmd("e log.level=1")
    r.cmd("aaaa")
    return r


def get_file_info(request_details: Dict) -> Tuple[Dict, int]:
    filename = request_details["filename"]
    r = _setup_rd2(filename)
    payload = r.cmdj("iaj")
    payload["afl"] = r.cmdj("aflj")
    response = jsonify(msg="r2response", payload=payload)
    response = corsify_response(response)
    r.quit()
    return response, HTTP.OK.value


def disassemble_binary(filename: str, direction: str = None, target: str = "", mode: str = "add") -> Tuple[Dict, int]:
    r = _setup_rd2(filename)

    if (direction == "up"):
        sign = "-"
    else:
        sign = ""

    if not target:
        target = ""

    payload = r.cmdj(f"pdJ {sign}64 @ {target}")
    response = jsonify(msg="r2response", payload=payload,
                       direction=direction, mode=mode)
    response = corsify_response(response)
    r.quit()
    return response, HTTP.OK.value


def decompile_function(filename: str, address: str = "") -> Tuple[Dict, int]:
    r = _setup_rd2(filename)
    decompiled_code: str = r.cmd(f"pddo @ {address}")
    lines = decompiled_code.splitlines(keepends=True)
    payload = []
    for line in lines:
        strings = line.split("|")
        address = strings[0].strip()
        if address != "":
            address = int(address, 16)
        else:
            address = None
        if len(strings) > 1:
            code = "".join(strings[1:])
            if len(code) > 0:
                code = code[1:]
        else:
            code = ""
        payload.append({"address": address, "code": code})

    response = jsonify(msg="r2response", payload=payload)
    response = corsify_response(response)
    r.quit()
    return response, HTTP.OK.value
