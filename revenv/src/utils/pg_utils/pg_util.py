import logging
from pprint import pprint
from src.utils.pg_utils.payload_generator import PayloadGenerator
from flask import jsonify
from http import HTTPStatus as HTTP
from typing import Dict, List, Tuple
from src.utils.request_util import corsify_response
from pygdbmi.IoManager import IoManager


def get_info(pg) -> Tuple[Dict, int]:
    available_regs = []
    simple_gadgets = []
    for gadget in pg.get_simple_gadgets().values():
        simple_gadgets.append({"address": hex(gadget.address), "insns": "; ".join(
            gadget.insns), "move": gadget.move, "regs": " " * (len(hex(gadget.address)) + 2) + "[" + ", ".join(gadget.regs) + "]"})
        available_regs.extend(
            item for item in gadget.regs if not item.startswith("0x"))
    response = corsify_response(
        jsonify(simple_gadgets=simple_gadgets, available_regs=available_regs))
    return response, HTTP.OK.value


def create_chain(pg: PayloadGenerator, chain: List) -> Tuple[Dict, int]:
    pg.clear()
    pg.create_rop_chain(chain)
    payload_dump = pg.dump()
    hexdump = pg.hexdump()
    return corsify_response(jsonify(payload_dump=payload_dump, hexdump=hexdump)), HTTP.OK.value


def get_payload_code(pg: PayloadGenerator) -> Tuple[Dict, int]:
    code = pg.get_payload_code()
    response = corsify_response(jsonify(code=code))
    return response, HTTP.OK.value


def use_payload(pg: PayloadGenerator, iomanager: IoManager) -> Tuple[Dict, int]:
    hex = "b\'" + ''.join([f'\\x{byte:02x}' for byte in pg.chain()]) + "\'"
    iomanager.write(f"run < <(python -c \"import sys; sys.stdout.buffer.write("
                    f"{hex})\")", timeout_sec=0, raise_error_on_timeout=False, read_response=False)
    return jsonify(msg="done"), HTTP.OK.value
