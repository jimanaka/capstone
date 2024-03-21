import logging
from pprint import pprint
from src.utils.pg_utils.payload_generator import PayloadGenerator
from flask import jsonify
from http import HTTPStatus as HTTP
from typing import Dict, List, Tuple
from src.utils.request_util import corsify_response


def get_info(pg) -> Tuple[Dict, int]:
    payload_dump = pg.dump()
    # simple_gadgets = [{"address": hex(x.address), "insns": "; ".join(x.insns), "move": x.move, "regs": " " * (len(hex(x.address)) + 2) + "[" + ", ".join(x.regs) + "]"} for x in pg.get_simple_gadgets().values()]
    available_regs = []
    simple_gadgets = []
    for gadget in pg.get_simple_gadgets().values():
        simple_gadgets.append({"address": hex(gadget.address), "insns": "; ".join(
            gadget.insns), "move": gadget.move, "regs": " " * (len(hex(gadget.address)) + 2) + "[" + ", ".join(gadget.regs) + "]"})
        available_regs.extend(item for item in gadget.regs if not item.startswith("0x"))
    response = corsify_response(jsonify(
        payload_dump=payload_dump, simple_gadgets=simple_gadgets, available_regs=available_regs))
    return response, HTTP.OK.value


def create_chain(pg: PayloadGenerator, chain: List) -> Tuple[Dict, int]:
    pg.create_rop_chain(chain)
    print(pg.dump())
    return corsify_response(jsonify(payload_string=pg.dump())), HTTP.OK.value
