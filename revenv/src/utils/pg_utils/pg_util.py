import logging
from src.utils.pg_utils.payload_generator import PayloadGenerator
from flask import jsonify
from http import HTTPStatus as HTTP
from typing import Dict, List, Tuple
from src.utils.request_util import corsify_response


def get_info(pg) -> Tuple[Dict, int]:
    payload_dump = pg.dump()
    simple_gadgets = [{"address": hex(x.address), "insns": "; ".join(x.insns), "move": x.move, "regs": " " * (len(hex(x.address)) + 2) + "[" + ", ".join(x.regs) + "]"} for x in pg.get_simple_gadgets().values()]
    response = corsify_response(jsonify(payload_dump=payload_dump, simple_gadgets=simple_gadgets))
    return response, HTTP.OK.value


def create_chain(pg: PayloadGenerator, chain: List) -> Tuple[Dict, int]:
    logging.info("CREATING PAYLOAD CHAIN")
    pg.create_rop_chain(chain)
    print(pg.dump())
    return corsify_response(jsonify(payload_string=pg.dump())), HTTP.OK.value
