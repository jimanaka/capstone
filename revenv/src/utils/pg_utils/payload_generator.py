import re
import logging
from pygdbmi.IoManager import IoManager
from pwnlib.rop import ROP
from pwnlib.elf import ELF
from pwnlib.util.fiddling import hexdump
from typing import List, Dict, Tuple


def _is_hexidecimal(string: str) -> bool:
    pattern = re.compile(r'^[0-9a-fA-F]+$')
    return bool(pattern.match(string))


def _is_numerical(string: str) -> bool:
    pattern = re.compile(r'^[0-9]+$')
    return bool(pattern.match(string))


class PayloadGenerator:
    def __init__(self, file_path: str):
        self.elf: ELF = ELF(file_path)
        self.rop: ROP = ROP(self.elf)
        self.all_gadgets: dict = {}

    def create_rop_chain(self, chain: List) -> None:
        for link in chain:
            if link["subtype"] == "hex":
                if not _is_hexidecimal(link["value"]):
                    # need to throw error
                    logging.info("not a hex value")
                link["value"] = int(link["value"], 16)
            elif link["subtype"] == "numeric":
                if not _is_numerical(link["value"]):
                    # need to throw error
                    logging.info("not a numerical value")
                link["value"] = int(link["value"])

            match link["type"]:
                case "reg":
                    self.rop(**{link["reg"]: link["value"]})
                case "raw":
                    logging.info("length is " + str(len(chain)))
                    self.rop.raw(link["value"])
                case "padding":
                    pass
                case _:
                    continue

    def dump(self) -> str:
        return self.rop.dump()

    def hexdump(self) -> str:
        return hexdump(self.rop.chain())

    def chain(self) -> str:
        return self.rop.chain()

    def get_simple_gadgets(self) -> Dict:
        return self.rop.gadgets

    def get_all_gadgets():
        pass

    def send_payload(gdbPID: int):
        pass

    def clear(self) -> None:
        self.rop = ROP(self.elf)
