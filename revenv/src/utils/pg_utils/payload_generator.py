import re
import logging
from pprint import pprint
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
            elif link["subtype"] == "numerical":
                if not _is_numerical(link["value"]):
                    # need to throw error
                    logging.info("not a numerical value")

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

    def hexdump(self) -> None:
        hexdump(self.rop.chain())

    def chain(self) -> str:
        return self.rop.chain()

    def get_simple_gadgets(self) -> Dict:
        return self.rop.gadgets

    def get_all_gadgets():
        pass

    def send_payload(gdbPID: int):
        pass

    def restart():
        pass


def do_stuff(iomanager: IoManager):
    elf = ELF("/app/user-uploads/test/hello_world.out")
    rop = ROP(elf)
    rop.raw(b'-break-insert main')
    print(f"{bytes(rop)}")
    iomanager.write(f"-exec-run < {bytes(rop)}", timeout_sec=0,
                    raise_error_on_timeout=False, read_response=False)
