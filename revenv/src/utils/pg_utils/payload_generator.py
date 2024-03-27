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
            match link["subtype"]:
                case "hex" | "address":
                    if not _is_hexidecimal(link["value"]):
                        # need to throw error
                        logging.info("not a hex value")
                    link["value"] = int(link["value"], 16)
                case "numeric":
                    if not _is_numerical(link["value"]):
                        # need to throw error
                        logging.info("not a numerical value")
                    link["value"] = int(link["value"])

            match link["type"]:
                case "reg":
                    self.rop(**{link["reg"]: link["value"]})
                case "raw":
                    self.rop.raw(link["value"])
                case "padding":
                    self.rop.raw(link["padding"] * int(link["paddingAmount"]))
                case "function":
                    for item in link["args"]:
                        if item["subtype"] == "numeric":
                            item["arg"] = int(item["arg"])
                        elif item["subtype"] == "hex":
                            item["arg"] = int(item["arg"], 16)

                    args = [x["arg"] for x in link["args"]]
                    print(args)
                    self.rop.call(link["value"], args)
                case _:
                    continue

    def dump(self) -> str:
        return self.rop.dump()

    def hexdump(self) -> str:
        return hexdump(self.rop.chain())

    def chain(self) -> str:
        return self.rop.chain()

    def get_byte_string(self) -> str:
        raw_bytes = self.chain()
        return repr(raw_bytes)[2:-1]

    def get_simple_gadgets(self) -> Dict:
        return self.rop.gadgets

    def get_all_gadgets():
        pass

    def send_payload(gdbPID: int):
        pass

    def get_payload_code(self) -> str:
        bits = str(self.elf.bits)
        endian = self.elf.endian
        input_string = self.rop.dump()
# Split the string into lines
        lines = input_string.split('\n')
        data_comments = []

        for line in lines:
            tokens = line.split()
            data_comments.append((tokens[1], " ".join(tokens[2:])))

        payload = "from pwn import *\nimport sys\nchain = b''\n"
        for data, comment in data_comments:
            if comment != "":
                comment = "\t\t# " + comment
            payload += f"chain += pack({data}, word_size={bits}, endianness='{endian}'){comment}\n"

        payload += """sys.stdout.buffer.write(chain)"""
        return payload

    def clear(self) -> None:
        self.rop = ROP(self.elf)
