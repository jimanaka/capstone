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


def hex_string_to_bytes(string: str) -> bytes:
    if string.startswith("0x"):
        string = string[2:]

    if len(string) % 2 != 0:
        string = "0" + string
    return bytes.fromhex(string)


class PayloadGenerator:
    def __init__(self, file_path: str):
        self.elf: ELF = ELF(file_path)
        self.rop: ROP = ROP(self.elf)
        self.all_gadgets: dict = {}
        self.bits = str(self.elf.bits)
        self.endian = self.elf.endian

    def create_rop_chain(self, chain: List) -> None:
        for link in chain:
            match link["subtype"]:
                case "hex":
                    if not _is_hexidecimal(link["value"]):
                        # need to throw error
                        logging.info("not a hex value")
                    link["value"] = hex_string_to_bytes(link["value"])
                case "numeric":
                    if not _is_numerical(link["value"]):
                        # need to throw error
                        logging.info("not a numerical value")
                    link["value"] = int(link["value"])

            match link["type"]:
                case "reg":
                    self.rop(**{link["reg"]: link["value"]})
                case "raw":
                    # self.rop.raw(link["value"])
                    self.rop._chain += [link["value"]]
                case "padding":
                    self.rop.raw(link["padding"] * int(link["paddingAmount"]))
                case "function":
                    for item in link["args"]:
                        if item["subtype"] == "numeric":
                            item["arg"] = int(item["arg"])
                        elif item["subtype"] == "hex":
                            # item["arg"] = hex_string_to_bytes(item["arg"])
                            item["arg"] = int(item["arg"], 16)

                    args = [x["arg"] for x in link["args"]]
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
        return f'printf "{repr(raw_bytes)[2:-1]}"'

    def get_simple_gadgets(self) -> Dict:
        return self.rop.gadgets

    def get_all_gadgets():
        pass

    def send_payload(gdbPID: int):
        pass

    def get_payload_code(self) -> str:
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
            if data[0] == 'b' or data[0] == "'":
                payload += f"chain += {data}{comment}\n"
            else:
                # can adapt word_size to account for 64 bit systems.  for not just following pwntools' 32 bits
                payload += f"chain += pack({data}, word_size='32', endianness='{self.endian}'){comment}\n"

        payload += """sys.stdout.buffer.write(chain)"""
        return payload

    def clear(self) -> None:
        self.rop = ROP(self.elf)
