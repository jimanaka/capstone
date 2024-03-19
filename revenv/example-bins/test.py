from pwnlib.rop import ROP
from pwnlib.elf import ELF

instructions = [{"type": "setReg", "regValues": {"rsp": 0xdeadbeef}}, {"type": "setReg"}]

binary = ELF("hello_world.out")
rop = ROP(binary)

for insn in instructions:
    match insn["type"]:
        case "setReg":
            rop(**insn["regValues"])

        case _:
            print("nothing...")

print(rop.dump())
