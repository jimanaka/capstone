from pwnlib import ELF, ROP
from pprint import pprint

binary = ELF("hello_world.out")
rop = ROP(binary)
pprint(rop.ret)
