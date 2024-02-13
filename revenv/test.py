from pygdbmi.gdbcontroller import GdbController
from pprint import pprint
import re

gdbmi = GdbController()
print(gdbmi.command)
response = gdbmi.write("-file-exec-and-symbols /app/example-bins/hello_world.out")
pprint(response)
print("-------------------")
response = gdbmi.write("-exec-run")
pprint(response)

