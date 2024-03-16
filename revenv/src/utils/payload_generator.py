from pygdbmi.IoManager import IoManager
from pwn import ELF, ROP


def do_stuff(iomanager: IoManager):
    elf = ELF("/app/user-uploads/test/hello_world.out")
    rop = ROP(elf)
    rop.raw(b'-break-insert main')
    print(f"{bytes(rop)}")
    iomanager.write(f"-exec-run < {bytes(rop)}", timeout_sec=0,
                    raise_error_on_timeout=False, read_response=False)
