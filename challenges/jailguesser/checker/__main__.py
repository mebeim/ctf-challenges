#!/usr/bin/env python3
#
# @mebeim - 2024-09-18
#

import os
import sys
from base64 import b64encode
from pathlib import Path
from re import compile

from pwn import context, log, remote

HOST = os.getenv('HOST', 'jailguesser.challs.ecsc2024.it')
PORT = int(os.getenv('PORT', 47019))
FLAG_EXP = compile(r'ECSC\{[^}]+\}')
ROUND_EXP = compile(r'Round (\d+)/(\d+)')

def close_conn(r: remote):
	with context.local(log_level='ERROR'):
		r.close()

def run(b64exe: bytes) -> bool:
	with context.local(log_level='ERROR'):
		r = remote(HOST, PORT)

	r.sendlineafter(b'done.\n', b64exe)
	r.sendline(b'EOF')

	p = log.progress('Running')

	while 1:
		round_result = r.recvline(keepends=False).decode()
		p.status(round_result)

		match = ROUND_EXP.match(round_result)
		if match is None:
			p.failure('Unexpected output: ' + round_result)
			close_conn(r)
			return False

		if 'OK' not in round_result:
			p.failure(round_result)

			if 'bad guess' in round_result:
				r.recvuntil(b'---\n', timeout=1)
				diff = r.recvuntil(b'---\n', timeout=1).decode()
				log.failure(diff)

			close_conn(r)
			return False

		cur, tot = map(int, match.groups())
		if cur == tot:
			break

	p.success('all rounds OK')

	r.recvuntil(b'---\nYou ')
	outcome = r.recvline().decode()
	if outcome.startswith('lost'):
		close_conn(r)
		log.failure('Attempt lost!?')
		return False

	match = FLAG_EXP.search(outcome)
	if match is None:
		close_conn(r)
		log.failure('No flag!? Outcome: ' + repr(outcome))
		return False

	print(match.group(0))
	close_conn(r)
	return True


if __name__ == '__main__':
	solver = Path(__file__).parent / '../solver/solve'
	if not solver.exists():
		sys.exit('Compile ../solver first!')

	b64exe = b64encode(solver.read_bytes())

	for _ in range(10):
		try:
			if run(b64exe):
				break
		except EOFError:
			log.failure('EOFError')
	else:
		sys.exit('Exceded 10 attempts!')
