#!/usr/bin/env python3

import sys
from hashlib import sha1, sha256
from itertools import count, product


def brute_Achievement02AsteroidAnnihilator():
	print('Achievement02AsteroidAnnihilator...')
	target = bytearray([0xdc, 0x1e, 0x5e, 0x97, 0xb3, 0x03, 0x46, 0x2f, 0x6c,
			0x9a, 0x00, 0x99, 0x94, 0xf1, 0x7f, 0xb8, 0x3d, 0x9f, 0x76, 0x24])

	for n in count(1):
		guess = str(n).encode()
		if sha1(guess).digest() == target:
			break
	else:
		sys.exit('Brute Achievement02AsteroidAnnihilator failed!')

	key = sha256(guess).hexdigest()
	print('->', n)
	print('->', key)


def brute_Achievement04InterstellarHacker():
	print('Achievement04InterstellarHacker...')
	target = bytearray([0xf5, 0x62, 0x73, 0xf6, 0x80, 0xf2, 0x0b, 0x7e, 0x00,
			0xa1, 0xfd, 0xd3, 0xa5, 0x44, 0x03, 0xbf, 0x8c, 0xc6, 0x57, 0x09])
	chars = bytearray(b'ABCDEFGHIJKLMNOPQRSTUVWXYZ')

	for guess in map(bytearray, product(chars, repeat=5)):
		if sha1(guess).digest() == target:
			break
	else:
		sys.exit('Brute Achievement04InterstellarHacker failed!')

	key = sha256(guess).hexdigest()
	print('->', guess.decode())
	print('->', key)


def brute_Achievement06Sharpshooter():
	print('Achievement06Sharpshooter...')
	target = bytearray([0x0b, 0x2f, 0x1c, 0x3f, 0x0d, 0xe2, 0xa5, 0x2c, 0x06,
			0x82, 0x4d, 0x9d, 0x4f, 0xc7, 0x47, 0x2e, 0xc1, 0xdf, 0xc9, 0x72])

	for deltas in product([25, 50, 100], repeat=9):
		guess = repr(list(deltas)).encode()
		if sha1(guess).digest() == target:
			break
	else:
		sys.exit('Brute Achievement06Sharpshooter failed!')

	key = sha256(guess).hexdigest()
	print('->', deltas)
	print('->', key)


def brute_Achievement08Survivor():
	print('Achievement08Survivor...')
	target = bytearray([0x15, 0xaa, 0x0c, 0x7e, 0x8f, 0xbd, 0x29, 0x23, 0xdb,
			0x70, 0x41, 0xd0, 0x12, 0xe8, 0x83, 0x8d, 0x66, 0xb9, 0x57, 0x2d])

	for time in count(1):
		guess = str(time).encode()
		if sha1(guess).digest() == target:
			break
	else:
		sys.exit('Brute Achievement08Survivor failed!')

	key = sha256(guess).hexdigest()
	print('->', time)
	print('->', key)


def brute_Achievement09Immortal():
	print('Achievement09Immortal...')
	target = bytearray([0x3e, 0x20, 0xa0, 0xed, 0x1e, 0x4c, 0xf8, 0x53, 0x36,
			0xc4, 0xa8, 0xb2, 0xb0, 0x6e, 0xe6, 0x1c, 0xbd, 0x40, 0xc3, 0x47])

	for time in count(1):
		guess = str(time).encode()
		if sha1(guess).digest() == target:
			break
	else:
		sys.exit('Brute Achievement09Immortal failed!')

	key = sha256(guess).hexdigest()
	print('->', time)
	print('->', key)


if __name__ == '__main__':
	brute_Achievement02AsteroidAnnihilator()
	brute_Achievement04InterstellarHacker()
	brute_Achievement06Sharpshooter()
	brute_Achievement08Survivor()
	brute_Achievement09Immortal()
