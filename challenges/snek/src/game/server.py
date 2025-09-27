#!/usr/bin/env python3
#
# @mebeim - 2025-09-27
#

import sys
import os
from pathlib import Path
from subprocess import check_call, CalledProcessError, TimeoutExpired
from tempfile import NamedTemporaryFile

mydir = Path(__file__).parent
os.chdir(mydir)

print('Replay size: ', end='', flush=True)

try:
	sz = int(sys.stdin.buffer.readline(), 0)
except ValueError:
	print('Malformed size!')
	sys.exit(1)

if sz <= 0 or sz > (1 << 20):
	print('Invalid size!')
	sys.exit(1)

print('Replay data: ', end='', flush=True)

replay = b''
while len(replay) != sz:
	replay += sys.stdin.buffer.read(sz - len(replay))

print('Validating your replay...', flush=True)

with NamedTemporaryFile('wb', prefix='snek_game_replay_') as f:
	f.write(replay)
	f.flush()

	try:
		check_call(['./snek', '--fast-replay', f.name],
			env={'SDL_VIDEODRIVER': 'dummy'}, timeout=10)
	except TimeoutExpired:
		print('Verification timed out!')
		sys.exit(1)
	except CalledProcessError:
		print('You crashed the game! WTF?!')
		sys.exit(1)

print('Replay validated!', flush=True)

yesno = ''
while yesno not in ('y', 'n'):
	print('Download game screenshot (y/n)? ', end='', flush=True)
	yesno = input()

if yesno == 'n':
	print('Bye bye!')
	sys.exit(0)

screenshot = None

try:
	with open('/tmp/snek.png', 'rb') as f:
		screenshot = f.read()
except FileNotFoundError:
	print('Something went wrong!', flush=True)
	sys.exit(1)

if screenshot is None:
	print('Something went wrong!', flush=True)
	sys.exit(1)

sys.stdout.buffer.write(screenshot)
sys.stdout.flush()
sys.exit(0)
