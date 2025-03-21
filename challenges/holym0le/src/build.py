#!/usr/bin/env python3
#
# @mebeim - 2024-04-14
#

import argparse
import atexit
import sys
import warnings
from hashlib import sha256
from os import mkfifo, getcwd
from pathlib import Path
from select import poll, POLLIN
from shutil import rmtree
from string import ascii_lowercase, digits
from subprocess import check_call, Popen, PIPE, DEVNULL
from tempfile import mkdtemp
from time import sleep, monotonic
from typing import Tuple, Optional
from urllib.request import urlopen

import fs
from fs.base import FS


def log(*a, **kwa):
	if NOPROGRESS:
		return

	print(*a, **kwa, flush=True)


def parse_args() -> argparse.Namespace:
	ap = argparse.ArgumentParser()

	ap.add_argument('--display', action='store_true',
		help='show VM display while building stuff (let QEMU open a new window)')
	ap.add_argument('--kvm', action='store_true',
		help='enable KVM for faster emulation (and therefore faster build)')
	ap.add_argument('--quiet', action='store_true',
		help='do not output information about build steps')
	ap.add_argument('--skip-setup', action='store_true',
		help='skip initial TinkerOS setup to bootstrap next build steps')

	return ap.parse_args()


def cwdrel(path: Path):
	return path.relative_to(getcwd())


def get_tinkeros_iso(iso: Path):
	if not iso.exists():
		log(f'Downloading TinkerOS_5.13.ISO to {cwdrel(iso)}')
		with urlopen('https://github.com/tinkeros/TinkerOS/releases/download/5.13/TinkerOS_5.13.ISO') as conn:
			data = conn.read()

		assert sha256(data).hexdigest() == '65f3db52b7b97432e35f918d2790dfbe6df69620899297d95127b0a14071d6c0'
		iso.write_bytes(data)


def qemu_run(disk: Path, iso: Optional[Path]=None, graphic: bool=False,
		kvm: bool=False) -> Tuple[Popen,Path]:
	# Create a pipe to forward guest serial COM1 to host
	tmpdir = Path(mkdtemp(prefix='templeos-install-'))
	com1_fifo = tmpdir / 'com1'
	mkfifo(com1_fifo)

	atexit.register(rmtree, tmpdir)

	args = [
		'qemu-system-x86_64',
		'-smp', 'cores=1',
		'-cpu', 'qemu64,-svm',
		'-m', '1G',
		'-rtc', 'base=localtime',
		'-monitor', 'stdio',
		'-serial', f'pipe:{com1_fifo}',
		'-drive', f'format=raw,file={str(disk.resolve())}'
	]

	if not graphic:
		args += ['-display', 'none']
	if kvm:
		args += ['-enable-kvm']
	if iso:
		args += ['-cdrom', iso, '-boot', 'd']

	return Popen(args, stdin=PIPE, stdout=PIPE), com1_fifo


def qemu_send_as_keys(qemu: Popen, keys: str):
	keymap = {c: c for c in ascii_lowercase + digits}
	keymap |= {c.upper(): f'shift-{c}' for c in ascii_lowercase}
	keymap |= {
		'(': 'shift-9', ')': 'shift-0',
		"'": 'apostrophe', '"': 'shift-apostrophe',
		'=': 'equal', '+': 'shift-equal', ' ': 'spc',
		',': 'comma', ';': 'semicolon', '&': 'shift-7', '\n': 'ret'
	}

	for k in keys:
		qemu.stdin.write(f'sendkey {keymap[k]}\n'.encode())

	qemu.stdin.flush()
	sleep(1) # for good measure


def qemu_sync_with_serial_and_quit(qemu: Popen, com1_fifo: Path,
		inject: bool=False, timeout: float=666.0):
	log('  - Waiting for sync through serial')

	with com1_fifo.open('rb') as com1:
		p = poll()
		p.register(com1.fileno(), POLLIN)
		err = None
		start = monotonic()

		while 1:
			if monotonic() - start > timeout:
				err = 'Failed: timeout waiting for data on serial port'
				break

			# With inject=False we expect the guest to perform the write itself
			if inject:
				# Don't bother setting up serial port properly, make the guest
				# keep writing 'X' until we read it from the host.
				qemu_send_as_keys(qemu, "OutU8(0x3f8,'X');\n")

			# Only one fd registered so we can treat the list as boolean
			if not p.poll(1.0):
				continue

			x = com1.read(1)
			if not x:
				err = 'Failed: unexpected EOF on serial port'
			elif x != b'X':
				err = 'Failed: bad ACK from guest on serial port:' + repr(x)

			break

	qemu.stdin.write(b'quit\n')
	qemu.stdin.flush()
	assert qemu.wait() == 0

	if err:
		sys.exit(err)


def create_disk(path: Path, size: str):
	log(f'Creating raw disk at {cwdrel(path)} of size {size}')
	check_call(('qemu-img', 'create', '-f', 'raw', path, size), stdout=DEVNULL, stderr=DEVNULL)


def convert_disk(src: Path, dst: Path, src_fmt: str, dst_fmt: str):
	log(f'Converting {src_fmt} disk to {dst_fmt}: {cwdrel(src)} -> {cwdrel(dst)}')
	check_call(['qemu-img', 'convert', '-f', src_fmt, '-O', dst_fmt, src, dst])


def replace_flag_in_raw_disk(src: Path):
	with warnings.catch_warnings():
		# Ignore some annoying but harmless pyfatfs warnings
		warnings.simplefilter('ignore')

		with fs.open_fs(f'fat://{src}?offset={512 * 63}') as vmfs:
			# Ensure real flag exists and replace its content: we only want the
			# normal uncompressed version for consistency
			assert not vmfs.exists('/Home/Flag.TXT.Z')
			assert vmfs.exists('/Home/Flag.TXT')

			flag = vmfs.readbytes('/Home/Flag.TXT')
			redacted_flag = b'ptm{REDACTED}'.ljust(len(flag) - 1) + b'\n'
			assert len(flag) == len(redacted_flag)

			vmfs.writebytes('/Home/Flag.TXT', redacted_flag)


def run_vm_install_os(disk: Path, iso: Path, graphic: bool=False, kvm: bool=False):
	boot_wait    = 10 if kvm else 30
	reboot_wait  = 5 if kvm else 10
	install_wait = 40 if kvm else 120

	log(f'Installing TinkerOS on {cwdrel(disk)}')
	qemu, _ = qemu_run(disk, iso, graphic, kvm)

	# Can't be bothered to figure out a nicer way to do this :')
	log(f'  - Waiting for boot ({boot_wait}s unconditionally)')
	sleep(boot_wait)

	log('  - Answering prompts')
	qemu_send_as_keys(qemu, 'y')   # install? y
	qemu_send_as_keys(qemu, 'y')   # automated partitioning and install? y
	qemu_send_as_keys(qemu, '1\n') # how many copies? 1
	qemu_send_as_keys(qemu, '0\n') # select graphics mode (640x480 w/ patches)
	qemu_send_as_keys(qemu, 'n')   # install extras? n
	qemu_send_as_keys(qemu, '\n')  # confirm

	# Can't be bothered to figure out a nicer way to do this :')
	log(f'  - Waiting for install ({install_wait}s unconditionally)')
	sleep(install_wait)

	log('  - Rebooting')
	qemu_send_as_keys(qemu, 'y') # reboot now? y
	sleep(reboot_wait)

	log('  - Should be done')
	qemu.stdin.write(b'quit\n')
	qemu.stdin.flush()
	assert qemu.wait() == 0


def run_vm_once(disk: Path, iso: Optional[Path]=None, graphic: bool=False, kvm: bool=False):
	qemu, com1_fifo = qemu_run(disk, iso, graphic, kvm)
	qemu_sync_with_serial_and_quit(qemu, com1_fifo)


def patch_bootloader(disk: Path):
	log('Patching TempleOS bootloader to autoselect disk 1')
	data = bytearray(disk.read_bytes())

	# Patch bootloader code to skip asking which disk to use.
	# xor ah, ah; int 0x16; push ax
	idx = data.find(bytes.fromhex('32e4 cd16 50'))
	if idx == -1:
		sys.exit('Failed: bootloader instruction sequence not found')

	# xor ah, ah; mov al, 0x31; push ax
	patch = bytes.fromhex('32e4 b031 50')
	data[idx:idx + len(patch)] = patch
	disk.write_bytes(data)


def copy_files_recursive(vmfs: FS, root: Path, cur: Path=None):
	if cur is None:
		assert root.is_dir()
		cur = root

	if cur.is_dir():
		for path in cur.iterdir():
			copy_files_recursive(vmfs, root, path)
	else:
		assert cur.is_file()

		dst = Path('/') / cur.relative_to(root)
		log(f'  - Copying {cwdrel(cur)} -> {dst}')

		# Remove first as simply doing a direct .writebytes() over an existing
		# file can break the filesystem (buggy implementation? Or maybe I'm
		# smoking and it's TempleOS messing up the FS... whatever)
		if vmfs.exists(dst.as_posix()):
			vmfs.remove(dst.as_posix())

		# Also remove eventual Z/non-Z alias
		ext = dst.suffix
		alt = dst.with_name(dst.stem) if ext == '.Z' else dst.with_suffix(ext + '.Z')
		if vmfs.exists(alt.as_posix()):
			vmfs.remove(alt.as_posix())

		# Create parent dirs as needed and add file
		vmfs.makedirs(dst.parent.as_posix(), recreate=True)
		vmfs.writebytes(dst.as_posix(), cur.read_bytes())


def main(args):
	global NOPROGRESS

	args = parse_args()
	NOPROGRESS = args.quiet

	mydir        = Path(__file__).parent
	outdir       = mydir / 'build'
	files        = mydir / 'files'
	tinkeros_iso = outdir / 'TinkerOS_5.13.ISO'
	chall_iso    = outdir / 'installer.iso'

	# We work with raw imgs to be able to patch the bootloader, but the final
	# disk is going to be QCOW2
	tmp_disk                 = outdir / 'tmp.img'
	chall_disk               = outdir / 'disk.img'
	chall_disk_release_qcow2 = outdir / 'disk.qcow2'
	chall_disk_players_qcow2 = outdir / 'disk-players.qcow2'

	outdir.mkdir(exist_ok=True)

	# Install TinkerOS into a temprary disk to bootstrap next steps
	if not tmp_disk.is_file() or not args.skip_setup:
		get_tinkeros_iso(tinkeros_iso)
		create_disk(tmp_disk, '64M')
		run_vm_install_os(tmp_disk, tinkeros_iso, args.display, args.kvm)
		patch_bootloader(tmp_disk)

	# Add our files to the disk
	with fs.open_fs(f'fat://{tmp_disk}?offset={512 * 63}') as vmfs:
		log('Copying install files to temporary disk')
		copy_files_recursive(vmfs, files)

	# Build custom installer ISO
	log('Running VM to build distro installer ISO')
	run_vm_once(tmp_disk, graphic=args.display, kvm=args.kvm)

	# Extract ISO from temporary disk
	with fs.open_fs(f'fat://{tmp_disk}?offset={512 * 63}') as vmfs:
		chall_iso.write_bytes(vmfs.readbytes('/Distro.ISO.C'))
		chall_iso.chmod(0o644)

	# Use distro installer ISO to install distro on final disk and patch
	# bootloader to select disk 1 automatically
	create_disk(chall_disk, '16M')
	log('Running VM to install distro on final disk')
	run_vm_once(chall_disk, chall_iso, args.display, args.kvm)
	patch_bootloader(chall_disk)

	# Create final QCOW2 disk with real flag
	convert_disk(chall_disk, chall_disk_release_qcow2, 'raw', 'qcow2')
	print('Release disk ready at', str(cwdrel(chall_disk_release_qcow2)))

	# Create final QCOW2 disk with redacted flag
	replace_flag_in_raw_disk(chall_disk)
	convert_disk(chall_disk, chall_disk_players_qcow2, 'raw', 'qcow2')
	print('Players\' disk ready at', str(cwdrel(chall_disk_players_qcow2)))


if __name__ == '__main__':
	main(sys.argv[1:])
