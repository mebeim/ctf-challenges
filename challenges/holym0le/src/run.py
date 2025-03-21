#!/usr/bin/env python3
#
# See `./run.py --help` for usage.
#
# You can technically also run this outside Docker with no problem (given that
# you have qemu-system-x86_64 and the modules in requirements.txt installed). In
# fact, some of the command line options only make sense outside Docker.
#

import argparse
import os
import sys
from ctypes import CDLL, c_int, c_ulong
from pathlib import Path
from signal import SIGTERM
from time import sleep


libc = CDLL('libc.so.6')
libc.prctl.argtypes = [c_int, c_ulong]
libc.prctl.restype = c_int
PR_SET_PDEATHSIG = 1


def parse_args() -> argparse.Namespace:
	ap = argparse.ArgumentParser()

	ap.add_argument('disk', metavar='disk.qcow2')
	ap.add_argument('--display', action='store_true',
		help='show VM display (let QEMU open a new window, '
			'does not work in Docker!)')
	ap.add_argument('--kvm', action='store_true',
		help='enable KVM for faster emulation (does not work in Docker!)')
	ap.add_argument('--gdb', action='store_true',
		help='enable QEMU GDB server on port 1338')
	ap.add_argument('--vnc', action='store_true',
		help='enable QEMU VNC server for the VM display on port 5900')
	ap.add_argument('--monitor', action='store_true',
		help='do not connect to the VM automatically after launching it: '
			'instead, redirect QEMU monitor to stdio')

	return ap.parse_args()


def launch_vm(disk: Path, flag: str, args: argparse.Namespace):
	assert disk.suffix == '.qcow2'

	# Make a raw copy to preserve original
	new_disk = Path('/tmp/holym0le-tmp-disk.qcow2')
	new_disk.write_bytes(disk.read_bytes())

	argv = [
		'qemu-system-x86_64',
		'-smp', 'cores=1',
		'-cpu', 'qemu64,-svm',
		'-m', '1G',
		'-rtc', 'base=localtime',
		'-drive', 'format=qcow2,file=' + str(new_disk),
		'-serial', 'tcp::1337,server=on'
	]

	if not args.display:
		argv += ['-display', 'none']
	if args.kvm:
		argv += ['-enable-kvm']
	if args.gdb:
		argv += ['-gdb', 'tcp::1338']
	if args.vnc:
		argv += ['-vnc', ':0'] # 0 means 5900+0
	if args.monitor:
		argv += ['-monitor', 'stdio']

	# Make sure QEMU stops when the parent (this script) dies
	libc.prctl(PR_SET_PDEATHSIG, SIGTERM)
	os.execvp(argv[0], argv)


def talk_to_vm():
	# Connect to VM serial and redirect to stdin/stdout
	sys.stderr.close()
	os.execlp('socat', 'socat', 'TCP:localhost:1337', 'STDIO')


def main():
	args = parse_args()

	disk = Path(args.disk)
	if not disk.is_file():
		sys.exit(f'Disk not found or not a file: {disk}')

	flag = os.getenv('FLAG', 'ptm{Dummy_test_flag}')

	if os.fork() == 0:
		launch_vm(disk, flag, args)
		sys.exit(0)

	if not args.monitor:
		sleep(3) # foolproof method to wait for child exec
		talk_to_vm()
		sys.exit(0)

	print('[*] Connect to localhost on port 1337 to start QEMU')
	if args.gdb:
		print('[*] GDB server also available on port 1338')
	if args.vnc:
		print('[*] VNC server also available on port 5900')

	try:
		os.wait()
	except KeyboardInterrupt:
		print('[-] Goodbye!')


if __name__ == '__main__':
	main()
