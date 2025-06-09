#!/usr/bin/env python3
#
# @mebeim - 2024-09-18
#

import sys
from base64 import b64decode
from os import getenv, urandom
from pathlib import Path
from random import SystemRandom
# from string import ascii_lowercase
from subprocess import Popen, check_output, CalledProcessError, TimeoutExpired
from subprocess import PIPE, DEVNULL
from tempfile import NamedTemporaryFile
from textwrap import dedent
from time import time


N_ROUNDS      = 32
ROUND_TIMEOUT = 10
TOTAL_TIMEOUT = int(getenv('TIMEOUT', 60))
MAX_EXE_SIZE  = 4 << 20
TMP_PREFIX    = '/tmp/jailguesser.'


class RandNSJailConfig:
	def __init__(self) -> None:
		self.seed = urandom(16)
		self.rng  = SystemRandom(self.seed)

		self.base = dedent('''\
			name: "jailguesser"
			mode: ONCE
			daemon: false
			keep_env: false
			cwd: "/jail"
			keep_caps: false
			disable_no_new_privs: false
			forward_signals: true
			max_cpus: 1
			time_limit: 0
			''')

		self._hostname      : str|None = None
		# self._env           : str|None = None
		self._idmaps        : str|None = None
		# self._rlimits       : str|None = None
		self._personality   : str|None = None
		self._mounts        : str|None = None
		self._seccomp       : str|None = None

	def __sample_list(self, lst: list) -> list:
		return self.rng.sample(lst, self.rng.randrange(len(lst) + 1))
	#
	# The original version of the challenge also had this, but it was removed
	# to shorten solve time.
	# def __rand_str(self, maxlen=128) -> str:
	# 	return ''.join(self.rng.choices(ascii_lowercase, k=self.rng.randrange(1, maxlen + 1)))

	@property
	def hostname(self) -> str:
		if self._hostname is None:
			self._hostname = f'hostname: "ecsc-2024-{self.rng.randbytes(8).hex()}"'
		return self._hostname
	#
	# The original version of the challenge also had this, but it was removed
	# to shorten solve time.
	#
	# @property
	# def env(self) -> str:
	# 	if self._env is not None:
	# 		return self._env
	#
	# 	vars = ['FLAG=ECSC{LOL_U_WISH}']
	# 	for _ in range(self.rng.randrange(16 + 1)):
	# 		vars.append(f'{self.__rand_str(32).upper()}={self.__rand_str(64)}')
	#
	# 	self.rng.shuffle(vars)
	# 	self._env = '\n'.join(f'envar: "{v}"' for v in vars)
	# 	return self._env

	@property
	def idmaps(self) -> str:
		if self._idmaps is not None:
			return self._idmaps

		uid = 69420 + self.rng.randrange(1337)
		gid = 69420 + self.rng.randrange(1337)
		self._idmaps = f'uidmap: {{ inside_id: "{uid}" outside_id: "65534" }}\n'
		self._idmaps += f'gidmap: {{ inside_id: "{gid}" outside_id: "65534" }}'
		return self._idmaps
	#
	# The original version of the challenge also had this, but it was removed
	# to shorten solve time.
	#
	# @property
	# def rlimits(self) -> str:
	# 	if self._rlimits is not None:
	# 		return self._rlimits
	#
	# 	self._rlimits = f'rlimit_fsize: {self.rng.randrange(1, 5)}\n'
	# 	self._rlimits += f'rlimit_nofile: {self.rng.randrange(8, 17)}'
	# 	return self._rlimits

	@property
	def personality(self) -> str:
		if self._personality is not None:
			return self._personality

		enabled_bits = self.__sample_list([
			'persona_addr_compat_layout',
			'persona_addr_no_randomize',
		])

		enabled_bits.sort()
		self._personality = '\n'.join(f'{bit}: true' for bit in enabled_bits)
		return self._personality

	@property
	def mounts(self) -> str:
		if self._mounts is not None:
			return self._mounts

		mounts = [
			'mount_proc: false',
			'mount { src: "/lib" dst: "/lib" is_bind: true nosuid: true rw: false mandatory: true }',
			'mount { src: "/lib64" dst: "/lib64" is_bind: true nosuid: true rw: false mandatory: true }',
			'mount { dst: "/jail" fstype: "tmpfs" rw: true is_bind: false noexec: false nodev: true nosuid: true options: "size=8388608" }'
		]
		#
		# The original version of the challenge also had this, but it was
		# removed to shorten solve time.
		#
		# paths: set[str] = set()
		# for _ in range(self.rng.randrange(16 + 1)):
		# 	paths.add(f'/tmp/{self.__rand_str(32)}')
		#
		# for path in sorted(paths):
		# 	rw = self.rng.choice(['true', 'false'])
		# 	size = self.rng.randrange(1, 10) << 12
		# 	mounts.append(
		# 		f'mount {{ dst: "{path}" fstype: "tmpfs" rw: {rw} '
		# 		'is_bind: false noexec: true nodev: true nosuid: true '
		# 		f'options: "size={size}" }}'
		# 	)

		self._mounts = '\n'.join(mounts)
		return self._mounts

	@property
	def seccomp(self) -> str:
		if self._seccomp is not None:
			return self._seccomp

		base_allow = [
			'open', 'openat', 'close', 'close_range',
			'access', 'fcntl', 'ioctl',
			'dup', 'dup2', 'pipe',
			'newstat', 'newfstat', 'newfstatat',
			'readlink', 'readlinkat',
			'chdir', 'fchdir', 'getcwd',
			'waitid', 'wait4',
			'brk', 'mmap', 'mprotect', 'munmap', 'mremap',
			'set_tid_address', 'set_robust_list',
			'rt_sigaction', 'rt_sigreturn', 'rt_sigprocmask', 'rt_sigtimedwait',
			'futex', 'getrandom', 'arch_prctl', 'rseq', 'newuname',
			'execve', 'exit', 'exit_group',
			'clone { (clone_flags & CLONE_THREAD) == CLONE_THREAD }'
		]

		rw_alternatives = [
			('read', 'readv', 'vmsplice', 'io_setup, io_destroy, io_submit, io_getevents, io_cancel'),
			('write', 'writev', 'io_setup, io_destroy, io_submit, io_getevents, io_cancel')
		]
		#
		# The original version of the challenge also had this, but it was
		# removed to shorten solve time.
		#
		# misc_alternatives = [
		# 	('getdents', 'getdents64'),
		# 	('statfs', 'fstatfs'),
		# 	('getuid', 'geteuid', 'getresuid'),
		# 	('getgid', 'getegid', 'getresgid')
		# ]

		optional = [
			'flock', 'getcpu', 'gettid', 'gettimeofday', 'kill', 'mkdir',
			'mlock', 'nanosleep', 'rmdir', 'sched_yield', 'tgkill',
			'truncate', 'unlink', 'unlinkat'
		]

		alt_allow = []

		for alts in rw_alternatives:
			alt = self.rng.choice(alts)
			if 'io_' in alt:
				alt_allow = [alt]
				break
			else:
				alt_allow.append(alt)
		#
		# The original version of the challenge also had this, but it was
		# removed to shorten solve time.
		#
		# for alts in misc_alternatives:
		# 	alt = self.rng.choice(alts)
		# 	if alt not in alt_allow:
		# 		alt_allow.append(alt)

		opt_allow = []
		opt_errno = []
		opt_trap = []
		opt_kill = []

		for sc in optional:
			match self.rng.randrange(4):
				case 0: opt_allow.append(sc)
				case 1: opt_errno.append(f'ERRNO({self.rng.randrange(150, 4096)}) {{ {sc} }}')
				case 2: opt_trap.append(f'TRAP({self.rng.randrange(150, 4096)}) {{ {sc} }}')
				case 3: opt_kill.append(sc)

		policy = [
			'#define rseq 334',
			'#define close_range 436',
			'#define CLONE_THREAD 0x10000',
			'DEFAULT ERRNO(38)',
			f'ALLOW {{ {", ".join(base_allow + alt_allow + opt_allow)} }}'
		]

		if opt_errno:
			policy.append(' '.join(opt_errno))
		if opt_trap:
			policy.append(' '.join(opt_trap))
		if opt_kill:
			policy.append(f'KILL {{ {", ".join(opt_kill)} }}')

		self._seccomp = '\n'.join(f'seccomp_string: "{p}"' for p in policy)
		return self._seccomp

	def __repr__(self) -> str:
		return f'<{self.__class__.__name__} with seed={self.seed.hex()!r}>'

	def __str__(self) -> str:
		return (
			self.base
			+ self.hostname       + '\n' * bool(self.hostname)
			# + self.env            + '\n' * bool(self.env)
			+ self.idmaps         + '\n' * bool(self.idmaps)
			# + self.rlimits        + '\n' * bool(self.rlimits)
			+ self.personality    + '\n' * bool(self.personality)
			+ self.mounts         + '\n' * bool(self.mounts)
			+ self.seccomp        + '\n' * bool(self.seccomp)
		)


def expiring_tempfile(mode: str, lifetime: int, delete: bool=True):
	suffix = f'.{int(time()) + lifetime}'
	return NamedTemporaryFile(mode, prefix=TMP_PREFIX, suffix=suffix, delete=delete)


def recv_exe() -> Path|None:
	print('Give me your Base64-encoded solution.')
	print('Input "EOF" on an empty line when done.', flush=True)

	line = input().strip()
	b64data = ''

	while line != 'EOF':
		b64data += line
		if len(b64data) > MAX_EXE_SIZE * 4 / 3:
			print('Too large!')
			return None

		line = input().strip()

	try:
		data = b64decode(b64data)
	except:
		print('Invalid Base64 data!')
		return None

	exe_tempfile = expiring_tempfile('wb', TOTAL_TIMEOUT, False)
	exe_tempfile.write(data)
	exe_tempfile.close()
	return Path(exe_tempfile.name)


def run_in_jail(exe: Path, cfg: Path, input_: str) -> str|None:
	exe.chmod(0o555)

	### Hint: use sys.stderr instead for debugging purposes
	stderr_file = DEVNULL

	p = Popen((
		'nsjail',
		### Hint: remove this option for debugging purposes
		'--really_quiet',
		'--config', cfg,
		'--bindmount_ro', f'{exe}:/jail/exe',
		'--',
		'/jail/exe'
	), text=True, stdin=PIPE, stdout=PIPE, stderr=stderr_file, bufsize=1 << 20)

	try:
		out, _ = p.communicate(input_, timeout=ROUND_TIMEOUT)
	except TimeoutExpired:
		p.kill()
		return None

	if p.returncode != 0:
		print('>', p.returncode, file=sys.stderr)
		return None
	return out


def print_diff(a: str, b: str) -> None:
	with expiring_tempfile('w', ROUND_TIMEOUT) as fa:
		with expiring_tempfile('w', ROUND_TIMEOUT) as fb:
			fa.write(a)
			fa.flush()
			fb.write(b)
			fb.flush()

			try:
				diff = check_output(f'diff -u "{fa.name}" "{fb.name}" || true',
					shell=True, text=True)
				print(diff, end='')
			except CalledProcessError:
				print('<failed to diff>')


def round(i: int, exe: Path) -> bool:
	print(f'Round {i}/{N_ROUNDS}... ', end='',flush=True)

	with expiring_tempfile('w', ROUND_TIMEOUT) as cfg_tempfile:
		cfg = RandNSJailConfig()
		cfg_str = str(cfg)
		cfg_tempfile.write(cfg_str)
		cfg_tempfile.flush()

		n_bytes = int.from_bytes(urandom(2), 'little')
		rand_input = urandom(n_bytes // 2).hex() + '\n'

		out = run_in_jail(exe, Path(cfg_tempfile.name), rand_input)
		if out is None:
			print('FAIL: does this thing even work?')
			return False

		if not out:
			print('FAIL: you better speak up!')
			return False

		if len(out) > (1 << 20):
			print('FAIL: you talk too much!')
			return False

		if not out.startswith(rand_input):
			print("FAIL: that's not what I said!")
			return False

		out = out[len(rand_input):].strip()
		expected = cfg_str.strip()

		if out != expected:
			print('FAIL: bad guess!')
			print('-' * 80)
			print_diff(out, expected)
			return False

		print('OK!')
		return True

def main() -> int:
	exe = recv_exe()
	if exe is None:
		return 1

	try:
		for i in range(1, N_ROUNDS + 1):
			if not round(i, exe):
				print('-' * 80)
				print('You lost! Improve your guessing abilities and retry.')
				return 1

		print('-' * 80)
		print("You won! Here's your prize:", getenv('FLAG'))
		return 0
	finally:
		exe.unlink()


if __name__ == '__main__':
	sys.exit(main())
