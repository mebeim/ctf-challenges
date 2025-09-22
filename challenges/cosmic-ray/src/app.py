#!/usr/bin/env pypy3
#
# @mebeim - 2025-07-26
#

import os
import re


LAMBDAS = {}
LAMBDA_SRCS = {}
COSMIC_RAY_HIT = False

OPS = {
	'ADD'    : lambda expr, v: f'({expr}) + {v}',
	'SUB'    : lambda expr, v: f'({expr}) - {v}',
	'MUL'    : lambda expr, v: f'({expr}) * {v}',
	'DIV'    : lambda expr, v: f'({expr}) // {v}',
	'TRUEDIV': lambda expr, v: f'({expr}) / {v}',
	'BOOL'   : lambda expr: f'bool({expr})',
	'INT'    : lambda expr: f'int({expr})',
	'LIST'   : lambda expr: f'list({expr})',
	'INDEX'  : lambda expr, i: f'({expr})[{i}]',
	'SLICE'  : lambda expr, i, j: f'({expr})[{i}:{j}]',
	'REPEAT' : lambda expr, n: f'(({expr}) for _ in range({n}))',
	'CALL'   : lambda expr, f: f'LAMBDAS[{f!r}]({expr})',
}


def build_lambda():
	name = input('Name: ')

	if not name.isalpha() or not name.islower():
		raise ValueError('Invalid function name')

	if name in LAMBDAS:
		raise ValueError(f'Function {name!r} already defined')

	print('Input one operation per line, end with "END":')
	expr = 'x'

	while 1:
		raw_op = input('> ')
		if not raw_op:
			continue

		op, *args = raw_op.split()

		if op == 'END':
			break

		fn = OPS.get(op, None)
		if fn is None:
			print('Invalid operation')
			continue

		nargs = fn.__code__.co_argcount - 1
		if len(args) != nargs:
			print(f'Invalid number of arguments for {op!r}, expected {nargs}, got {len(args)}')
			continue

		if op == 'CALL':
			if args[0] not in LAMBDAS:
				print(f'Function {args[0]!r} is not defined')
				continue
		else:
			try:
				args = list(int(a, 0) for a in args)
			except ValueError:
				print(f'Invalid argument for {op!r}')
				continue

		expr = fn(expr, *args)

	body = f'lambda x: {expr}'
	LAMBDAS[name] = eval(body)
	LAMBDA_SRCS[name] = re.sub(r"LAMBDAS\['(\w+)'\]", r'\1', body)
	print('Function created!')


def list_lambdas():
	if not LAMBDA_SRCS:
		print('No functions defined')
		return

	print('Currently defined functions:')

	for name, body in sorted(LAMBDA_SRCS.items()):
		print(f'\t{name} = {body}')


def call_lambda():
	if not LAMBDAS:
		print('No functions defined')
		return

	name = input('Name: ')
	fn = LAMBDAS.get(name)
	if fn is None:
		raise ValueError(f'Function {name!r} is not defined')

	arg = input('Argument: ')

	try:
		arg = int(arg, 0)
	except ValueError:
		raise ValueError('Invalid argument')

	try:
		res = fn(arg)
	except Exception as e:
		print(f'ERR: Call failed ({e.__class__.__name__})')
	else:
		print('Result:', repr(res))


def cosmic_ray():
	global COSMIC_RAY_HIT

	if COSMIC_RAY_HIT:
		print('Cosmic ray already hit. What are the odds of that happening TWICE in the same run???')
		return

	try:
		where = int(input('Where? '), 0)
	except ValueError:
		raise ValueError('Invalid input') from None

	offset = where // 8
	bit = where % 8
	vaddr = None

	with open('/proc/self/maps', 'r') as f:
		for line in f:
			parts = line.split()

			prot = parts[1]
			if 'w' not in prot:
				continue

			ino = int(parts[4])
			if ino != 0:
				continue

			if 'stack' in parts[-1]:
				continue

			start, end = (int(v, 16) for v in parts[0].split('-'))
			size = end - start
			if offset >= size:
				print(f'Cosmic ray spares {size:#x} bytes...')
				offset -= size
				continue

			vaddr = start + offset
			break
		else:
			raise ValueError('Invalid position')

	from cffi import FFI
	FFI().cast("unsigned char *", vaddr)[0] ^= (1 << bit)

	COSMIC_RAY_HIT = True
	print('Cosmic ray hit RAM!')


def main():
	os.environ['PYTHONUNBUFFERED'] = '1'

	print('''\
Available commands:
	[B]uild a function
	[C]all a function
	[L]ist functions
	[T]rigger a cosmic ray
''')

	while 1:
		cmd = input('> ').strip()

		try:
			if cmd == 'B':
				build_lambda()
			elif cmd == 'C':
				call_lambda()
			elif cmd == 'L':
				list_lambdas()
			elif cmd == 'T':
				cosmic_ray()
			else:
				print('Invalid command')
		except ValueError as e:
			print('ERR:', str(e))

		print()


if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt:
		os._exit(0)
	except:
		print('FATAL: Unexpected exception')
		os._exit(1)
