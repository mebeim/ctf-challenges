#!/usr/bin/env python3
#
# @mebeim - 2024-09-16
#

import sys

from re import compile
from subprocess import check_output


STP_EXP = compile(r'stp\s+x29,\s*x30,\s*\[sp, #-(\d+)\]!')
EXPECTED_FRAME_SIZE = {
	'bdecode'           : 32,
	'bdecode_integer'   : 80,
	'bdecode_list'      : 32,
	'bdecode_dictionary': 32,
	'bdecode_key_value' : 16,
}
EXPECTED_PAC_PROTECTED = (
	'main',
	'bdecode',
	'bdecode_line',
	'bdecode_integer',
	'bdecode_string',
	'bdecode_list',
	'bdecode_dictionary',
	'bdecode_key_value',
	'die',
)


if len(sys.argv) != 2:
	sys.exit(f'Usage: {sys.argv[0]} EXECUTABLE')

disasm = check_output(('aarch64-linux-gnu-objdump', '-d', sys.argv[1]), text=True).splitlines()

for i, line in enumerate(disasm):
	for func, expected_sz in EXPECTED_FRAME_SIZE.items():
		if f'<{func}>:' in line:
			m = STP_EXP.search(disasm[i + 2])
			assert m is not None, 'Could not find STP for stack frame setup'

			sz = int(m.group(1))
			assert sz == expected_sz, f'Unexpected frame size for {func}: expected {expected_sz}, have {sz}'

	for func in EXPECTED_PAC_PROTECTED:
		if f'<{func}>:' in line:
			assert 'paciasp' in disasm[i + 1], f'Function {func} is not PAC protected'
