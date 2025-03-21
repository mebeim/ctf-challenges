#!/usr/bin/env python3
#
# @mebeim - 2025-03-15
#

from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64


cs = Cs(CS_ARCH_X86, CS_MODE_64)

# Look for gadgets within a signed 16-bit offset of the switch jump base addr
# (qemu) memsave 0x36773d3d 0x10000 dump.bin
code = Path('mem.bin').read_bytes()
base = 0x36773d46
res = []

for off in range(len(code)):
	insns = [x for x,_ in zip(cs.disasm(code[off:], base), range(10))]
	if not insns:
		continue

	asm = '; '.join((f'{i.mnemonic} {i.op_str}' for i in insns[:10]))
	res.append((asm, base + off))

res.sort()
for asm, addr in res:
	print(f'0x{addr:x}: {asm}')
