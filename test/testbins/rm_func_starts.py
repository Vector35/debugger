#!/usr/bin/env python3

# remove mach-o function starts by setting the size of the LUT in the load command to size 0
# offs+0: cmd (0x26 == LC_FUNCTION_STARTS)
# offs+4: cmdsize (0x10)
# offs+8: LUT offset
# offs+C: LUT size                        <---- HERE

import sys
from struct import unpack

data = None
with open(sys.argv[1], 'rb') as fp:
	data = fp.read()

assert data[0:4] == b'\xCF\xFA\xED\xFE'
assert data[4:8] == b'\x07\x00\x00\x01' # CPU_TYPE_X86_X64
ncmds = unpack('<I', data[16:20])[0]
offs_cmd_func_starts = None
offs = 0x20
found = False
for i in range(ncmds):
	(cmd, cmdsize) = unpack('<II', data[offs:offs+8])
	if cmd == 0x26: # LC_FUNCTION_STARTS
		found = True
		break
	offs += cmdsize
assert found

# set LUT size to 0
data = data[0:offs+12] + b'\x00\x00\x00\x00' + data[offs+16:]
with open(sys.argv[1], 'wb') as fp:
	fp.write(data)
