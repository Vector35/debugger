#!/usr/bin/env python

import os
import platform

exceptions = ['clear.py']

print('clearing all executable tests, regardless of OS')

executables = []
for fname in os.listdir('.'):
	if fname in exceptions:
		continue
	if fname.endswith('.exe'):
		executables.append(fname)
	elif fname.endswith('.obj'):
		executables.append(fname)
	elif fname.endswith('.pdb'):
		executables.append(fname)
	elif fname.endswith('.o'):
		executables.append(fname)
	elif platform.system() != 'Windows' and os.access(os.path.join(fname), os.X_OK):
		executables.append(fname)

print('plan to delete:\n%s\n\nhit any key to continue, ctrl+c to cancel' % '\n'.join(executables))
input()

for exe in executables:
	print('deleting %s' % exe)
	os.remove(exe)
