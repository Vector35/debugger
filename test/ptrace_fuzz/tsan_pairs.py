#!/usr/bin/env python3
"""Distinct data races that involve the debugger's code, as 'access @ file:line <-> access @ file:line' with counts.

usage: tsan_pairs.py /tmp/tsan/log [substring-filter]
"""
import collections, glob, re, sys

frame = re.compile(r'#\d+ (.*?) (/\S*?/((?:core|api)/\S+?:\d+))')
counts = collections.Counter()
only = sys.argv[2] if len(sys.argv) > 2 else ''
for path in glob.glob(sys.argv[1] + '*'):
    for rep in open(path, errors='replace').read().split('=================='):
        if 'ThreadSanitizer: data race' not in rep:
            continue
        sides = []
        for block in rep.split('\n\n'):
            m = re.search(r'^\s*(?:Previous )?([Rr]ead|[Ww]rite|[Aa]tomic \w+) of size', block, re.M)
            if not m:
                continue
            where = '(not ours)'
            for line in block.splitlines():
                f = frame.search(line)
                if f and 'BinaryNinjaDebugger::' in f.group(1) and not f.group(1).startswith('std::'):
                    name = re.sub(r'\(.*', '', f.group(1)).replace('BinaryNinjaDebugger::', '')
                    where = f'{name} @ {f.group(3)}'
                    break
            sides.append(f'{m.group(1).split()[0].lower()} {where}')
        if len(sides) < 2 or all('(not ours)' in s for s in sides[:2]):
            continue
        key = ' <-> '.join(sorted(sides[:2]))
        if only in key:
            counts[key] += 1
for key, n in counts.most_common(60):
    print(f'{n:5d}  {key}')
