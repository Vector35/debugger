#!/usr/bin/env python3
"""One line per distinct race that involves the debugger's own code: the first frame of ours on each side."""
import glob, re, sys, collections
fn = re.compile(r'BinaryNinjaDebugger::((?:[A-Za-z_~0-9]+::)*[A-Za-z_~0-9]+)\(?')
loc = re.compile(r'(?:core|api)/([\w/.]+:\d+)')
counts = collections.Counter()
only = sys.argv[2] if len(sys.argv) > 2 else ''
for path in glob.glob(sys.argv[1] + '*'):
    for rep in open(path, errors='replace').read().split('==================')[1:]:
        if 'ThreadSanitizer: data race' not in rep:
            continue
        blocks = re.split(r'\n\n', rep)
        sides = []
        for b in blocks:
            if not re.match(r'\s*(Previous )?(Read|Write|Atomic)', b):
                continue
            head = b.strip().splitlines()[0]
            kind = re.match(r'\s*(?:Previous )?([A-Za-z ]*?) of size', b).group(1).strip().lower()
            frame = ''
            for line in b.splitlines():
                m = fn.search(line)
                if m and not m.group(1).startswith(('PtraceEngine::Event', 'basic_string')) and 'std::' not in m.group(1):
                    l = loc.search(line)
                    frame = m.group(1) + (' @' + l.group(1) if l else '')
                    break
            sides.append(f'{kind} {frame or "(not ours)"}')
        if len(sides) < 2 or all('(not ours)' in s for s in sides[:2]):
            continue
        key = ' <-> '.join(sorted(sides[:2]))
        if only and only not in key:
            continue
        counts[key] += 1
for k, n in counts.most_common(40):
    print(f'{n:4d}  {k}')
