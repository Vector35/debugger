#!/usr/bin/env python3
"""Print only the ThreadSanitizer reports that involve the debugger's own code (BinaryNinjaDebugger / ptrace)."""
import glob, re, sys, collections
pat = re.compile(r'BinaryNinjaDebugger|Ptrace|DebuggerController|DebuggerState|debuggercore')
seen = collections.OrderedDict()
for path in glob.glob(sys.argv[1] + '*'):
    text = open(path, errors='replace').read()
    for rep in text.split('==================')[1:]:
        if 'WARNING: ThreadSanitizer' not in rep or not pat.search(rep):
            continue
        kind = re.search(r'WARNING: ThreadSanitizer: ([^(\n]*)', rep).group(1).strip()
        frames = [l.strip() for l in rep.splitlines() if re.match(r'\s+#[0-3] ', l)]
        key = kind + '|' + '|'.join(re.sub(r'\(.*', '', f)[:120] for f in frames[:6])
        seen.setdefault(key, rep)
print(len(seen), 'distinct reports involving our code')
for k, rep in seen.items():
    print('=' * 70); print(rep[:3500])
