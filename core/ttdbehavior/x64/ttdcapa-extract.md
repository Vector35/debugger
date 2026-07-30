# `ttdcapa-extract`

Sweeps a Time Travel Debugging trace and records every Windows API call it made: when it
happened, which function was called, what its arguments were, and what it returned.
Arguments are decoded against Microsoft's Win32 API metadata where a signature exists, so
parameters come back named and typed rather than as four guessed registers.

It writes either of two things, or both:

- **`-o report.json`** -- the JSON report [capa](https://github.com/mandiant/capa) consumes.
- **`-b report.ttdb`** -- a compact binary layout meant to be memory-mapped and browsed.
  On a 3.4M-call trace it takes 3.6s to write against ~56s for the JSON, and loading it is
  a memory map rather than a 17s parse. The format is specified [below](#the-ttdb-format).

## Usage

```
ttdcapa-extract <trace.run> [-o <out.json>] [-b <out.ttdb>] [options]
ttdcapa-extract --dump-sig <ApiName>
```

### Output

| Option | Effect |
| --- | --- |
| `-o`, `--output <path>` | write the JSON report |
| `-b`, `--binary <path>` | write the binary report |
| `--sample <path>` | hash this file and record its MD5/SHA1/SHA256 in the report |

Giving neither `-o` nor `-b` sweeps the trace and writes nothing, which is only useful for
timing.

### Finding the replay engine

| Option | Effect |
| --- | --- |
| `--ttd-dlls <dir>` | where `TTDReplay.dll` and `TTDReplayCPU.dll` live |

Those DLLs are Microsoft's, shipped with WinDbg, and are not redistributed with this tool.
Point at the copy WinDbg already installed -- normally its `amd64	td` folder:

```powershell
Join-Path (Get-AppxPackage Microsoft.WinDbg).InstallLocation 'amd64	td'
```

Without the flag the usual DLL search order applies, so copies placed beside the
executable work too. `TTDReplay.dll` is delay-loaded, which is what lets the location be
chosen at runtime; a missing engine is reported rather than crashing the process.

### Argument decoding

| Option | Effect |
| --- | --- |
| `--win32-index <path>` | use a specific `win32-index.bin` instead of the one beside the executable |
| `--no-metadata` | ignore the metadata entirely and use the register/stack heuristic everywhere |
| `--with-stack-args` | for calls with *no* signature, also grab four stack slots past the register arguments. Calls that have a signature always capture their true arity regardless |
| `--max-buffer N` | bytes to keep from any one captured buffer (default 65536). Buffers cut short at this limit carry their real length, so a consumer can tell a short buffer from a truncated one |
| `--max-calls N` | stop recording after N calls (default 0, unlimited). The sweep still runs to the end |
| `--dump-sig <ApiName>` | print one function's decoded signature and exit. Needs only the metadata index, not a trace or the replay DLLs, which makes it a good smoke test |

### Driving it from another program

| Option | Effect |
| --- | --- |
| `--progress` | emit progress on stderr |
| `--cancel-on-stdin` | stop the sweep when a line reading `cancel` arrives on stdin |

`--progress` writes `[phase] sweep` and `[phase] write` markers and, during the sweep,
`[progress] <percent> <calls>` a few times a second. The phases matter because the sweep is
only part of the wall clock: on a 3.4M-call trace it takes about 30s while serialising the
report takes comparable time, so a caller tracking only the sweep would sit at 100% looking
wedged. Percentages are clamped to be non-decreasing, since positions read from different
threads are not perfectly ordered.

`--cancel-on-stdin` interrupts the replay and then writes the report as usual: everything
recorded up to that point is kept, so a cancelled run yields a complete, valid report of a
shorter prefix of the trace.

## Notes on what the data can and cannot tell you

**A missing string argument is not evidence the argument was null.** The sweep reads guest
memory through the `IThreadView` the replay engine hands to a callback, and the SDK fixes
those reads to `QueryMemoryPolicy::ThreadLocal` -- a fast lookup explicitly allowed to
ignore memory observed by other threads or by this thread at another time. It returns
nothing for roughly a quarter of string parameters even though the data is in the trace;
reading the same address at the same position through a cursor returns the whole string.
The parameter's raw pointer value is still recorded, and is usually valid.

**Calls without a signature have guessed arguments.** Coverage is the public Windows SDK,
so `ntdll` internals and CRT helpers fall back to capturing argument registers (x64) or
stack slots (x86). Their values are positional, unnamed, and the count is a guess. The
binary format flags these per call.

## The `.ttdb` format

Designed to be **memory-mapped and read in place**: nothing is parsed on open and nothing
is allocated per call, so opening a 3.4-million-call report costs a header validation. The
reference implementations are `ttd/src/binreport.cpp` (writer) and, in the Binary Ninja
debugger, `core/ttdbehavior.cpp` (reader).

Format version 2. All integers are **little-endian**. All *file offsets* are byte offsets
from the start of the file, so a mapped view needs no fixups; *region offsets* (into the
string table or the blob) are relative to that region's start, and are noted as such.

### Layout

```
+----------------------------+ 0
| header                     | 128 bytes
+----------------------------+ callsOff
| call records               | callCount * 48 bytes, in sweep order
+----------------------------+ paramsOff
| parameter records          | variable length, referenced by call records
+----------------------------+ stringsOff
| string table               | stringsSize bytes, NUL-terminated UTF-8
+----------------------------+ blobOff
| blob                       | blobSize bytes: search text, strings, buffers
+----------------------------+ end of file
```

The split exists because the three kinds of data have different access patterns. Call
records are fixed size so row *N* is a multiply. The string table is deduplicated, which is
where the compression really comes from -- a trace has millions of calls but only thousands
of distinct module and function names, so every name in a 3.4M-call report fits in about
100 KB. Everything variable-length and unique to one call goes in the blob.

### Header (128 bytes)

| Offset | Type | Field | Notes |
| ---: | --- | --- | --- |
| 0 | `char[8]` | magic | `TTDBEHV1` |
| 8 | `u32` | version | 2 |
| 12 | `u32` | arch | 0 = x64, 1 = x86 |
| 16 | `u64` | callCount | number of call records |
| 24 | `u64` | paramBytes | size in bytes of the parameter region |
| 32 | `u64` | pid | process id of the traced process |
| 40 | `u64` | callsOff | file offset of the call records |
| 48 | `u64` | paramsOff | file offset of the parameter records |
| 56 | `u64` | stringsOff | file offset of the string table |
| 64 | `u64` | stringsSize | size in bytes of the string table |
| 72 | `u64` | blobOff | file offset of the blob |
| 80 | `u64` | blobSize | size in bytes of the blob |
| 88 | `u64` | decodedCount | calls whose parameters came from a real signature |
| 96 | `u64` | maxSeq | highest sequence number, i.e. `callCount - 1` |
| 104 | `u32` | tracePathStr | string-table offset of the source `.run` path |
| 108 | `u32` | sampleNameStr | string-table offset of the main module's name |
| 112 | `u32` | maxPositionChars | widest rendered position, for column sizing |
| 116 | | *(reserved)* | zero |

`arch` describes the **traced process**, taken from the main module's PE format, not the
machine that recorded the trace. A reader should reject a file whose magic does not match,
whose version it does not know, or whose regions do not fit inside the file.

### Call record (48 bytes)

| Offset | Type | Field | Notes |
| ---: | --- | --- | --- |
| 0 | `u64` | ret | the call's return value |
| 8 | `u32` | tid | TTD unique thread id |
| 12 | `u32` | positionSequence | TTD position, sequence part |
| 16 | `u32` | positionSteps | TTD position, steps part |
| 20 | `u32` | moduleStr | string-table offset of the module name, e.g. `kernel32` |
| 24 | `u32` | apiStr | string-table offset of the function name, e.g. `CreateFileW` |
| 28 | `u32` | paramOff | offset into the parameter region; 0 when there are none |
| 32 | `u32` | searchOff | offset into the blob of this call's search text |
| 36 | `u16` | paramCount | low 15 bits; bit 15 (`0x8000`) set means *decoded* |
| 38 | `u16` | searchLen | length in bytes of the search text |
| 40 | `u64` | returnAddress | the instruction after the CALL, i.e. the call site |

**There is no sequence number field.** Recorded calls are numbered densely from zero in
sweep order, so a record's index *is* its sequence number.

**Position** is conventionally rendered `%X:%X` of sequence and steps -- `45905:15A5` --
which is the form WinDbg and the Binary Ninja debugger accept for time travel.

**`returnAddress`** identifies the caller, which is how you distinguish a call the sample
made itself from one a system DLL made on its behalf.

**The decoded bit** matters for interpreting the parameters. When set, the extractor had a
real signature for the function from Microsoft's Win32 metadata, so the parameters have
correct arity, names, and types. When clear, it fell back to capturing argument registers
(x64) or stack slots (x86) heuristically: the values are positional, unnamed, and the count
is a guess. A decoded call may legitimately have zero parameters, which is why the flag is
separate from the count.

### Parameter record (variable length)

Parameters for one call are stored consecutively starting at `paramsOff + paramOff`, and
are decoded in sequence -- there is no index, so reading parameter *k* means walking the
*k* before it. That is deliberate: a viewer only decodes parameters for rows a user
actually looks at.

Fixed part, 18 bytes:

| Offset | Type | Field |
| ---: | --- | --- |
| 0 | `u8` | kind |
| 1 | `u8` | bits |
| 2 | `u32` | nameStr (string-table offset; 0 when unnamed) |
| 6 | `u32` | typeStr (string-table offset; 0 when untyped) |
| 10 | `u64` | value (the raw register or stack value) |

Then, in this order, only the parts whose bit is set in `bits`:

| Bit | Name | Adds |
| ---: | --- | --- |
| 0x01 | Out | *(nothing; marks an `[Out]` parameter)* |
| 0x02 | AtReturn | *(nothing; value was re-read at the call's return)* |
| 0x04 | HasDeref | `u64` deref -- the pointed-to value |
| 0x08 | HasStr | `u32` strOff, `u32` strLen -- blob offset and length |
| 0x10 | HasBytes | `u32` bytesOff, `u32` bytesLen, `u64` bytesTotal |
| 0x20 | HasFlags | `u32` flagsOff, `u32` flagsLen -- `|`-joined names in the blob |

So a parameter's size is 18 bytes plus 8 for HasDeref, 8 for HasStr, 16 for HasBytes and 8
for HasFlags, in that order.

**`bytesTotal`** is the buffer's real length when only a prefix was captured (the capture
limit defaults to 64 KiB); `bytesLen` is what is actually in the file. `bytesTotal >
bytesLen` means truncated.

**`AtReturn`** marks values re-read at the call's return position rather than at the call.
This is what makes `[Out]` parameters renderable at all -- at the moment of the call they
have not been written yet -- and it is the one thing a time-travel trace gives you that a
live debugger cannot easily.

### Parameter kinds

`kind` is an index into this list. It describes how the value should be interpreted, not
its C type, which is in `typeStr`.

| # | Name | Meaning |
| ---: | --- | --- |
| 0 | *(unknown)* | unclassified, or a heuristic capture with no signature |
| 1 | `int` | plain scalar |
| 2 | `bool` | |
| 3 | `handle` | opaque, pointer-sized, never dereferenced |
| 4 | `enum` | scalar with a symbolic value table; see HasFlags |
| 5 | `float` | |
| 6 | `double` | |
| 7 | `str` | `char*`, NUL-terminated |
| 8 | `wstr` | `wchar_t*`, NUL-terminated |
| 9 | `strbuf` | `char[]`, length from a sibling parameter |
| 10 | `wstrbuf` | `wchar_t[]` |
| 11 | `buf` | `void*`/byte array |
| 12 | `int*` | pointer to a scalar; see HasDeref |
| 13 | `struct*` | pointer to a struct or union, not expanded |
| 14 | `fnptr` | |
| 15 | `guid` | pointer to a 16-byte GUID, rendered into HasStr |
| 16 | `ptr` | opaque pointer |
| 17 | `str*` | `char**`, an out-parameter receiving an allocated string |
| 18 | `wstr*` | `wchar_t**` |

### String table

A run of NUL-terminated UTF-8 strings, deduplicated. A string-table offset is relative to
`stringsOff`. **Offset 0 is the empty string**, so 0 doubles as "absent".

Only repeated text lives here: module names, function names, parameter names, parameter
type names.

### Blob

Raw bytes, referenced by `(offset, length)` pairs relative to `blobOff`. It holds three
things, interleaved in whatever order the writer emitted them:

- **Search text**, one per call, referenced by `searchOff`/`searchLen`. This is a
  lowercased rendering of `module!api` followed by each parameter as it would be displayed,
  including printable runs extracted from captured buffers. It exists so a text filter is a
  substring scan over mapped pages with nothing to build first.
- **Parameter strings**, referenced by HasStr.
- **Captured buffer contents**, referenced by HasBytes. Raw bytes, not hex.

### Reading a report

Validate the magic and version, check the regions fit in the file, and map it. Then:

- **Row *N***: read 48 bytes at `callsOff + N * 48`.
- **Its module and function**: NUL-terminated strings at `stringsOff + moduleStr` and
  `stringsOff + apiStr`.
- **Its parameters**: walk `paramCount & 0x7FFF` records from `paramsOff + paramOff`,
  decoding each per the bits.
- **Filtering**: for a text match, `memmem` the needle in the `searchLen` bytes at
  `blobOff + searchOff`. For a match on module or function, resolve the name against the
  string table once to a set of offsets, then compare `moduleStr`/`apiStr` as integers --
  that is far cheaper than a string search, which is why scoped queries are faster than
  plain text ones.
