# Copyright 2020-2026 Vector 35 Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Query the Windows API calls extracted from a TTD trace.

A report is produced by the external extractor (``ttdcapa-extract -b out.ttdb``) and is
memory-mapped rather than parsed, so opening one is effectively free no matter how many
calls it holds.

    >>> from debugger.ttdbehavior import TTDBehaviorReport
    >>> with TTDBehaviorReport("NetacLockFile01.ttdb") as report:
    ...     print(report.call_count)
    ...     for call in report.query("module:kernel32 api:WriteFile ret:!0"):
    ...         print(call.position, call.api, call.param_summary)

``query`` filters entirely inside the core, returning the matching row indices in a
single crossing of the FFI; rows are then decoded only as you touch them. Iterating a
whole multi-million-call report one call at a time from Python is possible but is the
slow way round -- narrow with a query first.

Calls come back with their parameters decoded. On a query matching millions of rows that
is worth turning off with ``with_params=False``, which leaves ``param_summary`` but skips
building the structured list.

``extract`` produces a report from a trace, which requires Windows -- see its docstring.
"""

import ctypes
import os
import subprocess
from dataclasses import dataclass, field
from typing import Callable, Iterator, List, Optional, Sequence

import binaryninja
from binaryninja.settings import Settings

from . import _debuggercore as dbgcore

__all__ = [
	"TTDBehaviorReport",
	"TTDApiCall",
	"TTDApiCallParam",
	"extract",
	"extractor_path",
	"ttd_replay_directory",
]


@dataclass
class TTDApiCallParam:
	"""One decoded parameter. Which fields are meaningful depends on what the Win32
	metadata knew about the parameter."""

	name: str = ""
	type: str = ""
	kind: str = ""
	value: int = 0
	string: str = ""
	flags: List[str] = field(default_factory=list)
	data: bytes = b""
	#: The buffer's real length when ``data`` is only a prefix, else 0.
	data_total: int = 0
	deref: Optional[int] = None
	out: bool = False
	#: The value was re-read at the call's return position, which is what makes an
	#: [Out] parameter renderable at all.
	at_return: bool = False

	@property
	def truncated(self) -> bool:
		return self.data_total > len(self.data)


@dataclass
class TTDApiCall:
	"""One Windows API call observed during the trace."""

	index: int = 0
	tid: int = 0
	position_sequence: int = 0
	position_steps: int = 0
	module: str = ""
	api: str = ""
	ret: int = 0
	#: The instruction after the CALL, i.e. the call site -- which tells you whether the
	#: sample made this call itself or something made it on the sample's behalf.
	return_address: int = 0
	param_summary: str = ""
	#: True when a real signature backed the parameters, rather than the four-register
	#: heuristic fallback.
	decoded: bool = False
	params: List[TTDApiCallParam] = field(default_factory=list)

	@property
	def position(self) -> str:
		"""The TTD position, in the ``Sequence:Steps`` form WinDbg and the debugger use."""
		return "%X:%X" % (self.position_sequence, self.position_steps)

	def __repr__(self) -> str:
		return "<TTDApiCall %s %s!%s(%s) -> 0x%x>" % (
			self.position, self.module, self.api, self.param_summary, self.ret)


class TTDBehaviorReport:
	"""A memory-mapped report of the API calls in a TTD trace."""

	def __init__(self, path: str):
		error = ctypes.c_char_p()
		handle = dbgcore.BNTTDBehaviorOpenReport(path, ctypes.byref(error))
		if not handle:
			message = dbgcore.pyNativeStr(error.value) if error.value else "unknown error"
			if error.value:
				dbgcore.BNDebuggerFreeString(error)
			raise IOError("cannot open %s: %s" % (path, message))
		self.handle = handle
		self.path = path

	def __del__(self):
		self.close()

	def __enter__(self) -> "TTDBehaviorReport":
		return self

	def __exit__(self, exc_type, exc_value, traceback) -> None:
		self.close()

	def close(self) -> None:
		handle = getattr(self, "handle", None)
		if handle:
			dbgcore.BNTTDBehaviorCloseReport(handle)
			self.handle = None

	def __len__(self) -> int:
		return self.call_count

	def __getitem__(self, index: int) -> TTDApiCall:
		call = self.get_call(index)
		if call is None:
			raise IndexError(index)
		return call

	def __iter__(self) -> Iterator[TTDApiCall]:
		for index in range(self.call_count):
			call = self.get_call(index)
			if call is not None:
				yield call

	def __repr__(self) -> str:
		return "<TTDBehaviorReport %s: %d calls, %s>" % (self.path, self.call_count, self.architecture)

	@property
	def call_count(self) -> int:
		return dbgcore.BNTTDBehaviorGetCallCount(self.handle)

	@property
	def decoded_count(self) -> int:
		"""Calls whose parameters came from a real signature rather than the heuristic."""
		return dbgcore.BNTTDBehaviorGetDecodedCount(self.handle)

	@property
	def pid(self) -> int:
		return dbgcore.BNTTDBehaviorGetProcessId(self.handle)

	@property
	def trace_path(self) -> str:
		return dbgcore.BNTTDBehaviorGetTracePath(self.handle) or ""

	@property
	def architecture(self) -> str:
		"""``"x86"`` or ``"x64"``, from the traced process rather than the host."""
		return dbgcore.BNTTDBehaviorGetArchitecture(self.handle) or ""

	def query_indices(self, query: str) -> List[int]:
		"""Row indices matching ``query``, evaluated in one crossing of the FFI.

		The filter runs entirely in the core, so this costs about what filtering in
		native code costs -- the boundary is not in the loop.
		"""
		count = ctypes.c_ulonglong()
		result = dbgcore.BNTTDBehaviorRunQuery(self.handle, query, ctypes.byref(count))
		if not result:
			return []
		try:
			return [int(result[i]) for i in range(count.value)]
		finally:
			dbgcore.BNTTDBehaviorFreeQueryResult(result)

	def query(self, query: str, with_params: bool = True) -> Iterator[TTDApiCall]:
		"""Calls matching ``query``, decoded lazily as you iterate.

		Terms are ANDed; a bare word matches anywhere including buffer contents, and
		``field:value`` narrows::

		    module:kernel32 api:WriteFile     only kernel32's, not ntdll's
		    api:Reg* ret:!0                   registry calls that failed
		    retaddr:0x400000-0x500000         calls the sample made itself
		    tid:4 "c:\\\\windows"               thread 4, mentioning that path

		Numeric fields (``tid``, ``ret``, ``retaddr``) take ``!=``, ``>``, ``>=``,
		``<``, ``<=`` and ``a-b`` ranges, decimal or ``0x`` hex.

		Each call arrives with its full parameter list. Pass ``with_params=False`` to skip
		that when you only need ``param_summary`` -- it is about 4x cheaper per call and
		holds far less memory, which starts to matter once a query matches millions of
		rows rather than hundreds.
		"""
		for index in self.query_indices(query):
			call = self.get_call(index, with_params)
			if call is not None:
				yield call

	def get_call(self, index: int, with_params: bool = True) -> Optional[TTDApiCall]:
		raw = dbgcore.BNTTDApiCall()
		if not dbgcore.BNTTDBehaviorGetCall(self.handle, index, with_params, ctypes.byref(raw)):
			return None
		try:
			call = TTDApiCall(
				index=raw.m_seq,
				tid=raw.m_tid,
				position_sequence=raw.m_positionSequence,
				position_steps=raw.m_positionSteps,
				module=raw.m_module,
				api=raw.m_api,
				ret=raw.m_ret,
				return_address=raw.m_returnAddress,
				param_summary=raw.m_paramSummary,
				decoded=raw.m_decoded,
			)
			for i in range(raw.m_paramCount):
				call.params.append(self._convert_param(raw.m_params[i]))
			return call
		finally:
			dbgcore.BNTTDBehaviorFreeCall(ctypes.byref(raw))

	@staticmethod
	def _convert_param(raw) -> TTDApiCallParam:
		param = TTDApiCallParam(
			name=raw.m_name,
			type=raw.m_type,
			kind=raw.m_kind,
			value=raw.m_value,
			string=raw.m_str,
			data_total=raw.m_bytesTotal,
			deref=raw.m_deref if raw.m_hasDeref else None,
			out=raw.m_out,
			at_return=raw.m_atReturn,
		)
		for f in range(raw.m_flagCount):
			param.flags.append(dbgcore.pyNativeStr(raw.m_flags[f]))
		if raw.m_byteCount:
			param.data = bytes(bytearray(raw.m_bytes[i] for i in range(raw.m_byteCount)))
		return param


_EXTRACTOR_SETTING = "debugger.ttdBehaviorExtractorPath"
_MAX_BUFFER_SETTING = "debugger.ttdBehaviorMaxBuffer"


def _setting(key: str, getter: str):
	"""A setting's value, or None if the debugger did not register it.

	The TTD settings only exist on Windows, so reading them unguarded would raise on the
	platforms where extraction is unavailable anyway.
	"""
	settings = Settings()
	if not settings.contains(key):
		return None
	return getattr(settings, getter)(key)


def _plugin_root() -> str:
	return (
		binaryninja.user_plugin_path()
		if os.environ.get("BN_STANDALONE_DEBUGGER") is not None
		else binaryninja.bundled_plugin_path()
	)


def extractor_path() -> Optional[str]:
	"""The extractor the debugger would run, or None if there is not one.

	A path configured in ``debugger.ttdBehaviorExtractorPath`` wins outright, so someone
	running their own build always gets it; a configured path that is not a file raises
	rather than quietly falling back, since reporting results from a different binary than
	you think you are running is worse than failing.
	"""
	configured = _setting(_EXTRACTOR_SETTING, "get_string")
	if configured:
		if os.path.isfile(configured):
			return configured
		raise RuntimeError(
			"%s is set to %r, which is not a file. Clear the setting to use the extractor "
			"shipped with the debugger." % (_EXTRACTOR_SETTING, configured))

	bundled = os.path.join(_plugin_root(), "ttd-extract", "ttdcapa-extract.exe")
	return bundled if os.path.isfile(bundled) else None


def ttd_replay_directory() -> Optional[str]:
	"""Where ``TTDReplay.dll`` lives, or None if it cannot be found.

	Those DLLs are Microsoft's and ship with WinDbg rather than with us, so the extractor
	is pointed at them instead of carrying copies. None is not fatal: the extractor then
	falls back to the ordinary DLL search order.
	"""
	def has_replay(directory: Optional[str]) -> bool:
		return bool(directory) and os.path.isfile(os.path.join(directory, "TTDReplay.dll"))

	# A configured DbgEng path is authoritative: if it is set and wrong, fall through to
	# the extractor's own search rather than silently using a different engine.
	configured = _setting("debugger.x64dbgEngPath", "get_string")
	if configured:
		path = os.path.join(configured, "TTD")
		return path if has_replay(path) else None

	bundled = os.path.join(_plugin_root(), "dbgeng", "amd64", "TTD")
	return bundled if has_replay(bundled) else None


def extract(
	trace: str,
	output: Optional[str] = None,
	*,
	extractor: Optional[str] = None,
	ttd_dlls: Optional[str] = None,
	max_buffer: Optional[int] = None,
	progress: Optional[Callable[[str, float, int], bool]] = None,
) -> TTDBehaviorReport:
	"""Sweep a TTD trace for the Windows API calls it made and open the resulting report.

	**Windows only.** The sweep replays the trace through Microsoft's TTD engine, which
	exists nowhere else. Reading a report has no such restriction, so one produced here
	opens on any platform.

	    >>> from debugger.ttdbehavior import extract
	    >>> report = extract(r"C:\\traces\\sample.run")
	    >>> print(report.call_count)

	The report is written beside the trace as ``<trace>.ttdb`` unless ``output`` says
	otherwise. An existing file at that path is overwritten.

	``progress`` is called as ``progress(phase, percent, calls)``, where ``phase`` is
	``"sweep"`` or ``"write"``. It fires a few times a second during the sweep, and once
	when each phase begins -- writing the report is a large part of the wall clock but
	reports no percentage of its own, so that transition is the only notice of it.
	Returning False cancels: the extractor stops replaying and writes what it has, so a
	cancelled run still yields a complete, valid report of a shorter prefix of the trace.

	    >>> def show(phase, percent, calls):
	    ...     print(f"{phase} {percent}% {calls} calls")
	    ...     return calls < 1_000_000        # stop once we have a million
	    >>> report = extract("sample.run", progress=show)

	``extractor``, ``ttd_dlls`` and ``max_buffer`` default to the same values the sidebar
	uses -- respectively ``debugger.ttdBehaviorExtractorPath`` or the bundled copy, the
	replay DLLs beside the configured DbgEng, and ``debugger.ttdBehaviorMaxBuffer``.

	Raises RuntimeError if no extractor can be found or the sweep fails, and IOError if
	the trace does not exist.
	"""
	trace = os.path.abspath(trace)
	if not os.path.isfile(trace):
		raise IOError("no such trace: %s" % trace)

	output = os.path.abspath(output if output else os.path.splitext(trace)[0] + ".ttdb")

	if extractor is None:
		extractor = extractor_path()
	if extractor is None:
		raise RuntimeError(
			"no TTD behavior extractor found. It ships with the debugger on Windows; on "
			"other platforms reports can be opened but not produced. Set %s to point at a "
			"build of your own." % _EXTRACTOR_SETTING)
	if not os.path.isfile(extractor):
		raise RuntimeError("not a TTD behavior extractor: %s" % extractor)

	command = [extractor, trace, "-b", output, "--progress"]

	if ttd_dlls is None:
		ttd_dlls = ttd_replay_directory()
	if ttd_dlls:
		command += ["--ttd-dlls", ttd_dlls]

	if max_buffer is None:
		max_buffer = _setting(_MAX_BUFFER_SETTING, "get_integer")
	if max_buffer is not None:
		command += ["--max-buffer", str(int(max_buffer))]

	if progress is not None:
		command.append("--cancel-on-stdin")

	process = subprocess.Popen(
		command,
		stdin=subprocess.PIPE if progress is not None else subprocess.DEVNULL,
		stdout=subprocess.DEVNULL,
		stderr=subprocess.PIPE,
		text=True,
		bufsize=1,
		# Otherwise a script flashes up a console window on every call.
		creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
	)

	phase = "sweep"
	percent = 0.0
	calls = 0
	cancelled = False
	# Only the tail is kept: a failing run can be chatty, and the last lines are the ones
	# that say why.
	tail: List[str] = []

	def report_progress() -> None:
		nonlocal cancelled
		if progress is None or cancelled:
			return
		if progress(phase, percent, calls) is not False:
			return
		cancelled = True
		try:
			process.stdin.write("cancel\n")
			process.stdin.flush()
		except OSError:
			pass  # already gone; the sweep is ending anyway

	for line in process.stderr:
		line = line.strip()
		if not line:
			continue

		if line.startswith("[phase]"):
			parts = line.split(None, 1)
			if len(parts) > 1:
				phase = parts[1]
				# Announced rather than waited on: the extractor only emits [progress]
				# during the sweep, so without this a caller would never learn that
				# writing had started, and writing is a large part of the wall clock.
				report_progress()
			continue

		if line.startswith("[progress]"):
			parts = line.split()
			try:
				# The percentage is fractional, e.g. "[progress] 5.10 160".
				percent, calls = float(parts[1]), int(parts[2])
			except (IndexError, ValueError):
				continue
			report_progress()
			continue

		tail.append(line)
		del tail[:-20]

	process.wait()
	if process.stdin:
		process.stdin.close()

	if process.returncode != 0:
		raise RuntimeError(
			"extraction failed (exit %d):\n%s" % (process.returncode, "\n".join(tail)))

	return TTDBehaviorReport(output)


def modules(report: TTDBehaviorReport) -> Sequence[str]:
	"""Every distinct module seen in the report, in first-call order.

	Convenience for the common "what did this touch?" question; walks the whole report,
	so narrow with a query first if you only care about part of it.
	"""
	seen = []
	known = set()
	for call in report:
		if call.module not in known:
			known.add(call.module)
			seen.append(call.module)
	return seen
