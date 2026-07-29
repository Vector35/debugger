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
"""

import ctypes
from dataclasses import dataclass, field
from typing import Iterator, List, Optional, Sequence

from . import _debuggercore as dbgcore


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

	def query(self, query: str, with_params: bool = False) -> Iterator[TTDApiCall]:
		"""Calls matching ``query``, decoded lazily as you iterate.

		Terms are ANDed; a bare word matches anywhere including buffer contents, and
		``field:value`` narrows::

		    module:kernel32 api:WriteFile     only kernel32's, not ntdll's
		    api:Reg* ret:!0                   registry calls that failed
		    retaddr:0x400000-0x500000         calls the sample made itself
		    tid:4 "c:\\\\windows"               thread 4, mentioning that path

		Numeric fields (``tid``, ``ret``, ``retaddr``) take ``!=``, ``>``, ``>=``,
		``<``, ``<=`` and ``a-b`` ranges, decimal or ``0x`` hex.

		Pass ``with_params`` to decode each call's full parameter list; leaving it off
		is markedly cheaper when you only need the summary.
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
