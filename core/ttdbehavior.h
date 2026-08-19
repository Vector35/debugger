/*
Copyright 2020-2026 Vector 35 Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#pragma once

// Reader and query engine for the Windows API calls extracted from a TTD trace.
//
// The report is written by an external extractor in a compact layout designed to be
// memory-mapped and read in place -- see ttd-capa's ttd/src/binreport.hpp for the format.
// Nothing is parsed on open and nothing is allocated per call: a 3.4M-call report costs
// a header validation instead of the ~17s and ~1.4GB that parsing the equivalent JSON
// did. Records are decoded out of the mapping only when something asks for a row.
//
// This lives in core rather than the UI so that queries are available over the FFI, and
// therefore from Python. The boundary is drawn so that no loop over the call list ever
// crosses it: RunQuery evaluates the whole filter here and hands back matching row
// indices in one call, which measures within noise of doing it in-process, where
// crossing per row costs 30-50%.

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace BinaryNinjaDebugger {

	// One decoded parameter of an API call. Which fields are meaningful depends on what
	// the Win32 metadata said about the parameter; `has*` flags say which.
	struct TTDApiCallParam
	{
		std::string name;
		std::string type;
		std::string kind;
		uint64_t value = 0;
		std::string str;                // resolved ANSI/UTF-16 string
		std::vector<std::string> flags; // symbolic names for enum/flag parameters
		std::vector<uint8_t> bytes;     // captured buffer contents, possibly a prefix
		uint64_t bytesTotal = 0;        // real length when `bytes` was capped, else 0
		uint64_t deref = 0;             // pointee, for int*-like parameters
		bool hasDeref = false;
		bool out = false;
		bool atReturn = false;          // re-read at the call's return position
	};


	struct TTDApiCall
	{
		uint64_t seq = 0;
		uint64_t tid = 0;
		uint64_t positionSequence = 0;
		uint64_t positionSteps = 0;
		std::string module;
		std::string api;
		uint64_t ret = 0;
		uint64_t returnAddress = 0;  // the instruction after the CALL, i.e. the call site
		std::vector<TTDApiCallParam> params;
		bool decoded = false;        // a real signature backed this call's parameters
		std::string paramSummary;    // single-line rendering, for a table cell
	};


	// A parsed filter expression: whitespace-separated terms, ANDed. A bare word (or
	// "quoted phrase") matches anywhere in a call's searchable text; `field:value`
	// narrows to one field.
	//
	//   module:kernel32 api:WriteFile     only kernel32's, not ntdll's
	//   api:Reg* ret:!0                   registry calls that failed
	//   retaddr:0x400000-0x500000         calls the sample made itself
	//
	// module and api resolve against the report's deduplicated string table once per
	// query, so evaluating them per row is an integer compare rather than a search.
	class TTDBehaviorQuery
	{
	public:
		struct Numeric
		{
			enum Op { Equal, NotEqual, Greater, GreaterEqual, Less, LessEqual, Range };
			Op op = Equal;
			uint64_t a = 0;
			uint64_t b = 0;
			bool Test(uint64_t value) const;
		};

		enum class Field { Text, Module, Api, Tid, Ret, RetAddr };

		struct Term
		{
			Field field = Field::Text;
			std::string text;
			bool prefix = false;
			Numeric numeric;
			std::vector<uint32_t> stringOffsets;
		};

		// Never fails: anything that does not look like a field term is treated as text,
		// so a half-typed query narrows rather than erroring.
		void Parse(const std::string& text);
		bool IsEmpty() const { return m_terms.empty(); }
		const std::vector<Term>& GetTerms() const { return m_terms; }
		std::vector<Term>& GetTerms() { return m_terms; }

	private:
		std::vector<Term> m_terms;
	};


	class TTDBehaviorReport
	{
	public:
		TTDBehaviorReport() = default;
		~TTDBehaviorReport();
		TTDBehaviorReport(const TTDBehaviorReport&) = delete;
		TTDBehaviorReport& operator=(const TTDBehaviorReport&) = delete;

		// Maps the report at `path`. Returns false with `error` set; the object is left
		// closed and safe to destroy.
		bool Open(const std::string& path, std::string& error);
		void Close();
		bool IsOpen() const { return m_map != nullptr; }

		const std::string& GetPath() const { return m_path; }
		const std::string& GetTracePath() const { return m_tracePath; }
		const std::string& GetArchitecture() const { return m_arch; }
		uint64_t GetProcessId() const { return m_pid; }
		uint64_t GetCallCount() const { return m_callCount; }
		uint64_t GetDecodedCount() const { return m_decodedCount; }
		uint64_t GetMaxSequence() const { return m_maxSeq; }
		uint32_t GetMaxPositionChars() const { return m_maxPositionChars; }

		// Decode one call. `withParams` is the expensive half, so a table can skip it and
		// only a detail view asks for it.
		bool GetCall(uint64_t index, TTDApiCall& out, bool withParams) const;

		// Evaluate `query` over every call and return the matching row indices. One call
		// does the whole filter, which is what keeps this affordable across the FFI.
		std::vector<uint64_t> RunQuery(const std::string& query) const;

		// Same, for a query already parsed and resolved against this report.
		std::vector<uint64_t> RunQuery(TTDBehaviorQuery& query) const;

		// Bind a query's module/api terms to this report's string table.
		void ResolveQuery(TTDBehaviorQuery& query) const;

		bool Matches(uint64_t index, const TTDBehaviorQuery& query) const;

	private:
		const uint8_t* CallRecord(uint64_t index) const;
		std::string MappedString(uint32_t offset) const;
		void ForEachString(const std::function<void(uint32_t, const char*, size_t)>& fn) const;

		std::string m_path;
		std::string m_tracePath;
		std::string m_arch;

		// Platform handles for the mapping, opaque here to keep windows.h out of the
		// header.
		void* m_fileHandle = nullptr;
		void* m_mappingHandle = nullptr;
		const uint8_t* m_map = nullptr;
		uint64_t m_mapSize = 0;

		uint64_t m_callCount = 0;
		uint64_t m_decodedCount = 0;
		uint64_t m_maxSeq = 0;
		uint64_t m_pid = 0;
		uint32_t m_maxPositionChars = 0;
		uint64_t m_callsOff = 0;
		uint64_t m_paramsOff = 0;
		uint64_t m_stringsOff = 0;
		uint64_t m_stringsSize = 0;
		uint64_t m_blobOff = 0;
		uint64_t m_blobSize = 0;
	};

}  // namespace BinaryNinjaDebugger
