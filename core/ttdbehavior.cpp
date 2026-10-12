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

#include "ttdbehavior.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <string_view>

#ifdef WIN32
	#ifndef WIN32_LEAN_AND_MEAN
		#define WIN32_LEAN_AND_MEAN
	#endif
	#include <windows.h>
#else
	#include <fcntl.h>
	#include <sys/mman.h>
	#include <sys/stat.h>
	#include <unistd.h>
#endif

using namespace BinaryNinjaDebugger;

namespace {
	// Mirrors ttd-capa's ttd/src/binreport.hpp. Any change there needs one here.
	constexpr char kMagic[8] = { 'T', 'T', 'D', 'B', 'E', 'H', 'V', '1' };
	constexpr uint32_t kVersion = 2;  // 2 added returnAddress to the call record
	constexpr uint64_t kHeaderSize = 128;
	constexpr uint64_t kCallRecordSize = 48;
	constexpr uint16_t kDecodedFlag = 0x8000;

	enum ParamBits : uint8_t
	{
		ParamOut = 0x01,
		ParamAtReturn = 0x02,
		ParamHasDeref = 0x04,
		ParamHasStr = 0x08,
		ParamHasBytes = 0x10,
		ParamHasFlags = 0x20,
	};

	// The extractor writes the parameter kind as a raw byte; these are the display names,
	// indexed by that value. Order matches win32meta.hpp's ArgKind.
	const char* const kKindNames[] = { "", "int", "bool", "handle", "enum", "float", "double", "str",
		"wstr", "strbuf", "wstrbuf", "buf", "int*", "struct*", "fnptr", "guid", "ptr", "str*", "wstr*" };

	template <typename T>
	T Read(const uint8_t* p)
	{
		T v {};
		std::memcpy(&v, p, sizeof(T));
		return v;
	}

	std::string ToLower(std::string s)
	{
		std::transform(s.begin(), s.end(), s.begin(),
			[](unsigned char c) { return static_cast<char>(std::tolower(c)); });
		return s;
	}

	std::string FormatHex(uint64_t value)
	{
		char buf[32];
		std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(value));
		return buf;
	}


	// Bytes a table cell can show before it stops being a glance.
	constexpr size_t kMaxPreviewBytes = 32;

	std::string PreviewBytes(const std::vector<uint8_t>& bytes)
	{
		static const char* digits = "0123456789abcdef";
		// Not std::min: windows.h defines a min macro and this file includes it.
		size_t shown = bytes.size() < kMaxPreviewBytes ? bytes.size() : kMaxPreviewBytes;
		std::string out;
		out.reserve(shown * 3 + 4);
		for (size_t i = 0; i < shown; ++i)
		{
			if (i != 0)
				out.push_back(' ');
			out.push_back(digits[bytes[i] >> 4]);
			out.push_back(digits[bytes[i] & 0x0f]);
		}
		if (bytes.size() > shown)
			out += " \xe2\x80\xa6";  // ellipsis
		return out;
	}

	// Decimal, or hex when prefixed with 0x.
	bool ParseNumber(const std::string& text, uint64_t& out)
	{
		if (text.empty())
			return false;
		try
		{
			size_t consumed = 0;
			bool hex = text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X');
			out = std::stoull(hex ? text.substr(2) : text, &consumed, hex ? 16 : 10);
			return consumed == (hex ? text.size() - 2 : text.size());
		}
		catch (...)
		{
			return false;
		}
	}

	// `!0`, `>0x1000`, `>=5`, `<10`, `<=10`, `0x400000-0x500000`, or a plain value.
	bool ParseNumeric(const std::string& text, TTDBehaviorQuery::Numeric& out)
	{
		std::string value = text;
		if (value.rfind("!", 0) == 0)
		{
			out.op = TTDBehaviorQuery::Numeric::NotEqual;
			value = value.substr(1);
		}
		else if (value.rfind(">=", 0) == 0)
		{
			out.op = TTDBehaviorQuery::Numeric::GreaterEqual;
			value = value.substr(2);
		}
		else if (value.rfind("<=", 0) == 0)
		{
			out.op = TTDBehaviorQuery::Numeric::LessEqual;
			value = value.substr(2);
		}
		else if (value.rfind(">", 0) == 0)
		{
			out.op = TTDBehaviorQuery::Numeric::Greater;
			value = value.substr(1);
		}
		else if (value.rfind("<", 0) == 0)
		{
			out.op = TTDBehaviorQuery::Numeric::Less;
			value = value.substr(1);
		}
		else
		{
			// A '-' separating two numbers is a range. Searched past any 0x so the hex
			// digits of a lone value are not mistaken for one.
			size_t from = (value.size() > 2 && value[0] == '0' && (value[1] == 'x' || value[1] == 'X')) ? 2 : 1;
			size_t dash = value.find('-', from);
			if (dash != std::string::npos)
			{
				if (!ParseNumber(value.substr(0, dash), out.a) || !ParseNumber(value.substr(dash + 1), out.b))
					return false;
				out.op = TTDBehaviorQuery::Numeric::Range;
				return true;
			}
		}
		return ParseNumber(value, out.a);
	}

	// Split on whitespace, honouring double quotes so a phrase can contain spaces.
	std::vector<std::string> SplitTerms(const std::string& text)
	{
		std::vector<std::string> terms;
		std::string current;
		bool inQuotes = false;
		for (char c : text)
		{
			if (c == '"')
				inQuotes = !inQuotes;
			else if (std::isspace(static_cast<unsigned char>(c)) && !inQuotes)
			{
				if (!current.empty())
					terms.push_back(current);
				current.clear();
			}
			else
				current += c;
		}
		if (!current.empty())
			terms.push_back(current);
		return terms;
	}
}  // namespace


bool TTDBehaviorQuery::Numeric::Test(uint64_t value) const
{
	switch (op)
	{
	case NotEqual:
		return value != a;
	case Greater:
		return value > a;
	case GreaterEqual:
		return value >= a;
	case Less:
		return value < a;
	case LessEqual:
		return value <= a;
	case Range:
		return value >= a && value <= b;
	case Equal:
	default:
		return value == a;
	}
}


void TTDBehaviorQuery::Parse(const std::string& text)
{
	m_terms.clear();
	for (const std::string& raw : SplitTerms(text))
	{
		Term term;
		size_t colon = raw.find(':');
		std::string field = colon != std::string::npos && colon > 0 ? ToLower(raw.substr(0, colon)) : std::string();
		std::string value = colon != std::string::npos && colon > 0 ? raw.substr(colon + 1) : raw;

		// An unknown prefix is not an error: "c:\windows" should search for that text,
		// not complain about a field called "c".
		bool numericField = false;
		if (field == "module" || field == "mod")
			term.field = Field::Module;
		else if (field == "api" || field == "func" || field == "function")
			term.field = Field::Api;
		else if (field == "tid" || field == "thread")
		{
			term.field = Field::Tid;
			numericField = true;
		}
		else if (field == "ret" || field == "return")
		{
			term.field = Field::Ret;
			numericField = true;
		}
		else if (field == "retaddr" || field == "caller" || field == "from")
		{
			term.field = Field::RetAddr;
			numericField = true;
		}
		else
		{
			term.field = Field::Text;
			value = raw;
		}

		if (numericField)
		{
			if (!ParseNumeric(value, term.numeric))
			{
				// Unparseable number: treat the whole thing as text so the row set does
				// not silently become everything.
				term.field = Field::Text;
				term.text = ToLower(raw);
				m_terms.push_back(std::move(term));
				continue;
			}
		}
		else
		{
			if (!value.empty() && value.back() == '*')
			{
				term.prefix = true;
				value.pop_back();
			}
			if (value.empty())
				continue;
			term.text = ToLower(value);
		}
		m_terms.push_back(std::move(term));
	}
}


TTDBehaviorReport::~TTDBehaviorReport()
{
	Close();
}


void TTDBehaviorReport::Close()
{
#ifdef WIN32
	if (m_map != nullptr)
		::UnmapViewOfFile(const_cast<uint8_t*>(m_map));
	if (m_mappingHandle != nullptr)
		::CloseHandle(m_mappingHandle);
	if (m_fileHandle != nullptr && m_fileHandle != INVALID_HANDLE_VALUE)
		::CloseHandle(m_fileHandle);
#else
	if (m_map != nullptr)
		::munmap(const_cast<uint8_t*>(m_map), static_cast<size_t>(m_mapSize));
	if (m_fileHandle != nullptr)
		::close(static_cast<int>(reinterpret_cast<intptr_t>(m_fileHandle)) - 1);
#endif
	m_map = nullptr;
	m_mappingHandle = nullptr;
	m_fileHandle = nullptr;
	m_mapSize = 0;
	m_callCount = 0;
	m_decodedCount = 0;
	m_maxSeq = 0;
	m_pid = 0;
	m_maxPositionChars = 0;
	m_path.clear();
	m_tracePath.clear();
	m_arch.clear();
}


bool TTDBehaviorReport::Open(const std::string& path, std::string& error)
{
	Close();

	const uint8_t* map = nullptr;
	uint64_t size = 0;

#ifdef WIN32
	HANDLE file = ::CreateFileA(
		path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (file == INVALID_HANDLE_VALUE)
	{
		error = "cannot open " + path;
		return false;
	}
	LARGE_INTEGER fileSize {};
	if (!::GetFileSizeEx(file, &fileSize) || static_cast<uint64_t>(fileSize.QuadPart) < kHeaderSize)
	{
		::CloseHandle(file);
		error = "report is too small to contain a header";
		return false;
	}
	HANDLE mapping = ::CreateFileMappingA(file, nullptr, PAGE_READONLY, 0, 0, nullptr);
	if (mapping == nullptr)
	{
		::CloseHandle(file);
		error = "cannot create a mapping for " + path;
		return false;
	}
	map = static_cast<const uint8_t*>(::MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0));
	if (map == nullptr)
	{
		::CloseHandle(mapping);
		::CloseHandle(file);
		error = "cannot map " + path;
		return false;
	}
	size = static_cast<uint64_t>(fileSize.QuadPart);
	m_fileHandle = file;
	m_mappingHandle = mapping;
#else
	int fd = ::open(path.c_str(), O_RDONLY);
	if (fd < 0)
	{
		error = "cannot open " + path;
		return false;
	}
	struct stat st {};
	if (::fstat(fd, &st) != 0 || static_cast<uint64_t>(st.st_size) < kHeaderSize)
	{
		::close(fd);
		error = "report is too small to contain a header";
		return false;
	}
	void* addr = ::mmap(nullptr, static_cast<size_t>(st.st_size), PROT_READ, MAP_PRIVATE, fd, 0);
	if (addr == MAP_FAILED)
	{
		::close(fd);
		error = "cannot map " + path;
		return false;
	}
	map = static_cast<const uint8_t*>(addr);
	size = static_cast<uint64_t>(st.st_size);
	// Stored offset by one so that fd 0 is distinguishable from "no handle".
	m_fileHandle = reinterpret_cast<void*>(static_cast<intptr_t>(fd) + 1);
#endif

	m_map = map;
	m_mapSize = size;

	if (std::memcmp(map, kMagic, sizeof(kMagic)) != 0)
	{
		Close();
		error = "not a TTD behavior report";
		return false;
	}
	uint32_t version = Read<uint32_t>(map + 8);
	if (version != kVersion)
	{
		Close();
		error = "report format version " + std::to_string(version) + " is not supported (expected "
			+ std::to_string(kVersion) + "); re-extract it";
		return false;
	}

	uint32_t archId = Read<uint32_t>(map + 12);
	m_callCount = Read<uint64_t>(map + 16);
	m_pid = Read<uint64_t>(map + 32);
	m_callsOff = Read<uint64_t>(map + 40);
	m_paramsOff = Read<uint64_t>(map + 48);
	m_stringsOff = Read<uint64_t>(map + 56);
	m_stringsSize = Read<uint64_t>(map + 64);
	m_blobOff = Read<uint64_t>(map + 72);
	m_blobSize = Read<uint64_t>(map + 80);
	m_decodedCount = Read<uint64_t>(map + 88);
	m_maxSeq = Read<uint64_t>(map + 96);
	uint32_t tracePathStr = Read<uint32_t>(map + 104);
	m_maxPositionChars = Read<uint32_t>(map + 112);

	// Refuse a file whose regions do not fit rather than trusting offsets from disk.
	auto withinFile = [size](uint64_t off, uint64_t len) {
		return off <= size && len <= size - off;
	};
	if (!withinFile(m_callsOff, m_callCount * kCallRecordSize) || !withinFile(m_stringsOff, m_stringsSize)
		|| !withinFile(m_blobOff, m_blobSize))
	{
		Close();
		error = "report header describes regions outside the file; it may be truncated";
		return false;
	}

	m_path = path;
	m_arch = archId == 1 ? "x86" : "x64";
	m_tracePath = MappedString(tracePathStr);
	return true;
}


const uint8_t* TTDBehaviorReport::CallRecord(uint64_t index) const
{
	return m_map + m_callsOff + index * kCallRecordSize;
}


std::string TTDBehaviorReport::MappedString(uint32_t offset) const
{
	if (m_map == nullptr || offset >= m_stringsSize)
		return std::string();
	const char* start = reinterpret_cast<const char*>(m_map + m_stringsOff + offset);
	size_t maxLen = static_cast<size_t>(m_stringsSize - offset);
	size_t len = 0;
	while (len < maxLen && start[len] != '\0')
		++len;
	return std::string(start, len);
}


void TTDBehaviorReport::ForEachString(const std::function<void(uint32_t, const char*, size_t)>& fn) const
{
	if (m_map == nullptr)
		return;
	const char* base = reinterpret_cast<const char*>(m_map + m_stringsOff);
	uint64_t offset = 0;
	while (offset < m_stringsSize)
	{
		size_t length = 0;
		while (offset + length < m_stringsSize && base[offset + length] != '\0')
			++length;
		if (length != 0)
			fn(static_cast<uint32_t>(offset), base + offset, length);
		offset += length + 1;
	}
}


void TTDBehaviorReport::ResolveQuery(TTDBehaviorQuery& query) const
{
	bool needsStrings = false;
	for (TTDBehaviorQuery::Term& t : query.GetTerms())
	{
		t.stringOffsets.clear();
		if (t.field == TTDBehaviorQuery::Field::Module || t.field == TTDBehaviorQuery::Field::Api)
			needsStrings = true;
	}
	if (!needsStrings || m_map == nullptr)
		return;

	// One pass over the string table -- a few thousand entries, not a few million rows --
	// collecting the offsets each module/api term accepts. Matching a row afterwards is
	// then a lookup in a handful of integers.
	ForEachString([&query](uint32_t offset, const char* text, size_t length) {
		std::string lowered = ToLower(std::string(text, length));
		for (TTDBehaviorQuery::Term& t : query.GetTerms())
		{
			if (t.field != TTDBehaviorQuery::Field::Module && t.field != TTDBehaviorQuery::Field::Api)
				continue;
			bool hit = t.prefix ? lowered.rfind(t.text, 0) == 0 : lowered == t.text;
			if (hit)
				t.stringOffsets.push_back(offset);
		}
	});

	for (TTDBehaviorQuery::Term& t : query.GetTerms())
		std::sort(t.stringOffsets.begin(), t.stringOffsets.end());
}


bool TTDBehaviorReport::Matches(uint64_t index, const TTDBehaviorQuery& query) const
{
	if (query.IsEmpty())
		return true;
	if (m_map == nullptr || index >= m_callCount)
		return false;

	const uint8_t* rec = CallRecord(index);
	for (const TTDBehaviorQuery::Term& t : query.GetTerms())
	{
		bool ok = true;
		switch (t.field)
		{
		case TTDBehaviorQuery::Field::Text:
		{
			uint32_t searchOff = Read<uint32_t>(rec + 32);
			uint16_t searchLen = Read<uint16_t>(rec + 38);
			// searchOff is relative to the blob region, so it is bounded against the
			// region's size rather than its position in the file.
			if (static_cast<uint64_t>(searchOff) + searchLen > m_blobSize)
				return false;
			std::string_view hay(reinterpret_cast<const char*>(m_map + m_blobOff + searchOff), searchLen);
			ok = hay.find(t.text) != std::string_view::npos;
			break;
		}
		case TTDBehaviorQuery::Field::Module:
		case TTDBehaviorQuery::Field::Api:
		{
			uint32_t offset = Read<uint32_t>(rec + (t.field == TTDBehaviorQuery::Field::Module ? 20 : 24));
			ok = std::binary_search(t.stringOffsets.begin(), t.stringOffsets.end(), offset);
			break;
		}
		case TTDBehaviorQuery::Field::Tid:
			ok = t.numeric.Test(Read<uint32_t>(rec + 8));
			break;
		case TTDBehaviorQuery::Field::Ret:
			ok = t.numeric.Test(Read<uint64_t>(rec + 0));
			break;
		case TTDBehaviorQuery::Field::RetAddr:
			ok = t.numeric.Test(Read<uint64_t>(rec + 40));
			break;
		}
		if (!ok)
			return false;
	}
	return true;
}


std::vector<uint64_t> TTDBehaviorReport::RunQuery(TTDBehaviorQuery& query) const
{
	std::vector<uint64_t> result;
	if (m_map == nullptr)
		return result;
	ResolveQuery(query);
	if (query.IsEmpty())
	{
		result.resize(static_cast<size_t>(m_callCount));
		for (uint64_t i = 0; i < m_callCount; ++i)
			result[static_cast<size_t>(i)] = i;
		return result;
	}
	for (uint64_t i = 0; i < m_callCount; ++i)
	{
		if (Matches(i, query))
			result.push_back(i);
	}
	return result;
}


std::vector<uint64_t> TTDBehaviorReport::RunQuery(const std::string& query) const
{
	TTDBehaviorQuery parsed;
	parsed.Parse(query);
	return RunQuery(parsed);
}


bool TTDBehaviorReport::GetCall(uint64_t index, TTDApiCall& out, bool withParams) const
{
	if (m_map == nullptr || index >= m_callCount)
		return false;

	const uint8_t* rec = CallRecord(index);
	out.params.clear();
	out.seq = index;  // recorded calls are numbered densely, so the row index is the seq
	out.ret = Read<uint64_t>(rec + 0);
	out.tid = Read<uint32_t>(rec + 8);
	out.positionSequence = Read<uint32_t>(rec + 12);
	out.positionSteps = Read<uint32_t>(rec + 16);
	out.module = MappedString(Read<uint32_t>(rec + 20));
	out.api = MappedString(Read<uint32_t>(rec + 24));
	out.returnAddress = Read<uint64_t>(rec + 40);

	uint32_t paramOff = Read<uint32_t>(rec + 28);
	uint16_t rawCount = Read<uint16_t>(rec + 36);
	out.decoded = (rawCount & kDecodedFlag) != 0;
	int paramCount = rawCount & ~kDecodedFlag;

	// The parameter region is variable-length, so a call's parameters are decoded in
	// sequence from its offset. Only ever done for rows something actually asked about.
	const uint8_t* p = m_map + m_paramsOff + paramOff;
	const uint8_t* blob = m_map + m_blobOff;
	std::string summary;
	for (int i = 0; i < paramCount; ++i)
	{
		uint8_t kind = *p++;
		uint8_t bits = *p++;
		uint32_t nameStr = Read<uint32_t>(p);
		p += 4;
		uint32_t typeStr = Read<uint32_t>(p);
		p += 4;

		TTDApiCallParam param;
		param.name = MappedString(nameStr);
		param.type = MappedString(typeStr);
		param.kind = kind < (sizeof(kKindNames) / sizeof(kKindNames[0])) ? kKindNames[kind] : "";
		param.value = Read<uint64_t>(p);
		p += 8;
		param.out = (bits & ParamOut) != 0;
		param.atReturn = (bits & ParamAtReturn) != 0;

		if (bits & ParamHasDeref)
		{
			param.hasDeref = true;
			param.deref = Read<uint64_t>(p);
			p += 8;
		}
		if (bits & ParamHasStr)
		{
			uint32_t off = Read<uint32_t>(p);
			uint32_t len = Read<uint32_t>(p + 4);
			p += 8;
			param.str.assign(reinterpret_cast<const char*>(blob + off), len);
		}
		if (bits & ParamHasBytes)
		{
			uint32_t off = Read<uint32_t>(p);
			uint32_t len = Read<uint32_t>(p + 4);
			param.bytesTotal = Read<uint64_t>(p + 8);
			p += 16;
			param.bytes.assign(blob + off, blob + off + len);
		}
		if (bits & ParamHasFlags)
		{
			uint32_t off = Read<uint32_t>(p);
			uint32_t len = Read<uint32_t>(p + 4);
			p += 8;
			std::string joined(reinterpret_cast<const char*>(blob + off), len);
			size_t start = 0;
			while (start <= joined.size())
			{
				size_t bar = joined.find('|', start);
				if (bar == std::string::npos)
				{
					if (start < joined.size())
						param.flags.push_back(joined.substr(start));
					break;
				}
				param.flags.push_back(joined.substr(start, bar - start));
				start = bar + 1;
			}
		}

		// Rendered the way it reads best given what the decoder recovered: a resolved
		// string beats symbolic flags, which beat a raw value.
		std::string rendered;
		if (!param.str.empty())
			rendered = "\"" + param.str + "\"";
		else if (!param.flags.empty())
		{
			for (size_t f = 0; f < param.flags.size(); ++f)
			{
				if (f != 0)
					rendered += "|";
				rendered += param.flags[f];
			}
		}
		else if (!param.bytes.empty())
		{
			// Worth the width: the head of a buffer tells you at a glance what a
			// WriteFile actually wrote, where the pointer alone tells you nothing.
			rendered = FormatHex(param.value) + " -> [" + PreviewBytes(param.bytes) + "]";
		}
		else if (param.hasDeref)
			rendered = FormatHex(param.value) + " -> " + FormatHex(param.deref);
		else
			rendered = FormatHex(param.value);

		if (!summary.empty())
			summary += ", ";
		summary += out.decoded && !param.name.empty() ? param.name + "=" + rendered : rendered;

		if (withParams)
			out.params.push_back(std::move(param));
	}
	out.paramSummary = std::move(summary);
	return true;
}
