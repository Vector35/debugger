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

#include "debuggerapi.h"

using namespace BinaryNinjaDebuggerAPI;

namespace {
	// Every char* the FFI hands back is ours to free.
	std::string TakeString(char* raw)
	{
		if (raw == nullptr)
			return std::string();
		std::string result(raw);
		BNDebuggerFreeString(raw);
		return result;
	}
}  // namespace


TTDBehaviorReport::~TTDBehaviorReport()
{
	Close();
}


bool TTDBehaviorReport::Open(const std::string& path, std::string& error)
{
	Close();
	char* errorMessage = nullptr;
	m_object = BNTTDBehaviorOpenReport(path.c_str(), &errorMessage);
	if (m_object == nullptr)
	{
		error = TakeString(errorMessage);
		return false;
	}
	return true;
}


void TTDBehaviorReport::Close()
{
	if (m_object != nullptr)
	{
		BNTTDBehaviorCloseReport(m_object);
		m_object = nullptr;
	}
}


uint64_t TTDBehaviorReport::GetCallCount() const
{
	return m_object ? BNTTDBehaviorGetCallCount(m_object) : 0;
}


uint64_t TTDBehaviorReport::GetDecodedCount() const
{
	return m_object ? BNTTDBehaviorGetDecodedCount(m_object) : 0;
}


uint64_t TTDBehaviorReport::GetProcessId() const
{
	return m_object ? BNTTDBehaviorGetProcessId(m_object) : 0;
}


uint64_t TTDBehaviorReport::GetMaxSequence() const
{
	return m_object ? BNTTDBehaviorGetMaxSequence(m_object) : 0;
}


uint32_t TTDBehaviorReport::GetMaxPositionChars() const
{
	return m_object ? BNTTDBehaviorGetMaxPositionChars(m_object) : 0;
}


std::string TTDBehaviorReport::GetTracePath() const
{
	return m_object ? TakeString(BNTTDBehaviorGetTracePath(m_object)) : std::string();
}


std::string TTDBehaviorReport::GetArchitecture() const
{
	return m_object ? TakeString(BNTTDBehaviorGetArchitecture(m_object)) : std::string();
}


std::vector<uint64_t> TTDBehaviorReport::RunQuery(const std::string& query) const
{
	std::vector<uint64_t> result;
	if (m_object == nullptr)
		return result;

	size_t count = 0;
	uint64_t* rows = BNTTDBehaviorRunQuery(m_object, query.c_str(), &count);
	if (rows == nullptr)
		return result;
	result.assign(rows, rows + count);
	BNTTDBehaviorFreeQueryResult(rows);
	return result;
}


bool TTDBehaviorReport::GetCall(uint64_t index, TTDApiCall& out, bool withParams) const
{
	if (m_object == nullptr)
		return false;

	BNTTDApiCall raw {};
	if (!BNTTDBehaviorGetCall(m_object, index, withParams, &raw))
		return false;

	out.seq = raw.m_seq;
	out.tid = raw.m_tid;
	out.positionSequence = raw.m_positionSequence;
	out.positionSteps = raw.m_positionSteps;
	out.module = raw.m_module ? raw.m_module : "";
	out.api = raw.m_api ? raw.m_api : "";
	out.ret = raw.m_ret;
	out.returnAddress = raw.m_returnAddress;
	out.paramSummary = raw.m_paramSummary ? raw.m_paramSummary : "";
	out.decoded = raw.m_decoded;

	out.params.clear();
	out.params.reserve(raw.m_paramCount);
	for (size_t i = 0; i < raw.m_paramCount; ++i)
	{
		const BNTTDApiCallParam& src = raw.m_params[i];
		TTDApiCallParam param;
		param.name = src.m_name ? src.m_name : "";
		param.type = src.m_type ? src.m_type : "";
		param.kind = src.m_kind ? src.m_kind : "";
		param.value = src.m_value;
		param.str = src.m_str ? src.m_str : "";
		for (size_t f = 0; f < src.m_flagCount; ++f)
			param.flags.emplace_back(src.m_flags[f] ? src.m_flags[f] : "");
		if (src.m_byteCount != 0 && src.m_bytes != nullptr)
			param.bytes.assign(src.m_bytes, src.m_bytes + src.m_byteCount);
		param.bytesTotal = src.m_bytesTotal;
		param.deref = src.m_deref;
		param.hasDeref = src.m_hasDeref;
		param.out = src.m_out;
		param.atReturn = src.m_atReturn;
		out.params.push_back(std::move(param));
	}

	// The strings and arrays above were copied, so the FFI's allocation goes back now.
	BNTTDBehaviorFreeCall(&raw);
	return true;
}
