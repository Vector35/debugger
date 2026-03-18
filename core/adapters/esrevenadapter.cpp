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

#include "esrevenadapter.h"
#include <memory>
#include <cstring>
#ifdef WIN32
#include <windows.h>
#undef min
#undef max
#else
#include <unistd.h>
#ifndef WIN32
#include <spawn.h>
#endif
#include <csignal>
#endif
#include <algorithm>
#include <string>
#include <chrono>
#include <thread>
#include <cstdio>
#include <iostream>
#include <string_view>
#include <regex>
#include <stdexcept>
#include "../../vendor/pugixml/pugixml.hpp"
#include <binaryninjacore.h>
#include <binaryninjaapi.h>
#include <lowlevelilinstruction.h>
#include <mediumlevelilinstruction.h>
#include <highlevelilinstruction.h>
#include <inttypes.h>

#include "../debuggercontroller.h"

using namespace BinaryNinja;
using namespace std;
using namespace BinaryNinjaDebugger;

static bool IsBigEndianArchitecture(const std::string& arch);

EsrevenAdapter::EsrevenAdapter(BinaryView* data, bool redirectGDBServer): DebugAdapter(data)
{
    m_isTargetRunning = false;

	GenerateDefaultAdapterSettings(data);
}

EsrevenAdapter::~EsrevenAdapter()
{
}

bool EsrevenAdapter::Execute(const std::string& path, const LaunchConfigurations& configs)
{
	LogWarn("EsrevenAdapter does not support Execute()");
    return false;
}

bool EsrevenAdapter::ExecuteWithArgs(const std::string &path, const std::string &args, const std::string &workingDir,
					 const LaunchConfigurations &configs)
{
	LogWarn("EsrevenAdapter does not support ExecuteWithArgs()");
	return false;
}

bool EsrevenAdapter::Attach(std::uint32_t pid)
{
	LogWarn("EsrevenAdapter does not support Attach()");
	return false;
}

bool EsrevenAdapter::LoadRegisterInfo()
{
    if (m_isTargetRunning || !m_rspConnector)
        return false;

    const auto xml = this->m_rspConnector->GetXml("target.xml");

    pugi::xml_document doc{};
    const auto parse_result = doc.load_string(xml.c_str());
    if (!parse_result)
        return false;

    std::string architecture{};
    std::string os_abi{};
    std::string endian{};
	size_t lastRegIndex = -1;

	auto processFeatures = [&](const pugi::xml_node& node) {
		for (auto reg_child = node.child("reg"); reg_child; reg_child = reg_child.next_sibling())
		{
			std::string register_name{};
			RegisterInfo register_info{};

			for (auto reg_attribute = reg_child.attribute("name"); reg_attribute; reg_attribute = reg_attribute.next_attribute())
			{
				if (reg_attribute.name() == "name"s )
					register_name = reg_attribute.value();
				else if (reg_attribute.name() == "bitsize"s )
					register_info.m_bitSize = reg_attribute.as_uint();

				// A register must have an index, which is used in the g reply packet
				// https://sourceware.org/gdb/current/onlinedocs/gdb.html/Target-Description-Format.html#Target-Description-Format
				if (reg_attribute.name() == "regnum"s)
					register_info.m_regNum = reg_attribute.as_uint();
				else
					register_info.m_regNum = (uint32_t)lastRegIndex + 1;
			}

			if (register_name.empty())
				continue;

			this->m_registerInfo[register_name] = register_info;
			lastRegIndex = register_info.m_regNum;
		}
	};

    for (auto node = doc.first_child().child("architecture"); node; node = node.next_sibling())
    {
        using namespace std::literals::string_literals;

        if ( node.name() == "architecture"s )
            architecture = node.child_value();
        else if ( node.name() == "osabi"s )
            os_abi = node.child_value();
        else if ( node.name() == "endian"s )
            endian = node.child_value();
        else if ( node.name() == "feature"s )
			processFeatures(node);
    	else if (node.name() == "xi:include"s )
    	{
    		auto includePath = node.attribute("href").value();
    		const auto includedXml = this->m_rspConnector->GetXml(includePath);
    		if (includedXml.empty())
    			continue;

    		pugi::xml_document includedDocs{};
    		const auto includedParseResult = includedDocs.load_string(includedXml.c_str());
    		if (!includedParseResult)
    			continue;

    		auto includedNode = includedDocs.first_child();
    		if (includedNode.name() == "feature"s )
    			processFeatures(includedNode);
    	}
    }

	if (architecture.empty())
	{
		LogWarn("failed to find architecture");
		return false;
	}

	// Store the original architecture for endianness detection before stripping the prefix
	std::string fullArchitecture = architecture;

	if (architecture.find(':') != std::string::npos)
	{
		architecture.erase(0, architecture.find(':') + 1);
		auto hyphenPos = architecture.find('-');
		if (hyphenPos != std::string::npos)
			architecture.replace(hyphenPos, 1, "_");
	}
	m_remoteArch = architecture;

	// Determine endianness: prefer explicit <endian> element, fall back to architecture-based detection
	if (!endian.empty())
		m_isBigEndian = (endian == "big");
	else
		m_isBigEndian = IsBigEndianArchitecture(fullArchitecture);

    std::unordered_map<std::uint32_t, std::string> id_name{};
    std::unordered_map<std::uint32_t, std::uint32_t> id_width{};

    for ( auto [key, value] : this->m_registerInfo ) {
        id_name[value.m_regNum] = key;
        id_width[value.m_regNum] = value.m_bitSize;
    }

    uint32_t max_id{};
    for ( auto [key, value] : this->m_registerInfo )
        max_id += value.m_regNum;

    uint32_t offset{};
    for ( uint32_t index{}; index < max_id; index++ ) {
        if ( !id_width[index] )
            break;

        const auto name = id_name[index];
        this->m_registerInfo[name].m_offset = offset;
        offset += id_width[index];
    }

    return true;
}

bool EsrevenAdapter::Connect(const std::string& server, std::uint32_t port)
{
	m_canReverseContinue = false;
	m_canReverseStep = false;

	BNSettingsScope scope = SettingsResourceScope;
	auto data = GetData();
	auto adapterSettings = GetAdapterSettings();
	auto inputFile = adapterSettings->Get<std::string>("common.inputFile", data, &scope);
	scope = SettingsResourceScope;
	auto ipAddress = adapterSettings->Get<std::string>("connect.ipAddress", data, &scope);
	scope = SettingsResourceScope;
	auto serverPort = adapterSettings->Get<uint64_t>("connect.port", data, &scope);
	scope = SettingsResourceScope;

    bool connected = false;
    for ( std::uint8_t index{}; index < 30; index++ ) {
        this->m_socket = new Socket(AF_INET, SOCK_STREAM, 0);

        sockaddr_in address{};
        address.sin_family = (u_short)AF_INET;
        address.sin_addr.s_addr = inet_addr(ipAddress.c_str());
        address.sin_port = htons((u_short)serverPort);

        if (this->m_socket->Connect(address)) {
            connected = true;
            break;
        }

    	m_socket->Close();
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    if ( !connected )
    {
    	DebuggerEvent event;
    	event.type = LaunchFailureEventType;
    	event.data.errorData.shortError = "Connection failed";
    	event.data.errorData.error =
			fmt::format("Failed to connect to {}:{}", ipAddress, serverPort);
    	PostDebuggerEvent(event);
    	return false;
    }

    this->m_rspConnector = new RspConnector(this->m_socket);
    this->m_rspConnector->TransmitAndReceive(RspData("Hg0"));
    this->m_rspConnector->NegotiateCapabilities(
            { "swbreak+", "hwbreak+", "qRelocInsn+", "fork-events+", "vfork-events+", "exec-events+",
                         "vContSupported+", "QThreadEvents+", "no-resumed+", "xmlRegisters=i386" } );

	auto capacities = m_rspConnector->GetServerCapabilities();
	if (std::find(capacities.begin(), capacities.end(), "ReverseContinue") != capacities.end())
		m_canReverseContinue = true;
	if (std::find(capacities.begin(), capacities.end(), "ReverseStep") != capacities.end())
		m_canReverseStep = true;

    if ( !this->LoadRegisterInfo() )
    {
    	DebuggerEvent event;
    	event.type = LaunchFailureEventType;
    	event.data.errorData.shortError = "Invalid Register Info";
    	event.data.errorData.error =
			fmt::format("Failed to read register info from the server");
    	PostDebuggerEvent(event);
	    return false;
    }

    const auto reply = this->m_rspConnector->TransmitAndReceive(RspData("?"));
    auto map = RspConnector::PacketToUnorderedMap(reply);
	this->m_lastActiveThreadId = (uint32_t)map["thread"];
	this->m_processPid = (uint32_t)map["thread"];
    m_isTargetRunning = false;

	// Apply any pending breakpoints that were added before connecting
	CheckApplyPendingBreakpoints();

	if (Settings::Instance()->Get<bool>("debugger.stopAtEntryPoint") && m_hasEntryFunction)
		AddBreakpoint(ModuleNameAndOffset(inputFile, m_entryPoint - m_start));

	DebuggerEvent dbgevt;
	dbgevt.type = AdapterStoppedEventType;
	dbgevt.data.targetStoppedData.reason = InitialBreakpoint;
	PostDebuggerEvent(dbgevt);

    return true;
}

bool EsrevenAdapter::ConnectToDebugServer(const std::string &server, std::uint32_t port)
{
	LogWarn("DbgAdapter does not support connecting to a debug server, please use connect to remote process instead");
	return false;
}

bool EsrevenAdapter::Detach()
{
	if (!m_rspConnector)
		return false;

    this->m_rspConnector->SendPayload(RspData("D"));
    this->m_socket->Kill();
    m_isTargetRunning = false;
	InvalidateCache();
	ClearCachedBreakpoints();

	if (m_rspConnector)
	{
		delete m_rspConnector;
		m_rspConnector = nullptr;
	}

	DebuggerEvent dbgevt;
	dbgevt.type = TargetExitedEventType;
	dbgevt.data.exitData.exitCode = ExitCode();
	PostDebuggerEvent(dbgevt);

	return true;
}

bool EsrevenAdapter::Quit()
{
	if (!m_rspConnector)
		return false;

	// Modern gdbserver uses vkill to kill the taget:
	// $vKill;7c3d#6e
	// $OK#9a
    this->m_rspConnector->SendPayload(RspData("k"));
    this->m_socket->Kill();
    m_isTargetRunning = false;
	InvalidateCache();
	ClearCachedBreakpoints();

	if (m_rspConnector)
	{
		delete m_rspConnector;
		m_rspConnector = nullptr;
	}

	// TODO: we should only treat the target as exited when either 1) the remote side closes the socket, or, 2) the
	// remote side returns OK to the vkill request.
	// The current implementation is only a workaround since when we send the "k" request, the gdbserver will close
	// the connection immediately and NOT send any response. However, if we let the target run and exit on its own,
	// gdbserver will send a stop reply packet starting with "W".
	DebuggerEvent dbgevt;
	dbgevt.type = TargetExitedEventType;
	dbgevt.data.exitData.exitCode = ExitCode();
	PostDebuggerEvent(dbgevt);

	return true;
}

std::vector<DebugThread> EsrevenAdapter::GetThreadList()
{
	// Return cached data if available
	if (m_threadCache.has_value())
	{
		std::vector<DebugThread> threads;
		for (const auto& cached : m_threadCache.value())
		{
			threads.emplace_back(cached.tid, cached.rip);
		}
		return threads;
	}

	if (m_isTargetRunning || !m_rspConnector)
		return {};

	// Use the custom rvn:list-threads packet
	auto response = m_rspConnector->TransmitAndReceive(RspData("rvn:list-threads"));
	std::string jsonStr = response.AsString();

	// Check if we got a valid JSON response
	if (jsonStr.empty() || jsonStr[0] != '[')
		return {};

	std::vector<ThreadFrameCache> cache;
	std::vector<DebugThread> threads;

	// Parse JSON array of threads
	size_t pos = 0;
	while (pos < jsonStr.length())
	{
		// Find the start of a thread object
		size_t threadStart = jsonStr.find('{', pos);
		if (threadStart == std::string::npos)
			break;

		// Find the end of the thread object (handles nested frames array)
		int braceCount = 0;
		size_t threadEnd = threadStart;
		for (size_t i = threadStart; i < jsonStr.length(); i++)
		{
			if (jsonStr[i] == '{')
				braceCount++;
			else if (jsonStr[i] == '}')
			{
				braceCount--;
				if (braceCount == 0)
				{
					threadEnd = i;
					break;
				}
			}
		}

		if (threadEnd == threadStart)
			break;

		std::string threadObj = jsonStr.substr(threadStart, threadEnd - threadStart + 1);

		// Parse thread fields
		ThreadFrameCache threadData;
		threadData.tid = 0;
		threadData.rip = 0;

		// Extract "tid"
		size_t tidPos = threadObj.find("\"tid\"");
		if (tidPos != std::string::npos)
		{
			size_t colonPos = threadObj.find(':', tidPos);
			if (colonPos != std::string::npos)
			{
				colonPos++;
				while (colonPos < threadObj.length() && std::isspace(threadObj[colonPos]))
					colonPos++;

				size_t numEnd = colonPos;
				while (numEnd < threadObj.length() && std::isdigit(threadObj[numEnd]))
					numEnd++;

				if (numEnd > colonPos)
				{
					std::string tidStr = threadObj.substr(colonPos, numEnd - colonPos);
					threadData.tid = std::stoull(tidStr);
				}
			}
		}

		// Extract "rip"
		size_t ripPos = threadObj.find("\"rip\"");
		if (ripPos != std::string::npos)
		{
			size_t colonPos = threadObj.find(':', ripPos);
			if (colonPos != std::string::npos)
			{
				colonPos++;
				while (colonPos < threadObj.length() && std::isspace(threadObj[colonPos]))
					colonPos++;

				size_t numEnd = colonPos;
				while (numEnd < threadObj.length() && std::isdigit(threadObj[numEnd]))
					numEnd++;

				if (numEnd > colonPos)
				{
					std::string ripStr = threadObj.substr(colonPos, numEnd - colonPos);
					threadData.rip = std::stoull(ripStr);
				}
			}
		}

		// Extract "frames" array
		size_t framesPos = threadObj.find("\"frames\"");
		if (framesPos != std::string::npos)
		{
			size_t arrayStart = threadObj.find('[', framesPos);
			if (arrayStart != std::string::npos)
			{
				// Find the matching closing bracket
				int bracketCount = 0;
				size_t arrayEnd = arrayStart;
				for (size_t i = arrayStart; i < threadObj.length(); i++)
				{
					if (threadObj[i] == '[')
						bracketCount++;
					else if (threadObj[i] == ']')
					{
						bracketCount--;
						if (bracketCount == 0)
						{
							arrayEnd = i;
							break;
						}
					}
				}

				if (arrayEnd > arrayStart)
				{
					std::string framesArray = threadObj.substr(arrayStart + 1, arrayEnd - arrayStart - 1);

					// Parse individual frame objects
					size_t framePos = 0;
					while (framePos < framesArray.length())
					{
						size_t frameStart = framesArray.find('{', framePos);
						if (frameStart == std::string::npos)
							break;

						int frameBraceCount = 0;
						size_t frameEnd = frameStart;
						for (size_t i = frameStart; i < framesArray.length(); i++)
						{
							if (framesArray[i] == '{')
								frameBraceCount++;
							else if (framesArray[i] == '}')
							{
								frameBraceCount--;
								if (frameBraceCount == 0)
								{
									frameEnd = i;
									break;
								}
							}
						}

						if (frameEnd == frameStart)
							break;

						std::string frameObj = framesArray.substr(frameStart, frameEnd - frameStart + 1);

						// Parse frame fields
						DebugFrame frame;
						frame.m_index = 0;
						frame.m_pc = 0;
						frame.m_sp = 0;
						frame.m_fp = 0;
						frame.m_functionName = "";
						frame.m_functionStart = 0;
						frame.m_module = "<unknown>";

						// Helper lambda to extract integer value
						auto extractInt = [](const std::string& obj, const std::string& key) -> uint64_t {
							size_t keyPos = obj.find("\"" + key + "\"");
							if (keyPos != std::string::npos)
							{
								size_t colonPos = obj.find(':', keyPos);
								if (colonPos != std::string::npos)
								{
									colonPos++;
									while (colonPos < obj.length() && std::isspace(obj[colonPos]))
										colonPos++;

									// Check for null
									if (obj.substr(colonPos, 4) == "null")
										return 0;

									size_t numEnd = colonPos;
									while (numEnd < obj.length() && std::isdigit(obj[numEnd]))
										numEnd++;

									if (numEnd > colonPos)
									{
										std::string numStr = obj.substr(colonPos, numEnd - colonPos);
										return std::stoull(numStr);
									}
								}
							}
							return 0;
						};

						// Helper lambda to extract string value
						auto extractString = [](const std::string& obj, const std::string& key) -> std::string {
							size_t keyPos = obj.find("\"" + key + "\"");
							if (keyPos != std::string::npos)
							{
								size_t colonPos = obj.find(':', keyPos);
								if (colonPos != std::string::npos)
								{
									size_t quoteStart = obj.find('"', colonPos);
									if (quoteStart != std::string::npos)
									{
										size_t quoteEnd = obj.find('"', quoteStart + 1);
										if (quoteEnd != std::string::npos)
										{
											return obj.substr(quoteStart + 1, quoteEnd - quoteStart - 1);
										}
									}
									else
									{
										// Check for null
										colonPos++;
										while (colonPos < obj.length() && std::isspace(obj[colonPos]))
											colonPos++;
										if (obj.substr(colonPos, 4) == "null")
											return "";
									}
								}
							}
							return "";
						};

						frame.m_index = extractInt(frameObj, "index");
						frame.m_pc = extractInt(frameObj, "pc");
						frame.m_sp = extractInt(frameObj, "sp");
						frame.m_fp = extractInt(frameObj, "fp");
						frame.m_functionStart = extractInt(frameObj, "function_start");

						std::string funcName = extractString(frameObj, "function_name");
						if (!funcName.empty())
							frame.m_functionName = funcName;

						std::string moduleName = extractString(frameObj, "module");
						if (!moduleName.empty())
							frame.m_module = moduleName;

						threadData.frames.push_back(frame);
						framePos = frameEnd + 1;
					}
				}
			}
		}

		cache.push_back(threadData);
		threads.emplace_back(threadData.tid, threadData.rip);
		pos = threadEnd + 1;
	}

	// Cache the results
	m_threadCache = cache;

	return threads;
}


std::vector<DebugFrame> EsrevenAdapter::GetFramesOfThread(std::uint32_t tid)
{
	// If cache is empty, call GetThreadList() to populate it
	if (!m_threadCache.has_value())
	{
		GetThreadList();
	}

	// Search for the thread in the cache
	if (m_threadCache.has_value())
	{
		for (const auto& threadData : m_threadCache.value())
		{
			if (threadData.tid == tid)
			{
				return threadData.frames;
			}
		}
	}

	// Thread not found, return empty vector
	return {};
}


DebugThread EsrevenAdapter::GetActiveThread() const
{
	// TODO: GetInstructionOffset() should really be const, but changing it requires changes in lots of files,
	// So I am abusing `this` and casting it to remove the const of it.
	// Definitely remember to get back and fix this.
	uint64_t pc = ((EsrevenAdapter*)this)->GetInstructionOffset();
    return DebugThread(this->GetActiveThreadId(), pc);
}

std::uint32_t EsrevenAdapter::GetActiveThreadId() const
{
    return m_lastActiveThreadId;
}

bool EsrevenAdapter::SetActiveThread(const DebugThread& thread)
{
	return SetActiveThreadId(thread.m_tid);
}

bool EsrevenAdapter::SetActiveThreadId(std::uint32_t tid)
{
	if (m_isTargetRunning || !m_rspConnector)
        return false;

    if ( this->m_rspConnector->TransmitAndReceive(RspData(string("T{:x}"), tid)).AsString() != "OK" )
    {
        LogWarn("thread does not exist");
        return false;
    }

    if ( this->m_rspConnector->TransmitAndReceive(RspData(string("Hc{:x}"), tid)).AsString() != "OK")
    {
        LogWarn("failed to set thread");
        return false;
    }

    if ( this->m_rspConnector->TransmitAndReceive(RspData(string("Hg{:x}"), tid)).AsString() != "OK")
    {
        LogWarn("failed to set thread");
        return false;
    }

    this->m_lastActiveThreadId = tid;

    return true;
}

DebugBreakpoint EsrevenAdapter::AddBreakpoint(const std::uintptr_t address, unsigned long breakpoint_type)
{
	if (m_isTargetRunning || !m_rspConnector)
        return {};

    if ( std::find(this->m_debugBreakpoints.begin(), this->m_debugBreakpoints.end(),
                   DebugBreakpoint(address)) != this->m_debugBreakpoints.end())
        return {};

    /* TODO: replace %d with the actual breakpoint size as it differs per architecture */
    size_t kind = 1;
    if (m_remoteArch == "aarch64")
        kind = 4;
//  TODO: other archs have other values for kind, e.g., thumb2 needs a value of 2 or 3 here.
//  https://sourceware.org/gdb/current/onlinedocs/gdb/ARM-Breakpoint-Kinds.html

    if (this->m_rspConnector->TransmitAndReceive(RspData("Z0,{:x},{}", address, kind)).AsString() != "OK" )
        return DebugBreakpoint{};

    const auto new_breakpoint = DebugBreakpoint(address, this->m_internalBreakpointId++, true, SoftwareBreakpoint);
    this->m_debugBreakpoints.push_back(new_breakpoint);

    return new_breakpoint;
}

bool EsrevenAdapter::RemoveBreakpoint(const DebugBreakpoint& breakpoint)
{
	if (m_isTargetRunning || !m_rspConnector)
        return false;

    if (auto location = std::find(this->m_debugBreakpoints.begin(), this->m_debugBreakpoints.end(), breakpoint);
            location == this->m_debugBreakpoints.end()) {
        return false;
    }

    /* TODO: replace %d with the actual breakpoint size as it differs per architecture */
    size_t kind = 1;
    if (m_remoteArch == "aarch64")
        kind = 4;

    if (this->m_rspConnector->TransmitAndReceive(RspData("z0,{:x},{}", breakpoint.m_address, kind)).AsString() != "OK" )
    {
    	LogDebug("rsp reply failure on remove breakpoint");
    	return false;
    }

    if (auto location = std::find(this->m_debugBreakpoints.begin(), this->m_debugBreakpoints.end(), breakpoint);
            location != this->m_debugBreakpoints.end())
        this->m_debugBreakpoints.erase(location);

    return true;
}

std::vector<DebugBreakpoint> EsrevenAdapter::GetBreakpointList() const
{
    return this->m_debugBreakpoints;
}


bool EsrevenAdapter::BreakpointExists(uint64_t address) const
{
    return std::find(this->m_debugBreakpoints.begin(), this->m_debugBreakpoints.end(),
                   DebugBreakpoint(address)) != this->m_debugBreakpoints.end();
}

static bool IsBigEndianArchitecture(const std::string& arch) {
	// PowerPC architectures (powerpc, ppc, common from "powerpc:common")
	if (arch.find("powerpc") != std::string::npos || arch.find("ppc") != std::string::npos || arch == "common")
		return true;
	// SPARC
	if (arch.find("sparc") != std::string::npos)
		return true;
	// Motorola 68k
	if (arch.find("m68k") != std::string::npos || arch.find("68k") != std::string::npos)
		return true;
	// IBM S/390
	if (arch.find("s390") != std::string::npos)
		return true;
	return false;
}

static intx::uint512 parseLittleEndianHexToUint512(const std::string& hex) {
	if (hex.size() % 2 != 0)
		return {};

	uint8_t buffer[64] = {};  // Zero-initialized

	size_t byteCount = hex.size() / 2;
	size_t limit = std::min(byteCount, size_t(64));

	for (size_t i = 0; i < limit; ++i)
	{
		std::string byteStr = hex.substr(i * 2, 2);
		buffer[i] = static_cast<uint8_t>(strtoul(byteStr.c_str(), nullptr, 16));
	}

	return intx::le::load<intx::uint512>(buffer);
}

static intx::uint512 parseBigEndianHexToUint512(const std::string& hex) {
	if (hex.size() % 2 != 0)
		return {};

	uint8_t buffer[64] = {};  // Zero-initialized

	size_t byteCount = hex.size() / 2;
	size_t limit = std::min(byteCount, size_t(64));

	// For big-endian: the hex string has MSB first. intx::be::load expects MSB at buffer[0]
	// for a full 512-bit value, so we must right-justify the bytes in the buffer.
	size_t offset = 64 - limit;
	for (size_t i = 0; i < limit; ++i)
	{
		std::string byteStr = hex.substr(i * 2, 2);
		buffer[offset + i] = static_cast<uint8_t>(strtoul(byteStr.c_str(), nullptr, 16));
	}

	return intx::be::load<intx::uint512>(buffer);
}

std::unordered_map<std::string, DebugRegister> EsrevenAdapter::ReadAllRegisters()
{
	if (m_isTargetRunning || !m_rspConnector)
		return {};

	if (m_regCache.has_value())
		return m_regCache.value();

    if ( this->m_registerInfo.empty() )
    {
        LogWarn("register info empty");
        return {};
    }

	// Sort the registers according to their index, as the g reply packet will provide values in the same order
    std::vector<register_pair> register_info_vec{};
    for ( const auto& [register_name, register_info] : this->m_registerInfo )
        register_info_vec.emplace_back(register_name, register_info);

    std::sort(register_info_vec.begin(), register_info_vec.end(),
              [](const register_pair& lhs, const register_pair& rhs) {
                  return lhs.second.m_regNum < rhs.second.m_regNum;
              });

    char request{'g'};
    const auto register_info_reply = this->m_rspConnector->TransmitAndReceive(RspData(&request, sizeof(request)));
    auto register_info_reply_string = register_info_reply.AsString();
    if ( register_info_reply_string.empty() )
    {
        LogWarn("register request reply empty");
        return {};
    }

    std::unordered_map<std::string, DebugRegister> all_regs{};
    for ( const auto& [register_name, register_info] : register_info_vec ) {
        const auto number_of_chars = 2 * ( register_info.m_bitSize / 8 );
        const auto value_string = register_info_reply_string.substr(0, number_of_chars);
    	if (!value_string.empty()) {
    		intx::uint512 value = m_isBigEndian ? parseBigEndianHexToUint512(value_string)
    		                                   : parseLittleEndianHexToUint512(value_string);
    		all_regs[register_name] = DebugRegister(register_name, value, register_info.m_bitSize, register_info.m_regNum);
    	}
        register_info_reply_string.erase(0, number_of_chars);
    }

	m_regCache = all_regs;
    return all_regs;
}

DebugRegister EsrevenAdapter::ReadRegister(const std::string& reg)
{
    if (m_isTargetRunning)
        return DebugRegister{};

    if ( this->m_registerInfo.find(reg) == this->m_registerInfo.end() )
    {
        LogWarn("register %s does not exist in target", reg.c_str());
        return DebugRegister{};
    }

    return this->ReadAllRegisters()[reg];
}

static std::string uint512ToLittleEndianHex(const intx::uint512& value, size_t width) {
	// Truncate to 64 bytes (512 bits max)
	if (width > 64)
		width = 64;

	uint8_t buffer[64] = {};
	intx::le::store(buffer, value);  // Store as little-endian

	std::string result;
	for (size_t i = 0; i < width; ++i)
		result += fmt::format("{:02X}", buffer[i]);

	return result;
}

static std::string uint512ToBigEndianHex(const intx::uint512& value, size_t width) {
	// Truncate to 64 bytes (512 bits max)
	if (width > 64)
		width = 64;

	uint8_t buffer[64] = {};
	intx::be::store(buffer, value);  // Store as big-endian

	std::string result;
	// For big-endian, we need to output from the position where the value starts
	// The value is stored right-aligned in the 64-byte buffer
	size_t offset = 64 - width;
	for (size_t i = 0; i < width; ++i)
		result += fmt::format("{:02X}", buffer[offset + i]);

	return result;
}

bool EsrevenAdapter::WriteRegister(const std::string& reg, intx::uint512 value)
{
    if (m_isTargetRunning || !m_rspConnector)
        return false;

    if (!this->m_registerInfo.contains(reg))
        return false;

    const auto newRegString = m_isBigEndian ? uint512ToBigEndianHex(value, this->m_registerInfo[reg].m_bitSize / 8)
                                           : uint512ToLittleEndianHex(value, this->m_registerInfo[reg].m_bitSize / 8);
    const auto reply = this->m_rspConnector->TransmitAndReceive(RspData("P{:02X}={}",
                                       this->m_registerInfo[reg].m_regNum, newRegString));

    if (reply.m_data[0])
        return true;

    char query{'g'};
    const auto generic_query = this->m_rspConnector->TransmitAndReceive(RspData(&query, sizeof(query)));
    const auto register_offset = this->m_registerInfo[reg].m_offset;

    // TODO: check if this works for aarch64
    const auto first_half = generic_query.AsString().substr(0, 2 * (register_offset / 8));
    const auto second_half = generic_query.AsString().substr(2 * ((register_offset + this->m_registerInfo[reg].m_bitSize) / 8) );
    const auto payload = "G" + first_half + newRegString + second_half;

    if ( this->m_rspConnector->TransmitAndReceive(RspData(payload)).AsString() != "OK" )
        return false;

    // TODO: we do not need to invalidate all register caches, we could probably just update the necessary ones here
    InvalidateCache();
    return true;
}

DataBuffer EsrevenAdapter::ReadMemory(std::uintptr_t address, std::size_t size)
{
    // This means whether the target is running. If it is, then we cannot read memory at the moment
	if (m_isTargetRunning || !m_rspConnector)
        return DataBuffer{};

    auto reply = this->m_rspConnector->TransmitAndReceive(RspData("m{:x},{:x}", address, size));
    if (reply.m_data[0] == 'E')
        return DataBuffer{};

    // The actual bytes read might be fewer than the requested size
    // We should pass this size by reference so the caller knows the number of bytes read
    size = reply.AsString().size() / 2;
    if (size == 0)
        return DataBuffer{};

    const auto source = std::make_unique<std::uint8_t[]>(2 * size + 1);
    const auto dest = std::make_unique<std::uint8_t[]>(size + 1);
    std::memset(source.get(), '\0', 2 * size + 1);
    std::memset(dest.get(), '\0', size + 1);
    std::memcpy(source.get(), reply.m_data.GetData(), 2 * size);

    [](const std::uint8_t* src, std::uint8_t* dst) {
        const auto char_to_int = [](std::uint8_t input) -> int {
            if(input >= '0' && input <= '9')
                return input - '0';
            if(input >= 'A' && input <= 'F')
                return input - 'A' + 10;
            if(input >= 'a' && input <= 'f')
                return input - 'a' + 10;
            return 0;
        };

        while(*src && src[1]) {
            *(dst++) = char_to_int(*src) * 16 + char_to_int(src[1]);
            src += 2;
        }
    }(source.get(), dest.get());

    return DataBuffer(dest.get(), size);
}


bool EsrevenAdapter::WriteMemory(std::uintptr_t address, const DataBuffer& buffer)
{
    if (m_isTargetRunning)
        return false;

    size_t size = buffer.GetLength();
	DataBuffer dest(2 * size);

    for ( std::size_t index{}; index < size; index++ )
	{
		// Feel free to write it in a more elegant way...
		std::string hex = fmt::format("{:02X}", buffer[index]);
		dest[2 * index] = hex[0];
		dest[2 * index + 1] = hex[1];
	}

    auto reply = this->m_rspConnector->TransmitAndReceive(RspData("M{:x},{:x}:{}", address, size, dest.ToEscapedString()));
    if (reply.AsString() != "OK")
        return false;

    return true;
}


std::string EsrevenAdapter::GetRemoteFile(const std::string& path)
{
    if (m_isTargetRunning || !m_rspConnector)
        return "";

    RspData output;
    int32_t error;
    int32_t ret = this->m_rspConnector->HostFileIO(RspData("vFile:setfs:0"), output, error);
    if (ret < 0)
    {
	    LogDebug("Could not set remote filesystem");
    	return "";
    }

    std::string path_hex_string{};
    for ( const auto& ch : path )
        path_hex_string += fmt::format("{:02X}", ch);

    ret = this->m_rspConnector->HostFileIO(
                    RspData("vFile:open:{},{:X},{:X}", path_hex_string.c_str(), 0, 0), output, error);
    if (ret < 0)
    {
	    LogDebug("Unable to open file with host I/O");
    	return "";
    }

    int32_t fd = ret;

    std::string data;
    size_t offset = 0;
    const size_t blockSize = 1024;

    while(true)
    {
        ret = this->m_rspConnector->HostFileIO(
                    RspData("vFile:pread:{:X},{:X},{:X}", fd, blockSize, offset), output, error);
        if (ret < 0)
        {
        	auto msg = fmt::format("host i/o pread() failed, result={}, errno={}", ret, error);
	        LogDebug("%s", msg.c_str());
        	return data;
        }
        if (ret == 0)
            // EOF
            break;

        if (ret != (int32_t)output.AsString().length())
        {
        	auto msg = fmt::format("host i/o pread() returned {:X} but decoded binary attachment is size {:X}",
					ret, output.AsString().length());
	        LogDebug("%s", msg.c_str());
        	return data;
        }

        data += output.AsString();
        offset += output.AsString().length();
    }

    ret = this->m_rspConnector->HostFileIO(RspData(fmt::format("vFile:close:{:X}", fd)), output, error);
    if (ret)
    {
    	auto msg = fmt::format("host i/o close() failed, result={}, errno={}", ret, error);
	    LogDebug("%s", msg.c_str());
	    return data;
    }

    return data;
}

std::vector<DebugModule> EsrevenAdapter::GetModuleList()
{
	if (m_moduleCache.has_value())
		return m_moduleCache.value();

	if (m_isTargetRunning)
		return {};

	if (!m_rspConnector)
		return {};

	// Use the custom reven list-current-mappings packet
	// Request all mappings (process, kernel, etc.)
	auto response = m_rspConnector->TransmitAndReceive(RspData("rvn:list-current-mappings:all"));
	std::string jsonStr = response.AsString();

	// Check if we got a valid JSON response
	if (jsonStr.empty() || jsonStr[0] != '[')
		return {};

	std::vector<DebugModule> result;

	// Simple JSON parser for the specific format
	size_t pos = 0;
	while (pos < jsonStr.length())
	{
		// Find the start of an object
		size_t objStart = jsonStr.find('{', pos);
		if (objStart == std::string::npos)
			break;

		// Find the end of the object (need to handle nested sections array)
		int braceCount = 0;
		size_t objEnd = objStart;
		for (size_t i = objStart; i < jsonStr.length(); i++)
		{
			if (jsonStr[i] == '{')
				braceCount++;
			else if (jsonStr[i] == '}')
			{
				braceCount--;
				if (braceCount == 0)
				{
					objEnd = i;
					break;
				}
			}
		}

		if (objEnd == objStart)
			break;

		std::string objStr = jsonStr.substr(objStart, objEnd - objStart + 1);

		// Parse the fields
		DebugModule module;
		module.m_loaded = true;

		// Extract "name"
		size_t nameStart = objStr.find("\"name\"");
		if (nameStart != std::string::npos)
		{
			size_t valueStart = objStr.find(':', nameStart);
			if (valueStart != std::string::npos)
			{
				valueStart = objStr.find('"', valueStart);
				if (valueStart != std::string::npos)
				{
					size_t valueEnd = objStr.find('"', valueStart + 1);
					if (valueEnd != std::string::npos)
					{
						module.m_short_name = objStr.substr(valueStart + 1, valueEnd - valueStart - 1);
					}
				}
			}
		}

		// Extract "path"
		size_t pathStart = objStr.find("\"path\"");
		if (pathStart != std::string::npos)
		{
			size_t valueStart = objStr.find(':', pathStart);
			if (valueStart != std::string::npos)
			{
				valueStart = objStr.find('"', valueStart);
				if (valueStart != std::string::npos)
				{
					size_t valueEnd = objStr.find('"', valueStart + 1);
					if (valueEnd != std::string::npos)
					{
						module.m_name = objStr.substr(valueStart + 1, valueEnd - valueStart - 1);
					}
				}
			}
		}

		// Extract "base_address"
		size_t baseAddrStart = objStr.find("\"base_address\"");
		if (baseAddrStart != std::string::npos)
		{
			size_t valueStart = objStr.find(':', baseAddrStart);
			if (valueStart != std::string::npos)
			{
				valueStart++;
				while (valueStart < objStr.length() && std::isspace(objStr[valueStart]))
					valueStart++;

				size_t valueEnd = valueStart;
				while (valueEnd < objStr.length() && std::isdigit(objStr[valueEnd]))
					valueEnd++;

				if (valueEnd > valueStart)
				{
					module.m_address = std::stoull(objStr.substr(valueStart, valueEnd - valueStart));
				}
			}
		}

		// Extract sections array to calculate module size
		size_t sectionsStart = objStr.find("\"sections\"");
		if (sectionsStart != std::string::npos)
		{
			size_t arrayStart = objStr.find('[', sectionsStart);
			if (arrayStart != std::string::npos)
			{
				size_t arrayEnd = objStr.find(']', arrayStart);
				if (arrayEnd != std::string::npos)
				{
					std::string sectionsStr = objStr.substr(arrayStart, arrayEnd - arrayStart + 1);

					uint64_t minAddr = UINT64_MAX;
					uint64_t maxEnd = 0;

					// Parse each section
					size_t sectionPos = 0;
					while (sectionPos < sectionsStr.length())
					{
						size_t sectionObjStart = sectionsStr.find('{', sectionPos);
						if (sectionObjStart == std::string::npos)
							break;

						size_t sectionObjEnd = sectionsStr.find('}', sectionObjStart);
						if (sectionObjEnd == std::string::npos)
							break;

						std::string sectionObjStr = sectionsStr.substr(sectionObjStart, sectionObjEnd - sectionObjStart + 1);

						uint64_t sectionAddr = 0;
						uint64_t sectionSize = 0;

						// Extract "address"
						size_t addrStart = sectionObjStr.find("\"address\"");
						if (addrStart != std::string::npos)
						{
							size_t valStart = sectionObjStr.find(':', addrStart);
							if (valStart != std::string::npos)
							{
								valStart++;
								while (valStart < sectionObjStr.length() && std::isspace(sectionObjStr[valStart]))
									valStart++;

								size_t valEnd = valStart;
								while (valEnd < sectionObjStr.length() && std::isdigit(sectionObjStr[valEnd]))
									valEnd++;

								if (valEnd > valStart)
									sectionAddr = std::stoull(sectionObjStr.substr(valStart, valEnd - valStart));
							}
						}

						// Extract "size"
						size_t sizeStart = sectionObjStr.find("\"size\"");
						if (sizeStart != std::string::npos)
						{
							size_t valStart = sectionObjStr.find(':', sizeStart);
							if (valStart != std::string::npos)
							{
								valStart++;
								while (valStart < sectionObjStr.length() && std::isspace(sectionObjStr[valStart]))
									valStart++;

								size_t valEnd = valStart;
								while (valEnd < sectionObjStr.length() && std::isdigit(sectionObjStr[valEnd]))
									valEnd++;

								if (valEnd > valStart)
									sectionSize = std::stoull(sectionObjStr.substr(valStart, valEnd - valStart));
							}
						}

						if (sectionAddr > 0)
						{
							minAddr = std::min(minAddr, sectionAddr);
							maxEnd = std::max(maxEnd, sectionAddr + sectionSize);
						}

						sectionPos = sectionObjEnd + 1;
					}

					if (minAddr != UINT64_MAX && maxEnd > minAddr)
					{
						module.m_size = maxEnd - minAddr;
					}
				}
			}
		}

		if (!module.m_name.empty() && module.m_address != 0)
			result.push_back(module);

		pos = objEnd + 1;
	}

	m_moduleCache = result;
	return result;
}


std::vector<TTDMemoryEvent> EsrevenAdapter::GetTTDMemoryAccessForAddress(uint64_t startAddress, uint64_t endAddress, TTDMemoryAccessType accessType)
{
	if (m_isTargetRunning)
		return {};

	if (!m_rspConnector)
		return {};

	// Convert TTDMemoryAccessType flags to comma-separated string
	std::vector<std::string> types;
	if (accessType & TTDMemoryRead)
		types.push_back("read");
	if (accessType & TTDMemoryWrite)
		types.push_back("write");
	if (accessType & TTDMemoryExecute)
		types.push_back("execute");

	if (types.empty())
		return {};

	std::string typesStr;
	for (size_t i = 0; i < types.size(); i++)
	{
		if (i > 0)
			typesStr += ",";
		typesStr += types[i];
	}

	// Send the custom REVEN packet: rvn:get-memory-accesses:<start>:<end>:<types>
	auto response = m_rspConnector->TransmitAndReceive(
		RspData("rvn:get-memory-accesses:{:x}:{:x}:{}", startAddress, endAddress, typesStr));
	std::string jsonStr = response.AsString();

	// Check if we got a valid JSON array response
	if (jsonStr.empty() || jsonStr[0] != '[')
		return {};

	std::vector<TTDMemoryEvent> result;

	// Simple JSON parser for array of memory access objects
	size_t pos = 0;
	while (pos < jsonStr.length())
	{
		// Find the start of an object
		size_t objStart = jsonStr.find('{', pos);
		if (objStart == std::string::npos)
			break;

		// Find the end of the object
		size_t objEnd = jsonStr.find('}', objStart);
		if (objEnd == std::string::npos)
			break;

		std::string objStr = jsonStr.substr(objStart, objEnd - objStart + 1);

		TTDMemoryEvent event;
		event.eventType = "MemoryAccess";

		// Helper lambda to extract uint64_t value from JSON
		auto extractUInt64 = [](const std::string& json, const std::string& key) -> uint64_t {
			size_t keyPos = json.find("\"" + key + "\"");
			if (keyPos == std::string::npos)
				return 0;

			size_t colonPos = json.find(':', keyPos);
			if (colonPos == std::string::npos)
				return 0;

			// Skip whitespace after colon
			size_t valueStart = colonPos + 1;
			while (valueStart < json.length() && std::isspace(json[valueStart]))
				valueStart++;

			// Check if value is null
			if (json.substr(valueStart, 4) == "null")
				return 0;

			// Find end of number (comma, closing brace, or whitespace)
			size_t valueEnd = valueStart;
			while (valueEnd < json.length() &&
				   std::isdigit(json[valueEnd]))
				valueEnd++;

			if (valueEnd > valueStart)
			{
				std::string valueStr = json.substr(valueStart, valueEnd - valueStart);
				return std::stoull(valueStr);
			}
			return 0;
		};

		// Helper lambda to extract string value from JSON
		auto extractString = [](const std::string& json, const std::string& key) -> std::string {
			size_t keyPos = json.find("\"" + key + "\"");
			if (keyPos == std::string::npos)
				return "";

			size_t colonPos = json.find(':', keyPos);
			if (colonPos == std::string::npos)
				return "";

			size_t valueStart = json.find('"', colonPos);
			if (valueStart == std::string::npos)
				return "";

			size_t valueEnd = json.find('"', valueStart + 1);
			if (valueEnd == std::string::npos)
				return "";

			return json.substr(valueStart + 1, valueEnd - valueStart - 1);
		};

		// Extract fields from JSON
		uint64_t transitionId = extractUInt64(objStr, "transition_id");
		event.address = extractUInt64(objStr, "address");
		event.memoryAddress = event.address;  // Same as address
		event.size = extractUInt64(objStr, "size");
		event.instructionAddress = extractUInt64(objStr, "instruction_address");
		event.value = extractUInt64(objStr, "value");

		// Extract thread_id (may be null)
		event.threadId = static_cast<uint32_t>(extractUInt64(objStr, "thread_id"));
		event.uniqueThreadId = event.threadId;

		// Convert transition_id to TTDPosition (use as sequence, step=0)
		event.timeStart = TTDPosition(transitionId, 0);
		event.timeEnd = event.timeStart;

		// Extract and convert access_type string to enum
		std::string accessTypeStr = extractString(objStr, "access_type");
		if (accessTypeStr == "read")
			event.accessType = TTDMemoryRead;
		else if (accessTypeStr == "write")
			event.accessType = TTDMemoryWrite;
		else if (accessTypeStr == "execute")
			event.accessType = TTDMemoryExecute;
		else
			event.accessType = TTDMemoryRead;  // Default

		result.push_back(event);

		pos = objEnd + 1;
	}

	return result;
}


std::vector<TTDPositionRangeIndexedMemoryEvent> EsrevenAdapter::GetTTDMemoryAccessForPositionRange(
	uint64_t startAddress, uint64_t endAddress, TTDMemoryAccessType accessType,
	const TTDPosition startTime, const TTDPosition endTime)
{
	if (m_isTargetRunning)
		return {};

	if (!m_rspConnector)
		return {};

	// Convert TTDMemoryAccessType flags to comma-separated string
	std::vector<std::string> types;
	if (accessType & TTDMemoryRead)
		types.push_back("read");
	if (accessType & TTDMemoryWrite)
		types.push_back("write");
	if (accessType & TTDMemoryExecute)
		types.push_back("execute");

	if (types.empty())
		return {};

	std::string typesStr;
	for (size_t i = 0; i < types.size(); i++)
	{
		if (i > 0)
			typesStr += ",";
		typesStr += types[i];
	}

	// TTDPosition.sequence maps to REVEN transition_id (step is always 0 in REVEN)
	uint64_t startTransition = startTime.sequence;
	uint64_t endTransition = endTime.sequence;

	// Send the custom REVEN packet with time range: rvn:get-memory-accesses:<start>:<end>:<types>:<start_trans>:<end_trans>
	auto response = m_rspConnector->TransmitAndReceive(
		RspData("rvn:get-memory-accesses:{:x}:{:x}:{}:{}:{}",
			startAddress, endAddress, typesStr, startTransition, endTransition));
	std::string jsonStr = response.AsString();

	// Check if we got a valid JSON array response
	if (jsonStr.empty() || jsonStr[0] != '[')
		return {};

	std::vector<TTDPositionRangeIndexedMemoryEvent> result;

	// Simple JSON parser for array of memory access objects
	size_t pos = 0;
	while (pos < jsonStr.length())
	{
		// Find the start of an object
		size_t objStart = jsonStr.find('{', pos);
		if (objStart == std::string::npos)
			break;

		// Find the end of the object
		size_t objEnd = jsonStr.find('}', objStart);
		if (objEnd == std::string::npos)
			break;

		std::string objStr = jsonStr.substr(objStart, objEnd - objStart + 1);

		TTDPositionRangeIndexedMemoryEvent event;

		// Helper lambda to extract uint64_t value from JSON
		auto extractUInt64 = [](const std::string& json, const std::string& key) -> uint64_t {
			size_t keyPos = json.find("\"" + key + "\"");
			if (keyPos == std::string::npos)
				return 0;

			size_t colonPos = json.find(':', keyPos);
			if (colonPos == std::string::npos)
				return 0;

			// Skip whitespace after colon
			size_t valueStart = colonPos + 1;
			while (valueStart < json.length() && std::isspace(json[valueStart]))
				valueStart++;

			// Check if value is null
			if (json.substr(valueStart, 4) == "null")
				return 0;

			// Find end of number
			size_t valueEnd = valueStart;
			while (valueEnd < json.length() && std::isdigit(json[valueEnd]))
				valueEnd++;

			if (valueEnd > valueStart)
			{
				std::string valueStr = json.substr(valueStart, valueEnd - valueStart);
				return std::stoull(valueStr);
			}
			return 0;
		};

		// Helper lambda to extract string value from JSON
		auto extractString = [](const std::string& json, const std::string& key) -> std::string {
			size_t keyPos = json.find("\"" + key + "\"");
			if (keyPos == std::string::npos)
				return "";

			size_t colonPos = json.find(':', keyPos);
			if (colonPos == std::string::npos)
				return "";

			size_t valueStart = json.find('"', colonPos);
			if (valueStart == std::string::npos)
				return "";

			size_t valueEnd = json.find('"', valueStart + 1);
			if (valueEnd == std::string::npos)
				return "";

			return json.substr(valueStart + 1, valueEnd - valueStart - 1);
		};

		// Extract fields from JSON
		uint64_t transitionId = extractUInt64(objStr, "transition_id");
		event.address = extractUInt64(objStr, "address");
		event.size = extractUInt64(objStr, "size");
		event.instructionAddress = extractUInt64(objStr, "instruction_address");
		event.value = extractUInt64(objStr, "value");

		// Extract thread_id (may be null)
		event.threadId = static_cast<uint32_t>(extractUInt64(objStr, "thread_id"));
		event.uniqueThreadId = event.threadId;

		// Convert transition_id to TTDPosition (use as sequence, step=0)
		event.position = TTDPosition(transitionId, 0);

		// Extract and convert access_type string to enum
		std::string accessTypeStr = extractString(objStr, "access_type");
		if (accessTypeStr == "read")
			event.accessType = TTDMemoryRead;
		else if (accessTypeStr == "write")
			event.accessType = TTDMemoryWrite;
		else if (accessTypeStr == "execute")
			event.accessType = TTDMemoryExecute;
		else
			event.accessType = TTDMemoryRead;  // Default

		// Initialize data array (first 8 bytes at memory address)
		// REVEN doesn't provide this currently, so zero it out
		for (int i = 0; i < 8; i++)
			event.data[i] = 0;

		result.push_back(event);

		pos = objEnd + 1;
	}

	return result;
}


std::string EsrevenAdapter::GetTargetArchitecture()
{
	return m_remoteArch;
}

bool EsrevenAdapter::BreakInto()
{
	if (!m_isTargetRunning || !m_rspConnector)
		return false;

    char var = '\x03';
    this->m_rspConnector->SendRaw(RspData(&var, sizeof(var)));
    m_isTargetRunning = false;
    return true;
}


DebugStopReason EsrevenAdapter::ResponseHandler(bool notifyStopped)
{
	if (!m_rspConnector)
		return InternalError;

	while (true)
	{
		const RspData reply = m_rspConnector->ReceiveRspData();
		if (reply[0] == 'T')
		{
			// Target stopped
			auto map = RspConnector::PacketToUnorderedMap(reply);
			const auto tid = map["thread"];
			m_isTargetRunning = false;
            m_lastActiveThreadId = (uint32_t)tid;

			CheckApplyPendingBreakpoints();

			auto reason = SignalToStopReason(map);
			if (notifyStopped)
			{
				DebuggerEvent dbgevt;
				dbgevt.type = AdapterStoppedEventType;
				dbgevt.data.targetStoppedData.reason = reason;
				PostDebuggerEvent(dbgevt);
			}
            return reason;
		}
		else if (reply[0] == 'S')
		{
			// Target stopped with signal (equivalent to T response with no n:r pairs)
			const auto replyString = reply.AsString();
			if (replyString.length() >= 3)
			{
				std::string signalString = replyString.substr(1, 2);
				uint64_t signal = std::stoull(signalString, nullptr, 16);
				
				m_isTargetRunning = false;
				CheckApplyPendingBreakpoints();
				
				// Look up the signal using helper function
				DebugStopReason reason = SignalToDebugStopReason(signal);
				
				if (notifyStopped)
				{
					DebuggerEvent dbgevt;
					dbgevt.type = AdapterStoppedEventType;
					dbgevt.data.targetStoppedData.reason = reason;
					PostDebuggerEvent(dbgevt);
				}
				return reason;
			}
		}
		else if (reply[0] == 'W')
		{
			InvalidateCache();
			ClearCachedBreakpoints();

			// Target exited
			std::string exitCodeString = reply.AsString().substr(1);
			uint8_t exitCode = (uint8_t)strtoul(exitCodeString.c_str(), nullptr, 16);
			m_isTargetRunning = false;
            m_exitCode = exitCode;

			if (notifyStopped)
			{
				DebuggerEvent dbgevt;
				dbgevt.type = TargetExitedEventType;
				dbgevt.data.exitData.exitCode = m_exitCode;
				PostDebuggerEvent(dbgevt);
			}

			this->m_socket->Kill();
			m_isTargetRunning = false;

			if (m_rspConnector)
			{
				delete m_rspConnector;
				m_rspConnector = nullptr;
			}

            return DebugStopReason::ProcessExited;
			break;
		}
		else if (reply[0] == 'O')
		{
			// stdout message
			const auto string = reply.AsString();
			const auto message = string.substr(1);

			// These duplicate code in GdbAdapter::ReadMemory(). We should probably add a ParseFromHex() and EncodeAsHex()
			// to the RspData class.
			if (message.size() % 2 == 1)
                continue;

			size_t size = message.size() / 2;
			if (size == 0)
				continue;

			std::string result;
			result.resize(size);

			[](const std::uint8_t* src, std::uint8_t* dst) {
				const auto char_to_int = [](std::uint8_t input) -> int {
					if(input >= '0' && input <= '9')
						return input - '0';
					if(input >= 'A' && input <= 'F')
						return input - 'A' + 10;
					if(input >= 'a' && input <= 'f')
						return input - 'a' + 10;
					return 0;
				};

				while(*src && src[1]) {
					*(dst++) = char_to_int(*src) * 16 + char_to_int(src[1]);
					src += 2;
				}
			}((const std::uint8_t*)message.c_str(), (std::uint8_t*)result.c_str());

			if (notifyStopped)
			{
				DebuggerEvent event;
				event.type = StdoutMessageEventType;
				event.data.messageData.message = result;
				PostDebuggerEvent(event);
			}
		}
		else
		{
			LogWarn("Unexpected rsp response, \"%s\"", reply.AsString().c_str());
		}
	}
}


// this should return the information about the target stop
DebugStopReason EsrevenAdapter::GenericGo(const std::string& goCommand, bool notifyStopped)
{
	if (!m_rspConnector)
		return InternalError;

	m_isTargetRunning = true;
	// TODO: these two calls should be combined
	m_rspConnector->SendPayload(RspData(goCommand));
	m_rspConnector->ExpectAck();

	return ResponseHandler(notifyStopped);
}


// The return value only indicates whether the command is successfully sent
bool EsrevenAdapter::Go()
{
	DebuggerEvent dbgevt;
	dbgevt.type = ResumeEventType;
	PostDebuggerEvent(dbgevt);

	InvalidateCache();
	GenericGo("c");

	return true;
}


bool EsrevenAdapter::StepInto()
{
	DebuggerEvent dbgevt;
	dbgevt.type = ResumeEventType;
	PostDebuggerEvent(dbgevt);

	InvalidateCache();
	GenericGo("s");

	return true;
}


bool EsrevenAdapter::StepOver()
{
	DebuggerEvent dbgevt;
	dbgevt.type = ResumeEventType;
	PostDebuggerEvent(dbgevt);

	InvalidateCache();
	GenericGo("rvn:step-over");

	return true;
}


bool EsrevenAdapter::StepReturn()
{
	DebuggerEvent dbgevt;
	dbgevt.type = ResumeEventType;
	PostDebuggerEvent(dbgevt);

	InvalidateCache();
	GenericGo("rvn:step-out");

	return true;
}


// The return value only indicates whether the command is successfully sent
bool EsrevenAdapter::GoReverse()
{
	DebuggerEvent dbgevt;
	dbgevt.type = ResumeEventType;
	PostDebuggerEvent(dbgevt);

	InvalidateCache();
	GenericGo("bc");

	return true;
}


bool EsrevenAdapter::StepIntoReverse()
{
	DebuggerEvent dbgevt;
	dbgevt.type = ResumeEventType;
	PostDebuggerEvent(dbgevt);

	InvalidateCache();
	GenericGo("bs");

	return true;
}


bool EsrevenAdapter::StepOverReverse()
{
	DebuggerEvent dbgevt;
	dbgevt.type = ResumeEventType;
	PostDebuggerEvent(dbgevt);

	InvalidateCache();
	GenericGo("rvn:reverse-step-over");

	return true;
}

bool EsrevenAdapter::AddHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size)
{
	if (m_isTargetRunning || !m_rspConnector)
	{
		// Cache the hardware breakpoint to be applied when target stops or connector becomes available
		PendingHardwareBreakpoint pending(address, type, size);
		if (std::find(m_pendingHardwareBreakpoints.begin(), m_pendingHardwareBreakpoints.end(), pending)
			== m_pendingHardwareBreakpoints.end())
		{
			m_pendingHardwareBreakpoints.push_back(pending);
		}
		return true;
	}

	std::string command;
	switch (type)
	{
		case HardwareExecuteBreakpoint:
			// Z1 = hardware execution breakpoint
			command = fmt::format("Z1,{:x},{}", address, size);
			break;
		case HardwareReadBreakpoint:
			// Z3 = hardware read watchpoint
			command = fmt::format("Z3,{:x},{}", address, size);
			break;
		case HardwareWriteBreakpoint:
			// Z2 = hardware write watchpoint
			command = fmt::format("Z2,{:x},{}", address, size);
			break;
		case HardwareAccessBreakpoint:
			// Z4 = hardware access watchpoint (read/write)
			command = fmt::format("Z4,{:x},{}", address, size);
			break;
		default:
			return false;
	}

	return m_rspConnector->TransmitAndReceive(RspData(command)).AsString() == "OK";
}


bool EsrevenAdapter::RemoveHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size)
{
	if (m_isTargetRunning || !m_rspConnector)
	{
		// Remove from pending list if target is running or connector not available
		PendingHardwareBreakpoint pending(address, type, size);
		auto it = std::find(m_pendingHardwareBreakpoints.begin(), m_pendingHardwareBreakpoints.end(), pending);
		if (it != m_pendingHardwareBreakpoints.end())
		{
			m_pendingHardwareBreakpoints.erase(it);
			return true;
		}
		return false;
	}

	std::string command;
	switch (type)
	{
		case HardwareExecuteBreakpoint:
			// z1 = remove hardware execution breakpoint
			command = fmt::format("z1,{:x},{}", address, size);
			break;
		case HardwareReadBreakpoint:
			// z3 = remove hardware read watchpoint
			command = fmt::format("z3,{:x},{}", address, size);
			break;
		case HardwareWriteBreakpoint:
			// z2 = remove hardware write watchpoint
			command = fmt::format("z2,{:x},{}", address, size);
			break;
		case HardwareAccessBreakpoint:
			// z4 = remove hardware access watchpoint (read/write)
			command = fmt::format("z4,{:x},{}", address, size);
			break;
		default:
			return false;
	}

	return m_rspConnector->TransmitAndReceive(RspData(command)).AsString() == "OK";
}


bool EsrevenAdapter::AddHardwareBreakpoint(const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size)
{
	uint64_t base{};
	if (GetModuleBase(location.module, base))
	{
		// Module is loaded - resolve to absolute address and delegate
		uint64_t address = base + location.offset;
		return AddHardwareBreakpoint(address, type, size);
	}
	else
	{
		// Module not loaded yet - add to pending list with module+offset
		PendingHardwareBreakpoint pending(location, type, size);
		// Also populate the address field for UI display purposes
		pending.address = location.offset + m_originalImageBase;
		if (std::find(m_pendingHardwareBreakpoints.begin(), m_pendingHardwareBreakpoints.end(), pending)
			== m_pendingHardwareBreakpoints.end())
		{
			m_pendingHardwareBreakpoints.push_back(pending);
		}
		return true;
	}
}


bool EsrevenAdapter::RemoveHardwareBreakpoint(const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size)
{
	uint64_t base{};
	if (GetModuleBase(location.module, base))
	{
		// Module is loaded - resolve to absolute address and delegate
		uint64_t address = base + location.offset;
		return RemoveHardwareBreakpoint(address, type, size);
	}
	else
	{
		// Module not loaded yet - remove from pending list using module+offset
		PendingHardwareBreakpoint pending(location, type, size);
		auto it = std::find(m_pendingHardwareBreakpoints.begin(), m_pendingHardwareBreakpoints.end(), pending);
		if (it != m_pendingHardwareBreakpoints.end())
		{
			m_pendingHardwareBreakpoints.erase(it);
			return true;
		}
		return false;
	}
}


bool EsrevenAdapter::AddHardwareWriteBreakpoint(uint64_t address)
{
	// Delegate to new standardized method
	return AddHardwareBreakpoint(address, HardwareWriteBreakpoint, 1);
}

bool EsrevenAdapter::RemoveHardwareWriteBreakpoint(uint64_t address)
{
	// Delegate to new standardized method
	return RemoveHardwareBreakpoint(address, HardwareWriteBreakpoint, 1);
}

bool EsrevenAdapter::StepReturnReverse()
{
	DebuggerEvent dbgevt;
	dbgevt.type = ResumeEventType;
	PostDebuggerEvent(dbgevt);

	InvalidateCache();
	GenericGo("rvn:reverse-step-out");

	return true;
}


std::string EsrevenAdapter::InvokeBackendCommand(const std::string& command)
{
	if (!m_rspConnector)
		return {};

	if (command.substr(0, 4) == "mon ")
		return RunMonitorCommand(command.substr(4));
	else if (command.substr(0, 8) == "monitor ")
		return RunMonitorCommand(command.substr(8));

	// Hardware breakpoint help
	if (command == "hwhelp" || command == "hhelp")
	{
		return "Hardware breakpoint commands:\n"
			"  hb <addr>   - Set hardware execute breakpoint\n"
			"  hw <addr>   - Set hardware write watchpoint\n"
			"  hr <addr>   - Set hardware read watchpoint\n"
			"  ha <addr>   - Set hardware access watchpoint\n"
			"  dhb <addr>  - Delete hardware execute breakpoint\n"
			"  dhw <addr>  - Delete hardware write watchpoint\n"
			"  dhr <addr>  - Delete hardware read watchpoint\n"
			"  dha <addr>  - Delete hardware access watchpoint\n"
			"\n"
			"Address can be in hex (0x...) or decimal format.\n"
			"Note: These are temporary workarounds for hardware breakpoint support.";
	}

	// Hardware breakpoint commands
	// Format: hb <addr>, hw <addr>, hr <addr>, ha <addr>
	// Delete: dhb <addr>, dhw <addr>, dhr <addr>, dha <addr>

	std::string addrStr;
	bool isDelete = false;
	int bpType = -1;  // 1=execute, 2=write, 3=read, 4=access

	if (command.substr(0, 4) == "dhb ")
	{
		isDelete = true;
		bpType = 1;
		addrStr = command.substr(4);
	}
	else if (command.substr(0, 4) == "dhw ")
	{
		isDelete = true;
		bpType = 2;
		addrStr = command.substr(4);
	}
	else if (command.substr(0, 4) == "dhr ")
	{
		isDelete = true;
		bpType = 3;
		addrStr = command.substr(4);
	}
	else if (command.substr(0, 4) == "dha ")
	{
		isDelete = true;
		bpType = 4;
		addrStr = command.substr(4);
	}
	else if (command.substr(0, 3) == "hb ")
	{
		bpType = 1;
		addrStr = command.substr(3);
	}
	else if (command.substr(0, 3) == "hw ")
	{
		bpType = 2;
		addrStr = command.substr(3);
	}
	else if (command.substr(0, 3) == "hr ")
	{
		bpType = 3;
		addrStr = command.substr(3);
	}
	else if (command.substr(0, 3) == "ha ")
	{
		bpType = 4;
		addrStr = command.substr(3);
	}

	if (bpType != -1)
	{
		// Parse address
		uint64_t address;
		try
		{
			// Support both hex (0x...) and decimal
			if (addrStr.substr(0, 2) == "0x" || addrStr.substr(0, 2) == "0X")
				address = std::stoull(addrStr, nullptr, 16);
			else
				address = std::stoull(addrStr, nullptr, 0);
		}
		catch (...)
		{
			return "Error: Invalid address format. Use hex (0x...) or decimal.";
		}

		// Determine kind (size) based on architecture
		size_t kind = 1;
		if (m_remoteArch == "aarch64")
			kind = 4;
		// TODO: Add other architectures as needed

		// Send the appropriate Z/z packet
		char zChar = isDelete ? 'z' : 'Z';
		auto reply = m_rspConnector->TransmitAndReceive(RspData("{}{},{:x},{}",
			zChar, bpType, address, kind));

		if (reply.AsString() == "OK")
		{
			const char* typeNames[] = {"", "hardware execute breakpoint",
				"hardware write watchpoint", "hardware read watchpoint",
				"hardware access watchpoint"};
			return fmt::format("{} {} at 0x{:x}",
				isDelete ? "Removed" : "Set",
				typeNames[bpType],
				address);
		}
		else
		{
			return fmt::format("Error: Failed to {} hardware breakpoint (response: {})",
				isDelete ? "remove" : "set",
				reply.AsString());
		}
	}

	auto reply = this->m_rspConnector->TransmitAndReceive(RspData(command));
	return reply.AsString();
}


// Function to convert hex string to ASCII string
static std::string HexToAscii(const std::string& hex)
{
	std::string ascii;

	// Ensure the hex string has an even number of characters
	if (hex.length() % 2 != 0)
	{
		std::cerr << "Invalid hex string length!" << std::endl;
		return "";
	}

	// Process the hex string two characters at a time
	for (size_t i = 0; i < hex.length(); i += 2)
	{
		// Convert the two hex characters to a byte (using a stringstream)
		std::string byte_string = hex.substr(i, 2);
		unsigned char byte = static_cast<unsigned char>(std::stoi(byte_string, nullptr, 16));  // Convert to byte

		// Append the byte (ASCII char) to the resulting string
		ascii.push_back(byte);
	}

	return ascii;
}


std::string EsrevenAdapter::RunMonitorCommand(const std::string& command)
{
	if (!m_rspConnector)
		return {};

	std::string commandToSend = "qRcmd,";
	for (const auto& c: command)
	{
		commandToSend += ("0123456789abcdef"[(c >> 4) & 0x0F]);
		commandToSend += ("0123456789abcdef"[c & 0x0F]);
	}

	m_rspConnector->SendPayload(RspData(commandToSend));
	m_rspConnector->ExpectAck();

	std::string result;
	while (true)
	{
		auto replyChunk = this->m_rspConnector->ReceiveRspData();
		if (replyChunk.AsString() == "OK" || replyChunk.AsString().empty())
			break;

		if (replyChunk.m_data[0] != 'O')
			break;

        result += HexToAscii(replyChunk.AsString().erase(0, 1));
	}

	return result;
}


uint64_t EsrevenAdapter::GetInstructionOffset()
{
    // TODO: obviously this will only support x86/x86_64, so we need a more systematic way for it
    std::string ipRegisterName = "";
    if ((m_remoteArch == "x86") || (m_remoteArch == "i386"))
        ipRegisterName = "eip";
    else if (m_remoteArch == "x86_64")
        ipRegisterName = "rip";
    else if ((m_remoteArch == "aarch64") || (m_remoteArch == "arm64"))
        ipRegisterName = "pc";
    else
        ipRegisterName = "pc";

    uint64_t value = (uint64_t)this->ReadRegister(ipRegisterName).m_value;
    return value;
}

uint64_t EsrevenAdapter::GetStackPointer()
{
	// TODO: obviously this will only support x86/x86_64, so we need a more systematic way for it
	std::string ipRegisterName = "";
	if ((m_remoteArch == "x86") || (m_remoteArch == "i386"))
		ipRegisterName = "esp";
	else if (m_remoteArch == "x86_64")
		ipRegisterName = "rsp";
	else if ((m_remoteArch == "aarch64") || (m_remoteArch == "arm64"))
		ipRegisterName = "sp";
	else
		ipRegisterName = "sp";

	uint64_t value = (uint64_t)this->ReadRegister(ipRegisterName).m_value;
	return value;
}


std::uint32_t EsrevenAdapter::GetActivePID()
{
	return m_processPid;
}


DebugStopReason EsrevenAdapter::StopReason()
{
    return this->m_lastStopReason;
}


bool EsrevenAdapter::SupportFeature(DebugAdapterCapacity feature)
{
    switch (feature)
    {
    case DebugAdapterSupportStepOver:
        return false;
    case DebugAdapterSupportStepOverReverse:
    	return true;
    case DebugAdapterSupportModules:
        return true;
    case DebugAdapterSupportThreads:
        return true;
    case DebugAdapterSupportTTD:
    {
        bool ttdSupported = m_canReverseContinue && m_canReverseStep;
        LogInfo("SupportFeature(DebugAdapterSupportTTD): m_canReverseContinue=%d, m_canReverseStep=%d, returning %d",
            m_canReverseContinue, m_canReverseStep, ttdSupported);
        return ttdSupported;
    }
    default:
        return false;
    }
}


void EsrevenAdapter::InvalidateCache()
{
	m_regCache.reset();
	m_moduleCache.reset();
	m_threadCache.reset();
}


DebugStopReason EsrevenAdapter::SignalToStopReason(std::unordered_map<std::string, std::uint64_t>& map)
{
	if (map.find("signal") != map.end())
	{
		uint64_t signal = map["signal"];
		if ((signal == 5) && (map.find("swbreak") != map.end()))
		{
			return DebugStopReason::Breakpoint;
		}
		else
		{
			return SignalToDebugStopReason(signal);
		}
	}

    return DebugStopReason::UnknownReason;
}


void EsrevenAdapter::HandleAsyncPacket(const RspData& data)
{
    if ( data.m_data[0] != 'O' )
        return;

    const auto string = data.AsString();
    const auto message = string.substr(1);

	// These duplicate code in EsrevenAdapter::ReadMemory(). We should probably add a ParseFromHex() and EncodeAsHex()
	// to the RspData class.
	if (message.size() % 2 == 1)
		return;

	size_t size = message.size() / 2;
	if (size == 0)
		return;

	std::string result;
	result.resize(size);

	[](const std::uint8_t* src, std::uint8_t* dst) {
		const auto char_to_int = [](std::uint8_t input) -> int {
			if(input >= '0' && input <= '9')
				return input - '0';
			if(input >= 'A' && input <= 'F')
				return input - 'A' + 10;
			if(input >= 'a' && input <= 'f')
				return input - 'a' + 10;
			return 0;
		};

		while(*src && src[1]) {
			*(dst++) = char_to_int(*src) * 16 + char_to_int(src[1]);
			src += 2;
		}
	}((const std::uint8_t*)message.c_str(), (std::uint8_t*)result.c_str());

	DebuggerEvent event;
	event.type = StdoutMessageEventType;
	event.data.messageData.message = result;
	PostDebuggerEvent(event);
}


std::vector<DebugProcess> EsrevenAdapter::GetProcessList()
{
	if (m_isTargetRunning)
		return {};

	// Use the custom reven list-processes packet
	auto response = m_rspConnector->TransmitAndReceive(RspData("rvn:list-processes"));
	std::string jsonStr = response.AsString();

	// Check if we got a valid JSON response
	if (jsonStr.empty() || jsonStr[0] != '[')
		return {};

	std::vector<DebugProcess> processes;

	// Simple JSON parser for the specific format: [{"name": "...", "pid": ..., "ppid": ...}, ...]
	size_t pos = 0;
	while (pos < jsonStr.length())
	{
		// Find the start of an object
		size_t objStart = jsonStr.find('{', pos);
		if (objStart == std::string::npos)
			break;

		// Find the end of the object
		size_t objEnd = jsonStr.find('}', objStart);
		if (objEnd == std::string::npos)
			break;

		std::string objStr = jsonStr.substr(objStart, objEnd - objStart + 1);

		// Parse the fields
		DebugProcess proc;

		// Extract "name"
		size_t nameStart = objStr.find("\"name\"");
		if (nameStart != std::string::npos)
		{
			size_t valueStart = objStr.find(':', nameStart);
			if (valueStart != std::string::npos)
			{
				valueStart = objStr.find('"', valueStart);
				if (valueStart != std::string::npos)
				{
					size_t valueEnd = objStr.find('"', valueStart + 1);
					if (valueEnd != std::string::npos)
					{
						proc.m_processName = objStr.substr(valueStart + 1, valueEnd - valueStart - 1);
					}
				}
			}
		}

		// Extract "pid"
		size_t pidStart = objStr.find("\"pid\"");
		if (pidStart != std::string::npos)
		{
			size_t valueStart = objStr.find(':', pidStart);
			if (valueStart != std::string::npos)
			{
				// Skip whitespace
				valueStart++;
				while (valueStart < objStr.length() && std::isspace(objStr[valueStart]))
					valueStart++;

				// Read the number
				size_t valueEnd = valueStart;
				while (valueEnd < objStr.length() && std::isdigit(objStr[valueEnd]))
					valueEnd++;

				if (valueEnd > valueStart)
				{
					proc.m_pid = std::stoul(objStr.substr(valueStart, valueEnd - valueStart));
				}
			}
		}

		// Extract "ppid"
		size_t ppidStart = objStr.find("\"ppid\"");
		if (ppidStart != std::string::npos)
		{
			size_t valueStart = objStr.find(':', ppidStart);
			if (valueStart != std::string::npos)
			{
				// Skip whitespace
				valueStart++;
				while (valueStart < objStr.length() && std::isspace(objStr[valueStart]))
					valueStart++;

				// Read the number
				size_t valueEnd = valueStart;
				while (valueEnd < objStr.length() && std::isdigit(objStr[valueEnd]))
					valueEnd++;

				if (valueEnd > valueStart)
				{
					// ppid is stored in the processName for now (as string representation)
					// This might need to be adjusted based on the DebugProcess structure
				}
			}
		}

		if (!proc.m_processName.empty())
			processes.push_back(proc);

		pos = objEnd + 1;
	}

	return processes;
}


bool EsrevenAdapter::SuspendThread(std::uint32_t tid)
{
	return false;
}


bool EsrevenAdapter::ResumeThread(std::uint32_t tid)
{
	return false;
}


bool EsrevenAdapter::GetModuleBase(const std::string &moduleName, uint64_t &base)
{
	if (moduleName.empty())
	{
		base = 0;
		return true;
	}

	auto modules = GetModuleList();
	for (const auto& module: modules)
	{
		if (module.IsSameBaseModule(moduleName))
		{
			base = module.m_address;
			return true;
		}
	}

	base = 0;
	return false;
}


DebugBreakpoint EsrevenAdapter::AddBreakpoint(const ModuleNameAndOffset& address, unsigned long breakpoint_type)
{
	uint64_t base{};
	if (GetModuleBase(address.module, base))
	{
		auto addr = base + address.offset;
		return AddBreakpoint(addr, breakpoint_type);
	}
	else
	{
		m_pendingBreakpoints.emplace_back(address, breakpoint_type);
		return {};
	}
}


void EsrevenAdapter::CheckApplyPendingBreakpoints()
{
	// Apply pending software breakpoints
	for (auto it = m_pendingBreakpoints.begin(); it != m_pendingBreakpoints.end(); )
	{
		uint64_t base{};
		if (GetModuleBase(it->address.module, base))
		{
			uint64_t addr = base + it->address.offset;
			// TODO: more robust check of whether the operation succeeds
			if (AddBreakpoint(addr, it->type).m_address != 0)
			{
				it = m_pendingBreakpoints.erase(it);
				continue;
			}
		}
		it++;
	}

	// Apply pending hardware breakpoints
	for (auto it = m_pendingHardwareBreakpoints.begin(); it != m_pendingHardwareBreakpoints.end(); )
	{
		bool success = false;
		if (it->isRelative)
		{
			// Module+offset based hardware breakpoint
			success = AddHardwareBreakpoint(it->location, it->type, it->size);
		}
		else
		{
			// Absolute address hardware breakpoint
			success = AddHardwareBreakpoint(it->address, it->type, it->size);
		}

		if (success)
		{
			it = m_pendingHardwareBreakpoints.erase(it);
		}
		else
		{
			it++;
		}
	}
}


EsrevenAdapterType::EsrevenAdapterType(): DebugAdapterType("esReven")
{

}


DebugAdapter* EsrevenAdapterType::Create(BinaryNinja::BinaryView *data)
{
	// TODO: someone should free this.
    return new EsrevenAdapter(data);
}


bool EsrevenAdapterType::IsValidForData(BinaryNinja::BinaryView *data)
{
//	it does not matter what the BinaryViewType is -- as long as we can connect to it, it is fine.
	return true;
}


bool EsrevenAdapterType::CanConnect(BinaryNinja::BinaryView *data)
{
//	We can connect to remote lldb on any host system
    return true;
}


bool EsrevenAdapterType::CanExecute(BinaryNinja::BinaryView *data)
{
    return false;
}

void BinaryNinjaDebugger::InitEsrevenAdapterType()
{
    static EsrevenAdapterType remoteType;
    DebugAdapterType::Register(&remoteType);
}


Ref<Settings> EsrevenAdapter::GetAdapterSettings()
{
	return EsrevenAdapterType::GetAdapterSettings();
}


void EsrevenAdapter::GenerateDefaultAdapterSettings(BinaryView* data)
{
	auto adapterSettings = GetAdapterSettings();
	BNSettingsScope scope = SettingsResourceScope;
	adapterSettings->Get<std::string>("common.inputFile", data, &scope);
	if (scope != SettingsResourceScope)
		adapterSettings->Set("common.inputFile", data->GetFile()->GetOriginalFilename(), data, SettingsResourceScope);

}


Ref<Settings> EsrevenAdapterType::RegisterAdapterSettings()
{
	Ref<Settings> settings = Settings::Instance("EsrevenAdapterSettings");
	settings->SetResourceId("esreven_adapter_settings");
	settings->RegisterSetting("common.inputFile",
		R"({
			"title" : "Input File",
			"type" : "string",
			"default" : "",
			"description" : "Input file to use to find the base address of the binary view",
			"readOnly" : false,
			"uiSelectionAction" : "file"
			})");

	settings->RegisterSetting("connect.ipAddress",
			R"({
			"title" : "IP Address",
			"type" : "string",
			"default" : "127.0.0.1",
			"description" : "IP address of the debug stub to connect to",
			"readOnly" : false
			})");
	settings->RegisterSetting("connect.port",
			R"({
			"title" : "Port",
			"type" : "number",
			"default" : 31337,
			"minValue" : 0,
			"maxValue" : 65535,
			"description" : "Port of the debug stub to connect to",
			"readOnly" : false
			})");

	settings->RegisterSetting("ttd.queryTimeout",
			R"JSON({
			"title" : "TTD Query Timeout",
			"type" : "number",
			"default" : 60000,
			"minValue" : 5000,
			"maxValue" : 600000,
			"description" : "Timeout in milliseconds for TTD query operations (calls, memory, events). Increase for large wildcard queries. Default: 60000ms (60s)",
			"readOnly" : false
			})JSON");

	settings->RegisterSetting("ttd.maxCallsQueryResults",
			R"JSON({
			"title" : "Max Calls Query Results",
			"type" : "number",
			"default" : 10000,
			"minValue" : 0,
			"maxValue" : 18446744073709551615,
			"description" : "Maximum number of results to return from TTD Calls queries. Set to 0 for no limit.",
			"readOnly" : false
			})JSON");

	settings->RegisterSetting("ttd.maxSymbolsLimit",
			R"JSON({
			"title" : "Max Symbols Wildcard Limit",
			"type" : "number",
			"default" : 50,
			"minValue" : 0,
			"maxValue" : 10000,
			"description" : "Maximum number of symbols to search when using wildcard patterns (e.g. 'kernel32!C*'). Set to 0 for no limit (searches all matching symbols). Increase for broader wildcard queries at the cost of performance.",
			"readOnly" : false
			})JSON");

	return settings;
}


TTDPosition EsrevenAdapter::GetCurrentTTDPosition()
{
	if (!m_rspConnector)
		return TTDPosition();

	auto reply = m_rspConnector->TransmitAndReceive(
		RspData("rvn:get-current-transition"), "ack_then_reply", nullptr,
		std::chrono::milliseconds(5000));

	std::string json = reply.AsString();

	if (json.empty() || json[0] == 'E')
		return TTDPosition();

	// Server returns JSON null when no transition is available
	if (json == "null" || json.empty())
		return TTDPosition();

	// Manual JSON extraction — no external library, same pattern as GetTTDCallsForSymbols
	std::string objectStr = json;
	auto extractUInt64 = [&objectStr](const std::string& fieldName) -> uint64_t {
		std::string searchStr = "\"" + fieldName + "\":";
		size_t pos = objectStr.find(searchStr);
		if (pos == std::string::npos)
			return 0;
		pos += searchStr.length();
		while (pos < objectStr.length() && std::isspace(objectStr[pos]))
			pos++;
		if (objectStr.substr(pos, 4) == "null")
			return 0;
		size_t end = pos;
		while (end < objectStr.length() && (std::isdigit(objectStr[end]) || objectStr[end] == '-'))
			end++;
		if (end > pos)
		{
			try { return std::stoull(objectStr.substr(pos, end - pos)); } catch (...) {}
		}
		return 0;
	};

	uint64_t transitionId = extractUInt64("transition_id");
	// TTDPosition: sequence = transition_id, step = 0 (REVEN has no sub-step granularity)
	return TTDPosition(transitionId, 0);
}


bool EsrevenAdapter::SetTTDPosition(const TTDPosition& position)
{
	if (!m_rspConnector)
		return false;

	DebuggerEvent dbgevt;
	dbgevt.type = ResumeEventType;
	PostDebuggerEvent(dbgevt);

	InvalidateCache();

	auto stopReason = GenericGo(fmt::format("rvn:set-current-transition:{}", position.sequence));
	return stopReason != InternalError;
}


std::vector<TTDCallEvent> EsrevenAdapter::GetTTDCallsForSymbols(const std::string& symbols, uint64_t startReturnAddress, uint64_t endReturnAddress)
{
	std::vector<TTDCallEvent> events;

	if (symbols.empty())
	{
		LogError("No symbols provided for TTD calls query");
		return events;
	}

	// Get settings
	auto adapterSettings = GetAdapterSettings();
	BNSettingsScope scope = SettingsResourceScope;
	auto timeoutMs = adapterSettings->Get<uint64_t>("ttd.queryTimeout", GetData(), &scope);
	auto maxResults = adapterSettings->Get<uint64_t>("ttd.maxCallsQueryResults", GetData(), &scope);
	auto maxSymbols = adapterSettings->Get<uint64_t>("ttd.maxSymbolsLimit", GetData(), &scope);
	auto timeout = std::chrono::milliseconds(timeoutMs);

	LogInfo("GetTTDCallsForSymbols: symbols='%s', timeout=%" PRIu64 "ms, maxResults=%" PRIu64 ", maxSymbols=%" PRIu64,
		symbols.c_str(), timeoutMs, maxResults, maxSymbols);

	try
	{
		// Detect wildcard patterns to add max_symbols limit
		bool isWildcard = (symbols.find('*') != std::string::npos) ||
						 (symbols.find('?') != std::string::npos);

		// Send rvn:get-calls-by-symbol packet with optional return address range and max_symbols
		// Format: rvn:get-calls-by-symbol:<symbol>[:<start_ret_addr>:<end_ret_addr>[:<max_symbols>]]
		std::string packet;
		if (startReturnAddress != 0 || endReturnAddress != 0)
		{
			// Include return address range for server-side filtering
			// maxSymbols == 0 means no limit: omit the suffix entirely
			packet = fmt::format("rvn:get-calls-by-symbol:{}:{:x}:{:x}{}",
				symbols,
				startReturnAddress != 0 ? startReturnAddress : 0,
				endReturnAddress != 0 ? endReturnAddress : 0xFFFFFFFFFFFFFFFF,
				(isWildcard && maxSymbols > 0) ? fmt::format(":{}", maxSymbols) : "");
		}
		else
		{
			// No filtering - query all calls
			// maxSymbols == 0 means no limit: omit :::N so the server searches all symbols
			packet = fmt::format("rvn:get-calls-by-symbol:{}{}",
				symbols,
				(isWildcard && maxSymbols > 0) ? fmt::format(":::{}", maxSymbols) : "");
		}

		// Send with custom timeout
		auto reply = m_rspConnector->TransmitAndReceive(
			RspData(packet),
			"ack_then_reply",
			nullptr,
			timeout  // Use configured timeout
		);

		// Check for error response
		if (reply.m_data[0] == 'E')
		{
			LogError("Failed to get calls for symbol: %s", symbols.c_str());
			return events;
		}

		std::string jsonData = reply.AsString();
		if (jsonData.empty() || jsonData == "[]")
		{
			return events;
		}

		// Manual JSON parsing (no external library dependency)
		// Expected format: [{"transition_id":...,"function_name":"...","function_address":...,"call_instruction_address":...,"return_address":...,"thread_id":...}, ...]

		size_t pos = 0;
		while ((pos = jsonData.find('{', pos)) != std::string::npos)
		{
			size_t endPos = jsonData.find('}', pos);
			if (endPos == std::string::npos)
				break;

			std::string objectStr = jsonData.substr(pos, endPos - pos + 1);

			// Helper lambda to extract uint64 field
			auto extractUInt64 = [&objectStr](const std::string& fieldName) -> uint64_t {
				std::string searchStr = "\"" + fieldName + "\":";
				size_t fieldPos = objectStr.find(searchStr);
				if (fieldPos == std::string::npos)
					return 0;

				fieldPos += searchStr.length();
				// Skip whitespace
				while (fieldPos < objectStr.length() && std::isspace(objectStr[fieldPos]))
					fieldPos++;

				// Check for null
				if (objectStr.substr(fieldPos, 4) == "null")
					return 0;

				// Extract number
				size_t endNum = fieldPos;
				while (endNum < objectStr.length() && (std::isdigit(objectStr[endNum]) || objectStr[endNum] == '-'))
					endNum++;

				if (endNum > fieldPos)
				{
					try {
						return std::stoull(objectStr.substr(fieldPos, endNum - fieldPos));
					} catch (...) {
						return 0;
					}
				}
				return 0;
			};

			// Helper lambda to extract string field
			auto extractString = [&objectStr](const std::string& fieldName) -> std::string {
				std::string searchStr = "\"" + fieldName + "\"";
				size_t fieldPos = objectStr.find(searchStr);
				if (fieldPos == std::string::npos)
					return "";

				fieldPos += searchStr.length();
				size_t colonPos = objectStr.find(':', fieldPos);
				if (colonPos == std::string::npos)
					return "";

				// Skip whitespace after colon (handles both `":"` and `": "`)
				size_t quotePos = colonPos + 1;
				while (quotePos < objectStr.length() && std::isspace(objectStr[quotePos]))
					quotePos++;

				if (quotePos >= objectStr.length() || objectStr[quotePos] != '"')
					return "";

				quotePos++; // skip opening quote
				size_t endQuote = objectStr.find('\"', quotePos);
				if (endQuote == std::string::npos)
					return "";

				return objectStr.substr(quotePos, endQuote - quotePos);
			};

			// Extract fields
			uint64_t transition_id = extractUInt64("transition_id");
			std::string function_name = extractString("function_name");
			uint64_t function_address = extractUInt64("function_address");
			uint64_t call_instruction_address = extractUInt64("call_instruction_address");
			uint64_t return_address = extractUInt64("return_address");
			uint64_t thread_id = extractUInt64("thread_id");

			// Note: Return address filtering is done server-side for performance

			// Create TTDCallEvent
			TTDCallEvent event;
			event.eventType = "Call";
			event.threadId = static_cast<uint32_t>(thread_id);
			event.uniqueThreadId = static_cast<uint32_t>(thread_id);
			event.function = function_name;
			event.functionAddress = function_address;
			event.returnAddress = return_address;
			event.returnValue = 0;
			event.hasReturnValue = false;
			event.timeStart = TTDPosition(transition_id, 0);
			event.timeEnd = TTDPosition(transition_id, 0);  // Same as timeStart for call events

			events.push_back(event);

			pos = endPos + 1;
		}

		LogInfo("Retrieved %zu call events for symbol: %s", events.size(), symbols.c_str());

		// Apply client-side result limiting (Option 2 pattern)
		if (maxResults > 0 && events.size() > maxResults)
		{
			LogWarn("Query returned %zu results, limiting to %" PRIu64, events.size(), maxResults);
			events.resize(maxResults);
		}
	}
	catch (const std::exception& e)
	{
		LogError("Exception while getting calls for symbol %s: %s", symbols.c_str(), e.what());
	}

	return events;
}

Ref<Settings> EsrevenAdapterType::GetAdapterSettings()
{
	static Ref<Settings> settings = RegisterAdapterSettings();
	return settings;
}
