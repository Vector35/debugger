/*
Copyright 2020-2025 Vector 35 Inc.

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
					register_info.m_regNum = lastRegIndex + 1;
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
		throw std::runtime_error("failed to find architecture");

	if (architecture.find(':') != std::string::npos)
	{
		architecture.erase(0, architecture.find(':') + 1);
		architecture.replace(architecture.find('-'), 1, "_");
	}
	m_remoteArch = architecture;

    std::unordered_map<std::uint32_t, std::string> id_name{};
    std::unordered_map<std::uint32_t, std::uint32_t> id_width{};

    for ( auto [key, value] : this->m_registerInfo ) {
        id_name[value.m_regNum] = key;
        id_width[value.m_regNum] = value.m_bitSize;
    }

    std::size_t max_id{};
    for ( auto [key, value] : this->m_registerInfo )
        max_id += value.m_regNum;

    std::size_t offset{};
    for ( std::size_t index{}; index < max_id; index++ ) {
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
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = inet_addr(ipAddress.c_str());
        address.sin_port = htons(serverPort);

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
	this->m_lastActiveThreadId = map["thread"];
	this->m_processPid = map["thread"];
    m_isTargetRunning = false;

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
	return {};

	// if (m_isTargetRunning || !m_rspConnector)
 //        return {};
 //
 //    std::vector<DebugThread> threads{};
 //
 //    auto reply = this->m_rspConnector->TransmitAndReceive(RspData("qfThreadInfo"));
 //    while(reply.m_data[0] != 'l') {
 //        if (reply.m_data[0] != 'm') {
	//         LogWarn("RSP thread list error");
 //        	return threads;
 //        }
 //
 //        const auto shortened_string =
 //                reply.AsString().substr(1);
 //        const auto tids = RspConnector::Split(shortened_string, ",");
 //        for ( const auto& tid : tids )
 //            threads.emplace_back(std::stoi(tid, nullptr, 16));
 //
 //        reply = this->m_rspConnector->TransmitAndReceive(RspData("qsThreadInfo"));
 //    }
 //
 //    return threads;
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
        throw std::runtime_error("thread does not exist!");

    if ( this->m_rspConnector->TransmitAndReceive(RspData(string("Hc{:x}"), tid)).AsString() != "OK")
        throw std::runtime_error("failed to set thread");

    if ( this->m_rspConnector->TransmitAndReceive(RspData(string("Hg{:x}"), tid)).AsString() != "OK")
        throw std::runtime_error("failed to set thread");

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

    const auto new_breakpoint = DebugBreakpoint(address, this->m_internalBreakpointId++, true);
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

std::unordered_map<std::string, DebugRegister> EsrevenAdapter::ReadAllRegisters()
{
	if (m_isTargetRunning || !m_rspConnector)
		return {};

	if (m_regCache.has_value())
		return m_regCache.value();

    if ( this->m_registerInfo.empty() )
        throw std::runtime_error("register info empty");

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
        throw std::runtime_error("register request reply empty");

    std::unordered_map<std::string, DebugRegister> all_regs{};
    for ( const auto& [register_name, register_info] : register_info_vec ) {
        const auto number_of_chars = 2 * ( register_info.m_bitSize / 8 );
        const auto value_string = register_info_reply_string.substr(0, number_of_chars);
    	if (!value_string.empty()) {
    		intx::uint512 value = parseLittleEndianHexToUint512(value_string);
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
        throw std::runtime_error(fmt::format("register {} does not exist in target", reg));

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

bool EsrevenAdapter::WriteRegister(const std::string& reg, intx::uint512 value)
{
    if (m_isTargetRunning || !m_rspConnector)
        return false;

	if (!this->m_registerInfo.contains(reg))
		return false;

	const auto newRegString = uint512ToLittleEndianHex(value, this->m_registerInfo[reg].m_bitSize / 8);
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
            throw std::invalid_argument("Invalid input string");
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
	return {};

	// if (m_moduleCache.has_value())
	// 	return m_moduleCache.value();
 //
 //    if (m_isTargetRunning)
 //        return {};
 //
 //    std::map<std::string, BNAddressRange> moduleRanges;
 //
 //    const auto path = "/proc/" + std::to_string(this->m_lastActiveThreadId) + "/maps";
 //    std::string data = GetRemoteFile(path);
	// if (data.empty())
	// 	return {};
 //
 //    for (const std::string& line: RspConnector::Split(data, "\n"))
 //    {
 //        std::string_view v = line;
 //        v.remove_prefix(std::min(v.find_first_not_of(" "), v.size()));
 //        auto trimPosition = v.find_last_not_of(" ");
 //        if (trimPosition != v.npos)
 //            v.remove_suffix(v.size() - trimPosition - 1);
 //
 //        // regex_match() requires the first argument to be const
 //        const std::string trimmedLine = std::string(v);
 //
 //        std::smatch match;
 //        const std::regex module_regex("^([0-9a-f]+)-([0-9a-f]+) [rwxp-]{4} .* (/.*)$");
 //        bool found = std::regex_match(trimmedLine, match, module_regex);
 //        if (found)
 //        {
 //            if (match.size() == 4) {
 //                std::string startString = match[1].str();
 //                uint64_t start = std::strtoull(startString.c_str(), nullptr, 16);
 //                std::string endString = match[2].str();
 //                uint64_t end = std::strtoull(endString.c_str(), nullptr, 16);
 //                std::string path = match[3].str();
 //
 //                auto iter = moduleRanges.find(path);
 //                if (iter != moduleRanges.end())
 //                {
 //                    BNAddressRange currentRange = iter->second;
 //                    BNAddressRange newRange;
 //                    newRange.start = std::min<uint64_t>(currentRange.start, start);
 //                    newRange.end = std::max<uint64_t>(currentRange.end, end);
 //                    iter->second = newRange;
 //                }
 //                else
 //                {
 //                    moduleRanges[path] = {start, end};
 //                }
 //            }
 //        }
 //    }
 //
 //    std::vector<DebugModule> result;
 //    for (auto& iter: moduleRanges)
 //    {
 //        DebugModule module;
 //        module.m_address = iter.second.start;
 //        module.m_size = iter.second.end - iter.second.start;
 //        module.m_name = iter.first;
 //        module.m_short_name = iter.first;
 //        module.m_loaded = true;
 //        result.push_back(module);
 //    }
	// m_moduleCache = result;
 //
 //    return result;
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
            m_lastActiveThreadId = tid;

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
			uint8_t exitCode = strtoul(exitCodeString.c_str(), nullptr, 16);
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
					throw std::invalid_argument("Invalid input string");
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
	LogWarn("EsrevenAdapter does not support StepOver() by itself -- the debugger is responsible for emulating it");
	return false;
}


bool EsrevenAdapter::StepReturn()
{
	LogWarn("EsrevenAdapter does not support StepReturn() yet");
	return false;
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
	InvalidateCache();
	auto status = GenericGo("bs");
	if (status == InternalError)
		return false;

	uint64_t remoteIP = GetInstructionOffset();
	uint64_t stack = GetStackPointer();

	// TODO: support the case where we cannot determined the remote arch
	ArchitectureRef remoteArch = GetController()->GetState()->GetRemoteArchitecture();
	if (!remoteArch)
		return InternalError;

	size_t size = remoteArch->GetMaxInstructionLength();
	DataBuffer buffer = ReadMemory(remoteIP, size);
	size_t bytesRead = buffer.GetLength();

	Ref<LowLevelILFunction> ilFunc = new LowLevelILFunction(remoteArch, nullptr);
	ilFunc->SetCurrentAddress(remoteArch, remoteIP);
	remoteArch->GetInstructionLowLevelIL((const uint8_t*)buffer.GetData(), remoteIP, bytesRead, *ilFunc);

	if (ilFunc->GetInstructionCount() == 0)
		return InternalError;

	const auto& instr = (*ilFunc)[0];
	if (instr.operation != LLIL_RET)
		return true;

	AddHardwareWriteBreakpoint(stack);
	InvalidateCache();
	status = GenericGo("bc");
	RemoveHardwareWriteBreakpoint(stack);

	return status != InternalError;
}

bool EsrevenAdapter::AddHardwareWriteBreakpoint(uint64_t address)
{
	if (m_isTargetRunning || !m_rspConnector)
		return false;

	return this->m_rspConnector->TransmitAndReceive(RspData("Z2,{:x},{}", address, 1)).AsString() != "OK";
}

bool EsrevenAdapter::RemoveHardwareWriteBreakpoint(uint64_t address)
{
	if (m_isTargetRunning || !m_rspConnector)
		return false;

	return this->m_rspConnector->TransmitAndReceive(RspData("Z2,{:x},{}", address, 1)).AsString() != "OK";
}

bool EsrevenAdapter::StepReturnReverse()
{
	LogWarn("EsrevenAdapter does not support StepReturnReverse() yet");
	return false;
}


std::string EsrevenAdapter::InvokeBackendCommand(const std::string& command)
{
	if (!m_rspConnector)
		return {};

	if (command.substr(0, 4) == "mon ")
		return RunMonitorCommand(command.substr(4));
	else if (command.substr(0, 8) == "monitor ")
		return RunMonitorCommand(command.substr(4));

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
    	return m_canReverseContinue && m_canReverseStep;
    default:
        return false;
    }
}


void EsrevenAdapter::InvalidateCache()
{
	m_regCache.reset();
	m_moduleCache.reset();
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
			throw std::invalid_argument("Invalid input string");
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
	return {};
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
		if (DebugModule::IsSameBaseModule(moduleName, module.m_name))
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

	return settings;
}


Ref<Settings> EsrevenAdapterType::GetAdapterSettings()
{
	static Ref<Settings> settings = RegisterAdapterSettings();
	return settings;
}
