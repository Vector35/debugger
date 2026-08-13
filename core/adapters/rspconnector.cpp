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

#include <inttypes.h>
#include <numeric>
#include <algorithm>
#include <chrono>
#include <thread>
#include <regex>
#include <type_traits>
#include <fmt/format.h>
#include "rspconnector.h"

using namespace BinaryNinjaDebugger;
using namespace BinaryNinja;

RspConnector::RspConnector(Socket* socket) : m_socket(socket) { }

RspConnector::~RspConnector() {}

// Expand one RLE run into result. A run is "<char>*<count>", so it repeats the character
// already emitted and the count says how many more copies to append. The count is encoded
// as count + 29 to keep the byte printable: the smallest count byte is ' ' (0x20), which
// decodes to 3, so "0* " expands to "0000", and the largest is '~' (0x7e). Returns false
// if there is nothing to repeat or the count is out of range, both of which mean the
// packet is malformed rather than merely unusual.
static bool ExpandRleRun(uint8_t countByte, std::string& result)
{
	if (result.empty())
	{
		LogError("Malformed RLE in remote protocol data: run marker with no preceding character");
		return false;
	}
	if ((countByte < 0x20) || (countByte > 0x7e))
	{
		LogError("Malformed RLE in remote protocol data: repeat count out of range");
		return false;
	}
	result.append(countByte - 29, result.back());
	return true;
}

RspData RspConnector::BinaryDecode(const RspData& data)
{
    std::string result{};
    bool skip{false};

    std::size_t index{};
    for ( const auto& c : data.AsString() ) {
        if (skip)
            skip = false;
        else if (c == 0x7d) {
            // '}' escapes the byte after it, which therefore has to exist. Return an empty
            // RspData on malformed input, the same way the receive paths report a bad packet;
            // a non-empty payload always decodes to at least one character, so empty is
            // unambiguous here.
            if (index + 1 >= data.m_data.GetLength())
            {
                LogError("Malformed escape in remote protocol data: escape marker with no escaped byte");
                return {};
            }
            result.push_back(data.m_data[index + 1] ^ 0x20);
            skip = true;
        } else if (c == 0x2a) {
            if (index + 1 >= data.m_data.GetLength())
            {
                LogError("Malformed RLE in remote protocol data: run marker with no repeat count");
                return {};
            }
            if (!ExpandRleRun(data.m_data[index + 1], result))
                return {};
            skip = true;
        } else {
            result.push_back(c);
        }
        index++;
    }

    return RspData(result);
}

RspData RspConnector::DecodeRLE(const RspData& data)
{
    if ( std::find(data.begin(), data.end(), '*') != data.end() )
    {
        std::string result{};
        bool should_skip = false;
        for ( std::size_t index{}; index < data.m_data.GetLength(); index++ )
        {
            if ( should_skip )
            {
                should_skip = false;
            }
            else if (data.m_data[index] == '*')
            {
                // The count byte of a run has to exist. Return an empty RspData on malformed
                // input, the same way the receive paths report a bad packet; a successful
                // decode always has at least the repeated character, so empty is unambiguous
                // here.
                if (index + 1 >= data.m_data.GetLength())
                {
                    LogError("Malformed RLE in remote protocol data: run marker with no repeat count");
                    return {};
                }
                if (!ExpandRleRun(data.m_data[index + 1], result))
                    return {};
                should_skip = true;
            }
            else
            {
                result.push_back((char)data.m_data[index]);
            }
        }

        return RspData(result);
    }

    return data;
}

std::unordered_map<std::string, std::uint64_t> RspConnector::PacketToUnorderedMap(const RspData& data)
{
    std::unordered_map<std::string, std::uint64_t> packet_map{};
    packet_map["signal"] = std::stoull(data.AsString().substr(1, 2), nullptr, 16);

    const auto data_string = data.AsString();
    const auto after_signal = data_string.substr(3);

    for ( const auto& entries : RspConnector::Split(after_signal, ";")) {
        const auto key_value = RspConnector::Split(entries, ":");
        if (key_value.empty())
            continue;

        const auto key = key_value[0];
		std::string value;
		if (key_value.size() == 2)
		{
			value = RspConnector::DecodeRLE(RspData(key_value[1])).AsString();
			// This is hack for registers wider than 8 bytes. We could parse it here like how we handle wide registers
			// in ReadAllRegisters(), but since we do not really use the returned information anywhere, it is fine to
			// just truncate the string
			if (value.length() > 16)
				value = value.substr(0, 16);

			if (key == "thread") {
				if (value[0] == 'p' && value.find('.') != std::string::npos) {
					auto core_id_and_thread_id = RspConnector::Split(value.substr(1), ".");
					packet_map["thread"] = std::stoull(core_id_and_thread_id[1], nullptr, 16);
				} else {
					packet_map["thread"] = std::stoull(value, nullptr, 16);
				}
			} else if (std::regex_search(key, std::regex("^[0-9a-fA-F]+$"))) {
				packet_map[fmt::format("r{}", std::stoi(key, nullptr, 16))] =
						static_cast<std::int64_t>( RspConnector::SwapEndianness(std::stoull(value, nullptr, 16)));
			} else {
				packet_map[key] = std::stoull(value, nullptr, 16);
			}
		}
		else
		{
			packet_map[key] = 0;
		}
    }

    return packet_map;
}

std::vector<std::string> RspConnector::Split(const std::string& string, const std::string& regex) {
    const auto regex_l = std::regex(regex);
    return { std::sregex_token_iterator(string.begin(), string.end(), regex_l, -1), std::sregex_token_iterator() };
}

void RspConnector::EnableAcks()
{
    this->m_acksEnabled = true;
}

void RspConnector::DisableAcks()
{
    this->m_acksEnabled = false;
}

char RspConnector::ExpectAck()
{
    std::unique_lock lock(m_socketLock);

    if ( !this->m_acksEnabled )
        return {};

    char buffer{};
    this->m_socket->Recv(&buffer, sizeof(buffer));

    if ( buffer == char{} )
    {
        LogError("Disconnected while waiting for ack");
        return {};
    }

    if ( buffer != '+' )
    {
        LogError("incorrect response, expected +, got %c", buffer);
        return {};
    }

    return buffer;
}

void RspConnector::SendAck()
{
    std::unique_lock lock(m_socketLock);

    if ( !this->m_acksEnabled )
        return;

    this->m_socket->Send((char*)"+", 1);
}

void RspConnector::NegotiateCapabilities(const std::vector <std::string>& capabilities)
{
    std::string capabilities_request = "qSupported:";
    for ( const auto& capability : capabilities )
    {
        capabilities_request.append(capability);
        if (&capability != &capabilities.back())
            capabilities_request.append(";");
    }

    const auto reply = this->TransmitAndReceive(RspData(capabilities_request));
    const auto reply_tokens = RspConnector::Split(reply.AsString(), ";");

    for ( auto reply_token : reply_tokens )
    {
        if ( reply_token.find("PacketSize=") != std::string::npos )
        {
            if (auto packet_tokens = RspConnector::Split(reply_token, "="); !packet_tokens.empty())
                this->m_maxPacketLength = std::stoi(packet_tokens[1], nullptr, 16);
            continue;
        }

        reply_token.erase(std::remove(reply_token.begin(), reply_token.end(), '+'), reply_token.end());
        this->m_serverCapabilities.push_back(reply_token);
    }

    const auto can_start_without_ack = this->TransmitAndReceive(RspData("QStartNoAckMode"));
    if (can_start_without_ack.AsString() == "OK" )
        this->m_acksEnabled = false;
}

void RspConnector::SendRaw(const RspData& data)
{
    this->m_socket->Send((char*)data.m_data.GetData(), static_cast<std::int32_t>( data.m_data.GetLength() ));
}

void RspConnector::SendPayload(const RspData& data)
{
    std::unique_lock lock(m_socketLock);

    const auto checksum = std::accumulate(data.begin(), data.end(), 0) % 256;
    auto packet = "$" + data.AsString() + "#" + fmt::format("{:02x}", checksum);

    this->SendRaw(RspData(packet));
}

RspData RspConnector::ReceiveRspData(std::chrono::milliseconds timeoutDuration)
{
    std::unique_lock lock(m_socketLock);

    std::vector<char> buffer{};
    auto startTime = std::chrono::steady_clock::now();

    while (true)
    {
        char tmp_buffer[RspData::BUFFER_MAX]{'\0'};
#ifdef WIN32
        intptr_t n = this->m_socket->Recv(tmp_buffer, sizeof(tmp_buffer), MSG_PEEK);
#else
        intptr_t n = this->m_socket->Recv(tmp_buffer, sizeof(tmp_buffer), MSG_DONTWAIT | MSG_PEEK);
#endif
        if (n <= 0)
        {
            // Check if timeout has been exceeded
            auto elapsedTime = std::chrono::steady_clock::now() - startTime;
            if (elapsedTime > timeoutDuration)
            {
                LogWarn("ReceiveRspData timeout: failed to receive data within %" PRId64 "ms", (int64_t)timeoutDuration.count());
                return {}; // Return an empty RspData object
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }

        std::vector<char> tmpBufferVec(tmp_buffer, tmp_buffer + n);
        auto location = std::find(tmpBufferVec.begin(), tmpBufferVec.end(), '#');
        // Find a '#' followed by two digits
        if ((location != tmpBufferVec.end())
            && (location + 1 != tmpBufferVec.end() && (std::isxdigit(*(location + 1))))
            && (location + 2 != tmpBufferVec.end() && (std::isxdigit(*(location + 2))))
        )
        {
            // Found the packet end, truncate the last tmp buffer, and return a packet
            tmpBufferVec.erase(location, tmpBufferVec.end());
            // We only consume the exact number of bytes that are in the current RSP packet. Otherwise, if two RSP
            // packets have already arrived, the latter one will be silently discarded
            // TODO: there is an edge case that '#' arrives in the first buffer and the two hex digits arrive in the
            // next one. I believe this is rare enough that we can deal with it later
            this->m_socket->Recv(tmp_buffer, (int32_t)tmpBufferVec.size() + 3);
            std::copy(tmpBufferVec.begin(), tmpBufferVec.end(), std::back_inserter(buffer));
            break;
        }
        else
        {
            // Consume the buffer
            this->m_socket->Recv(tmp_buffer, (int32_t)tmpBufferVec.size());
            std::copy(tmpBufferVec.begin(), tmpBufferVec.begin() + n, std::back_inserter(buffer));
        }
    }

    if ((buffer.size() < 1) || (buffer[0] != '$'))
    {
        LogWarn("ReceiveRspData: incorrect response, expected $");
        return {}; // Return an empty RspData object
    }

    // Swallow the '$' char
    buffer.erase(buffer.begin(), buffer.begin() + 1);

    this->SendAck();

	RspData reply = RspData(std::string(buffer.data(), buffer.size()));
	if ( std::find(reply.begin(), reply.end(), '*') != reply.end() )
		reply = this->DecodeRLE(reply);

	return reply;
}

RspData RspConnector::TransmitAndReceive(const RspData& data, const std::string& expect,
										 std::function<void(const RspData& data)> asyncPacketHandler,
										 std::chrono::milliseconds timeout)
{
	std::unique_lock lock(m_socketLock);

    this->SendPayload(data);

    RspData reply{};

    if ( expect == "nothing" )
        reply = RspData("");
    else if ( expect == "ack_then_reply" ) {
        this->ExpectAck();
        reply = this->ReceiveRspData(timeout);
    }
    else if ( expect == "mixed_output_ack_then_reply" ) {
        bool ack_received = false;
        while(true) {
            char peek{};
            this->m_socket->Recv(&peek, sizeof(peek), MSG_PEEK);

            if (!peek)
            {
                LogError("backend gone?");
                return {};
            }

            if (peek == '+') {
                if (ack_received)
                {
                    LogError("two acks came when only one was expected");
                    return {};
                }

                char buf{};
                ack_received = true;
                this->m_socket->Recv(&buf, sizeof(buf));
                continue;
            }

            if (peek != '$') {
                char buf[16];
                this->m_socket->Recv(buf, sizeof(buf));
                LogError("packet start is wrong");
                return {};
            }

            reply = this->ReceiveRspData();
            if (reply.m_data[0] == 'O') {
				// Right now, this handles the stdout message from the backend
                if (asyncPacketHandler)
                    asyncPacketHandler(reply);
            } else {
                break;
            }
        }

        if (!ack_received && this->m_acksEnabled)
        {
            LogError("expected ack, but received none");
            return {};
        }
    }

    if ( std::find(reply.begin(), reply.end(), '*') != reply.end() )
        reply = this->DecodeRLE(reply);

    return reply;
}


int32_t RspConnector::HostFileIO(const RspData& data, RspData& output, int32_t& error)
{
    std::unique_lock lock(m_socketLock);

    this->SendPayload(data);

    RspData reply{};

    this->ExpectAck();
    reply = this->ReceiveRspData();
    if (reply.m_data[0] != 'F')
    {
        LogDebug("host io packet is invalid");
        return -1;
    }

    std::string resultErrno = reply.AsString();

    // split off attachment
    if (resultErrno.find(';') != std::string::npos) {
        const auto split = RspConnector::Split(resultErrno, ";");
        if ((split.size() >= 2) && (split[1] != ""))
            output = RspConnector::BinaryDecode(RspData(split[1]));

        resultErrno = split[0];
    }

    // remove the 'F' char at the beginning
    if (resultErrno.length() > 0)
        resultErrno = resultErrno.substr(1);

    // split off errno
    if (resultErrno.find(',') != std::string::npos) {
        const auto split = RspConnector::Split(resultErrno, ",");
        if ((split.size() >= 2) && (split[1] != ""))
            error = std::stol(split[1].c_str(), nullptr, 16);

        return std::stol(split[0].c_str(), nullptr, 16);
    }
    return std::stol(resultErrno.c_str(), nullptr, 16);
}


std::string RspConnector::GetXml(const std::string& name)
{
    size_t readLength = 0;
    bool lastPacket = false;
    std::string result;

    while (true)
    {
        const auto chunk = this->TransmitAndReceive(RspData(
                "qXfer:features:read:{}:{:X},{:X}", name, readLength, RspData::BUFFER_MAX ));

        if (chunk.m_data.GetLength() == 0)
        {
            LogError("Failed to read xml data for '%s': received empty response", name.c_str());
            return {};
        }

        switch (chunk.m_data[0])
        {
        case 'l':
            lastPacket = true;
            // intentional fall through, no break
        case 'm':
        {
            auto chunk_string = chunk.AsString();
            chunk_string.erase(0, 1);
            readLength += chunk_string.length();
            result += chunk_string;
            break;
        }
        default:
            LogError("Failed to retrieve xml data for '%s': unexpected response type '%c'",
                name.c_str(), (char)chunk.m_data[0]);
            return {};
        }

        if (lastPacket)
            break;
    }

    return result;
}


uint8_t& RspData::operator[](size_t offset)
{
	return m_data[offset];
}


const uint8_t& RspData::operator[](size_t offset) const
{
	return m_data[offset];
}