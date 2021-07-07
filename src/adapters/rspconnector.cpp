#include <numeric>
#include <stdexcept>
#include <algorithm>
#include <chrono>
#include <thread>
#include <regex>
#include <type_traits>
#include "rspconnector.h"

RspConnector::RspConnector(Socket* socket) : m_socket(socket) { }

RspConnector::~RspConnector() {}

RspData RspConnector::BinaryDecode(const RspData& data)
{
    std::string result{};
    bool skip{false};

    std::size_t index{};
    for ( const auto& c : data.AsString() ) {
        if (skip)
            skip = false;
        else if (c == 0x7d) {
            result.push_back(data.m_data[index + 1] ^ 0x20);
            skip = true;
        } else if (c == 0x2a) {
            auto repeat = data.m_data[index + 1] - 29;
            auto last_char = result[result.size() - 1];
            for ( auto idx = 0; idx < repeat; idx++ )
                result.push_back(last_char);
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
        for ( std::size_t index{}; index < data.m_size; index++ )
        {
            if ( should_skip )
            {
                should_skip = false;
            }
            else if (data.m_data[index] == '*')
            {
                auto repeat = data.m_data[index + 1] - 29;
                auto last_char = result[result.size() - 1];
                for ( auto idx = 0; idx < repeat; idx++ )
                    result.push_back(last_char);
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
        if (key_value.empty() || key_value.size() < 2)
            continue;

        const auto key = key_value[0];
        const auto value = RspConnector::DecodeRLE( RspData(key_value[1]) ).AsString();

        if ( key == "thread" ) {
            if ( value[0] == 'p' && value.find('.') != std::string::npos ) {
                auto core_id_and_thread_id = RspConnector::Split(value.substr(1), ".");
                packet_map["thread"] = std::stoull(core_id_and_thread_id[1], nullptr, 16);
            } else {
                packet_map["thread"] = std::stoull(value, nullptr, 16);
            }
        } else if ( std::regex_search(key, std::regex("^[0-9a-fA-F]+$")) ) {
            char reg_name[64]{};
            std::sprintf(reg_name, "r%d", std::stoi(key, nullptr, 16));
            packet_map[reg_name] = static_cast<std::int64_t>( RspConnector::SwapEndianness( std::stoull(value, nullptr, 16)) );
        } else {
            packet_map[key] = std::stoull(value, nullptr, 16);
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
    if ( !this->m_acksEnabled )
        return {};

    char buffer{};
    this->m_socket->Recv(&buffer, sizeof(buffer));

    if ( buffer == char{} )
        throw std::runtime_error("Disconnected while waiting for ack");

    if ( buffer != '+' )
        throw std::runtime_error("Incorrect response");

    return buffer;
}

void RspConnector::SendAck() const
{
    if ( !this->m_acksEnabled )
        return;

    this->m_socket->Send("+", 1);
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

void RspConnector::SendRaw(const RspData& data) const
{
    this->m_socket->Send((char*)data.m_data, static_cast<std::int32_t>( data.m_size ));
}

void RspConnector::SendPayload(const RspData& data) const
{
    const auto checksum = std::accumulate(data.begin(), data.end(), 0) % 256;
    auto packet = "$" + data.AsString() + "#";

    char buf[32];
    std::sprintf(buf, "%02x", checksum);
    packet.append(buf);

    this->SendRaw(RspData(packet));
}

RspData RspConnector::ReceiveRspData() const
{
    std::vector<char> buffer{};

    bool did_find = false;
    while ( !did_find )
    {
        char tmp_buffer[RspData::BUFFER_MAX]{'\0'};
        this->m_socket->Recv(tmp_buffer, sizeof(tmp_buffer));
        std::copy(tmp_buffer, tmp_buffer + sizeof(tmp_buffer), std::back_inserter(buffer));

        std::this_thread::sleep_for(std::chrono::milliseconds(1));

        if (buffer[0] != '$')
            throw std::runtime_error("Incorrect response");

        bool parsed = false;
        int parse_count{};
        while ( !parsed )
        {
            auto location = std::find(buffer.rbegin() + parse_count, buffer.rend(), '#');
            if (location != buffer.rend())
            {
                auto location_index = std::distance(buffer.begin(), location.base()) - 1;
                if (buffer.begin() + location_index != buffer.end())
                {
                    if (std::isxdigit(*(buffer.begin() + location_index + 1)) &&
                        std::isxdigit(*(buffer.begin() + location_index + 2)) &&
                        (*(buffer.begin() + location_index)) == '#' )
                    {
                        did_find = true;
                        parsed = true;
                    }
                    else
                    {
                        parse_count++;
                        continue;
                    }
                }
            }
        }
    }

    if ( auto location = std::find(buffer.rbegin(), buffer.rend(), '#');
            location != buffer.rend() )
    {
        auto location_index = std::distance(buffer.begin(), location.base()) - 1;
        buffer.erase(buffer.begin() + location_index, buffer.end());
        buffer.erase(buffer.begin(), buffer.begin() + 1);
    }

    this->SendAck();

    return RspData(std::string(buffer.data(), buffer.size()));
}

RspData RspConnector::TransmitAndReceive(const RspData& data, const std::string& expect, bool async)
{
    this->SendPayload(data);

    RspData reply{};

    if ( expect == "nothing" )
        reply = RspData("");
    else if ( expect == "ack_then_reply" ) {
        this->ExpectAck();
        reply = this->ReceiveRspData();
    }
    else if ( expect == "mixed_output_ack_then_reply" ) {
        bool ack_received = false;
        while(true) {
            char peek{};
            this->m_socket->Recv(&peek, sizeof(peek), MSG_PEEK);

            if (!peek)
                throw std::runtime_error("backend gone?");

            if (peek == '+') {
                if (ack_received)
                    throw std::runtime_error("two acks came when only one was expected");

                char buf{};
                ack_received = true;
                this->m_socket->Recv(&buf, sizeof(buf));
                continue;
            }

            if (peek != '$') {
                char buf[16];
                this->m_socket->Recv(buf, sizeof(buf));
                throw std::runtime_error("packet start is wrong");
            }

            reply = this->ReceiveRspData();
            if (reply.m_data[0] == 'O') {
                if (async)
                    this->HandleAsyncPacket(reply);
            } else {
                break;
            }
        }

        if (!ack_received && this->m_acksEnabled)
            throw std::runtime_error("expected ack, but received none");
    } else if ( expect == "host_io" ) {
        this->ExpectAck();
        reply = this->ReceiveRspData();
        if (reply.m_data[0] != 'F')
            throw std::runtime_error("host io packet is invalid");

        /* TODO: finish this */
        if (reply.AsString().find(';') != std::string::npos) {
            const auto split = RspConnector::Split(reply.AsString(), ";");
            printf("host_io\n");
            printf("%s\n", split[0].c_str());
            printf("%s\n", split[1].c_str());
            printf("%s\n", RspConnector::BinaryDecode(RspData(split[1])).AsString().c_str());
        }
    }

    if ( std::find(reply.begin(), reply.end(), '*') != reply.end() )
        reply = this->DecodeRLE(reply);

    return reply;
}

std::string RspConnector::GetXml(const std::string& name)
{
    char buffer[128]{'\0'};
    std::sprintf(buffer, "qXfer:features:read:%s:%X,%X", name.c_str(), 0, RspData::BUFFER_MAX);
    const auto data = this->TransmitAndReceive(RspData(buffer));

    if ( data.m_data[0] != 'l' &&
         data.m_data[0] != 'm' )
        throw std::runtime_error("Failed to retrieve xml data");

    auto data_string = data.AsString();
    data_string.erase(0, 1);

    return data_string;
}

void RspConnector::HandleAsyncPacket(const RspData& data)
{
    if ( data.m_data[0] != 'O' )
        return;

    const auto string = data.AsString();
    const auto message = string.substr(1);
}