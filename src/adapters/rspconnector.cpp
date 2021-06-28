#include <numeric>
#include <stdexcept>
#include <algorithm>
#include <chrono>
#include <thread>
#include <regex>
#include <type_traits>
#include <sys/time.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include "rspconnector.h"

RspConnector::RspConnector(int socket) : m_socket(socket) { }

RspConnector::~RspConnector() {}

RspData RspConnector::BinaryDecode(const RspData& data)
{
    return RspData();
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

std::unordered_map<std::string, std::int64_t> RspConnector::PacketToUnorderedMap(const RspData& data)
{
    std::unordered_map<std::string, std::int64_t> packet_map{};
    packet_map["signal"] = std::stoll(data.AsString().substr(1, 2), nullptr, 16);

    const auto split = [](const std::string& string, const std::string& regex) -> std::vector<std::string> {
        const auto regex_l = std::regex(regex);
        return { std::sregex_token_iterator(string.begin(), string.end(), regex_l, -1), std::sregex_token_iterator() };
    };

    const auto data_string = data.AsString();
    const auto after_signal = data_string.substr(3, std::distance(data.begin(), data.end()));
    for ( const auto& entries : split(after_signal, ";")) {
        const auto key_value = split(entries, ":");
        const auto key = key_value[0];
        const auto value = RspConnector::DecodeRLE( RspData(key_value[1]) ).AsString();

        if ( key == "thread" ) {
            if ( value[0] == 'p' && value.find('.') != std::string::npos ) {
                auto core_id_and_thread_id = split(value.substr(1, std::distance(value.begin(), value.end())), ".");
                packet_map["thread"] = std::stoll(core_id_and_thread_id[1], nullptr, 16);
            } else {
                packet_map["thread"] = std::stoll(value, nullptr, 16);
            }
        } else if ( std::regex_search(key, std::regex("^[0-9a-fA-F]+$")) ) {
            const auto swap_endianness = [](auto val) {
                union {
                    decltype(val) m_val;
                    std::array<std::uint8_t, sizeof(decltype(val))> m_raw;
                } source{val}, dest{};
                std::reverse_copy(source.m_raw.begin(), source.m_raw.end(), dest.m_raw.begin());
                return dest.m_val;
            };

            char reg_name[64]{};
            std::sprintf(reg_name, "r%d", std::stoi(key, nullptr, 16));

            packet_map[reg_name] = static_cast<std::int64_t>( swap_endianness( std::stoull(value, nullptr, 16)) );
        } else {
            packet_map[key] = std::stoll(value, nullptr, 16);
        }
    }

    return packet_map;
}

void RspConnector::EnableAcks()
{
    this->m_acks_enabled = true;
}

void RspConnector::DisableAcks()
{
    this->m_acks_enabled = false;
}

char RspConnector::ExpectAck()
{
    if ( !this->m_acks_enabled )
        return {};

    char buffer{};
    recv(this->m_socket, &buffer, sizeof(buffer), 0);

    if ( buffer == char{} )
        throw std::runtime_error("Disconnected while waiting for ack");

    if ( buffer != '+' )
        throw std::runtime_error("Incorrect response");

    return buffer;
}

void RspConnector::SendAck() const
{
    if ( !this->m_acks_enabled )
        return;

    send(this->m_socket, "+", 1, 0);
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

    const auto split = [](const std::string& string, const std::string& regex) -> std::vector<std::string>
    {
        const auto regex_l = std::regex(regex);
        return { std::sregex_token_iterator(string.begin(), string.end(), regex_l, -1), std::sregex_token_iterator() };
    };

    const auto reply = this->TransmitAndReceive(RspData(capabilities_request));
    const auto reply_tokens = split(reply.AsString(), ";");
    for ( auto reply_token : reply_tokens )
    {
        if ( reply_token.find("PacketSize=") != std::string::npos )
        {
            if (auto packet_tokens = split(reply_token, "="); !packet_tokens.empty())
                this->m_max_packet_length = std::stoi(packet_tokens[1], nullptr, 16);
            continue;
        }

        reply_token.erase(std::remove(reply_token.begin(), reply_token.end(), '+'), reply_token.end());
        this->m_server_capabilities.push_back(reply_token);
    }

    const auto can_start_without_ack = this->TransmitAndReceive(RspData("QStartNoAckMode"));
    if (can_start_without_ack.AsString() == "OK" )
        this->m_acks_enabled = false;
}

void RspConnector::SendRaw(const RspData& data) const
{
    printf("[raw send]\n");
    for ( const auto& c : data )
        printf("%c", c);
    printf("\n");

    send(this->m_socket, data.m_data, data.m_size, 0);
}

void RspConnector::SendPayload(const RspData& data) const
{
    printf("[payload send]\n");
    for ( const auto& c : data )
        printf("%c", c);
    printf("\n");


    const auto checksum = std::accumulate(data.begin(), data.end(), 0) % 256;
    auto packet = "$" + data.AsString() + "#";

    char buf[32];
    std::sprintf(buf, "%02x", checksum);
    packet.append(buf);

    printf("[modified]\n");
    for ( const auto& c : packet )
        printf("%c", c);
    printf("\n");

    this->SendRaw(RspData(packet));
}

/*
RspData RspConnector::ReceiveRspData()
{
    char tmp_buffer[16];
    recv(this->m_socket, tmp_buffer, sizeof(tmp_buffer), 0);
    for ( auto idx = 0u; idx < sizeof(tmp_buffer);idx++)
        printf("%c", tmp_buffer[idx]);
    printf("\n");

    std::vector<char> buffer{tmp_buffer, tmp_buffer + sizeof(tmp_buffer)};
    if (buffer[0] != '$')
        throw std::runtime_error("Incorrect response");

    printf("[recv]\n");
    printf("0 : %c\n", buffer[0]);
    for ( const auto& c : buffer )
        printf("%c ", c);
    printf("\n");

    std::string result_string{};
    if (auto location = std::find(buffer.rbegin(), buffer.rend(), '#');
            location != buffer.rend() )
    {
        auto location_index = std::distance(buffer.begin(), location.base()) - 1;
        buffer.erase(buffer.begin() + location_index, buffer.end());
        buffer.erase(buffer.begin(), buffer.begin() + 1);
    }

    printf("[modified]\n");
    printf("0 : %c\n", buffer[0]);
    for ( const auto& c : buffer )
        printf("%c ", c);
    printf("\n");

    this->SendAck();

    return RspData(std::string(buffer.data(), buffer.size()));
}*/

RspData RspConnector::ReceiveRspData() const
{
    std::vector<char> buffer{};

    bool did_find = false;
    while ( !did_find )
    {
        char tmp_buffer[RspData::BUFFER_MAX]{'\0'};
        recv(this->m_socket, tmp_buffer, sizeof(tmp_buffer), 0);
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
    else if ( expect == "ack_then_reply" )
    {
        printf("EXPECT -> ack_then_reply\n");
        printf("ack -> %c\n", this->ExpectAck());
        reply = this->ReceiveRspData();
    }

    if ( std::find(reply.begin(), reply.end(), '*') != reply.end() )
    {
        printf("encoded -> %s\n", reply.AsString().c_str());
        reply = this->DecodeRLE(reply);
    }

    printf("decoded -> %s\n", reply.AsString().c_str());

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
