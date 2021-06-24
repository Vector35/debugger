#include <numeric>
#include <stdexcept>
#include <algorithm>
#include <chrono>
#include <thread>
#include "rspconnector.h"

RspConnector::RspConnector(int socket) : m_socket(socket) { }

RspConnector::~RspConnector()
{

}

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

std::unordered_map<std::string, RspData> RspConnector::PacketToUnorderedMap(const RspData& data)
{
    return {};
}

void RspConnector::EnableAcks()
{

}

void RspConnector::DisableAcks()
{

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

}

void RspConnector::SendRaw(const RspData& data) const
{
    printf("[raw send]\n");
    for ( const auto& c : data )
        printf("%c ", c);
    printf("\n");

    send(this->m_socket, data.m_data, data.m_size, 0);
}

void RspConnector::SendPayload(const RspData& data) const
{
    printf("[sending]\n");
    for ( const auto& c : data )
        printf("%c ", data);
    printf("\n");

    const auto checksum = std::accumulate(data.begin(), data.end(), 0) % 256;
    auto packet = "$" + data.AsString() + "#";

    char buf[32];
    std::sprintf(buf, "%02x", checksum);
    packet.append(buf);

    printf("[modified]\n");
    for ( const auto& c : packet )
        printf("%c ", c);
    printf("\n");

    this->SendRaw(RspData(packet));
}

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
}

RspData RspConnector::TransmitAndReceive(const RspData& data, const std::string& expect, bool async)
{
    this->SendPayload(data);

    RspData reply{};

    if ( expect == "nothing" )
        reply = RspData("");
    else if ( expect == "ack_then_reply" )
    {
        printf("ack -> %c\n", this->ExpectAck());
        reply = this->ReceiveRspData();
        printf("rle -> %s\n", reply.AsString().c_str());
    }

    if ( std::find(reply.begin(), reply.end(), '*') != reply.end() )
        reply = this->DecodeRLE(reply);
    printf("derle -> %s\n", reply.AsString().c_str());

    return reply;
}

std::string RspConnector::GetXml(const std::string& name)
{
    return nullptr;
}
