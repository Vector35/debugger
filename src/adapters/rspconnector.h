#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <cstring>

struct RspData
{
    struct RspIterator
    {
        using iterator_category = std::forward_iterator_tag;
        using difference_type   = std::ptrdiff_t;
        using value_type        = std::uint8_t;
        using pointer           = value_type*;
        using reference         = value_type&;

        RspIterator(pointer ptr) : m_pointer(ptr) {}

        virtual reference operator*() const { return *m_pointer; }
        pointer operator->() { return m_pointer; }
        RspIterator& operator++() { m_pointer++; return *this; }
        RspIterator operator++(int) { RspIterator tmp = *this; ++(*this); return tmp; }
        friend bool operator== (const RspIterator& a, const RspIterator& b) { return a.m_pointer == b.m_pointer; };
        friend bool operator!= (const RspIterator& a, const RspIterator& b) { return a.m_pointer != b.m_pointer; };

    protected:
        pointer m_pointer;
    };

    struct ReverseRspIterator : public RspIterator
    {
        ReverseRspIterator(pointer ptr) : RspIterator(ptr) {}
        RspIterator& operator--() { m_pointer--; return *this; }
        RspIterator operator--(int) { RspIterator tmp = *this; --(*this); return tmp; }
    };

    struct ConstRspIterator : public RspIterator
    {
        ConstRspIterator(pointer ptr) : RspIterator(ptr) {}
        const reference operator*() const override { return *m_pointer; }
    };

    RspIterator begin() const { return RspIterator(&this->m_data[0]); }
    RspIterator end() const { return RspIterator(&this->m_data[this->m_size]); }
    ReverseRspIterator rbegin() const { return ReverseRspIterator(&this->m_data[this->m_size]); }
    ReverseRspIterator rend() const { return ReverseRspIterator(&this->m_data[0]); }
    ConstRspIterator cbegin() const { return ConstRspIterator(&this->m_data[0]); }
    ConstRspIterator cend() const { return ConstRspIterator(&this->m_data[this->m_size]); }


    RspData() {}

    explicit RspData(const std::string& str)
    {
        this->m_data = new std::uint8_t[str.size()];
        strcpy((char*)this->m_data, str.c_str());
        this->m_size = str.size();
    }

    RspData(void* data, std::size_t size) : m_data((std::uint8_t*)data), m_size(size) {}
    RspData(char* data, std::size_t size) : m_data((std::uint8_t*)data), m_size(size) {}

    /* TODO: fix all this allocation stuff */

    [[nodiscard]] std::string AsString() const
    {
        return std::string((char*)this->m_data, this->m_size);
    }

    std::uint8_t* m_data{};
    std::size_t m_size{};
};

class RspConnector
{
    int m_socket{};
    bool m_acks_enabled{true};
    std::vector<std::string> m_server_capabilities{};
    int m_max_packet_length{0xfff};

public:
    RspConnector(int socket);
    ~RspConnector();

    static RspData BinaryDecode(const RspData& data);
    static RspData DecodeRLE(const RspData& data);
    static std::unordered_map<std::string, RspData> PacketToUnorderedMap(const RspData& data);

    void EnableAcks();
    void DisableAcks();

    char ExpectAck();
    void SendAck() const;

    void NegotiateCapabilities(const std::vector<std::string>& capabilities);

    void SendRaw(const RspData& data) const;
    void SendPayload(const RspData& data) const;

    RspData ReceiveRspData();
    RspData TransmitAndReceive(const RspData& data, const std::string& expect = "ack_then_reply", bool async = false);

    std::string GetXml(const std::string& name);
};