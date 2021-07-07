#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <algorithm>
#include <regex>
#include <array>
#ifdef WIN32
#include <windows.h>
#include <winsock.h>
#else
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/fcntl.h>
#include <unistd.h>
#endif
#include <cstring>
#include "socket.h"

struct RspData
{
    /* BUFFER_MAX/GDB_BUF_MAX - https://www.embecosm.com/appnotes/ean4/embecosm-howto-rsp-server-ean4-issue-2.pdf */
    static constexpr std::uint64_t BUFFER_MAX = (16 * 1024);

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

    RspIterator begin() const { return RspIterator((std::uint8_t*)&this->m_data[0]); }
    RspIterator end() const { return RspIterator((std::uint8_t*)&this->m_data[this->m_size]); }
    ReverseRspIterator rbegin() const { return ReverseRspIterator((std::uint8_t*)&this->m_data[this->m_size]); }
    ReverseRspIterator rend() const { return ReverseRspIterator((std::uint8_t*)&this->m_data[0]); }
    ConstRspIterator cbegin() const { return ConstRspIterator((std::uint8_t*)&this->m_data[0]); }
    ConstRspIterator cend() const { return ConstRspIterator((std::uint8_t*)&this->m_data[this->m_size]); }

    RspData() {}

    template <typename... Args>
    explicit RspData(const std::string& string, Args... args) {
        if ( string.size() > RspData::BUFFER_MAX )
            throw std::runtime_error("size > rsp BUFFER_MAX");

        char buffer[RspData::BUFFER_MAX]{};
        std::sprintf(buffer, string.c_str(), args...);

        this->m_size = std::string(buffer).size();
        std::memcpy(this->m_data, buffer, this->m_size);
    }

    explicit RspData(const std::string& str) : m_size(str.size())
    {
        if ( str.size() > RspData::BUFFER_MAX )
            throw std::runtime_error("size > rsp BUFFER_MAX");

        std::memcpy(this->m_data, str.data(), str.size());
    }

    RspData(void* data, std::size_t size) : m_size(size)
    {
        if ( size > RspData::BUFFER_MAX )
            throw std::runtime_error("size > rsp BUFFER_MAX");

        std::memcpy(this->m_data, data, size);
    }

    RspData(char* data, std::size_t size) : m_size(size)
    {
        if ( size > RspData::BUFFER_MAX )
            throw std::runtime_error("size > rsp BUFFER_MAX");

        std::memcpy(this->m_data, data, size);
    }

    [[nodiscard]] std::string AsString() const
    {
        return std::string((char*)this->m_data, this->m_size);
    }

    std::uint8_t m_data[RspData::BUFFER_MAX]{};
    std::size_t m_size{};
};

class RspConnector
{
    Socket* m_socket{};
    bool m_acksEnabled{true};
    std::vector<std::string> m_serverCapabilities{};
    int m_maxPacketLength{0xfff};

public:
    RspConnector() = default;
    RspConnector(Socket* socket);
    ~RspConnector();

    static RspData BinaryDecode(const RspData& data);
    static RspData DecodeRLE(const RspData& data);
    static std::unordered_map<std::string, std::uint64_t> PacketToUnorderedMap(const RspData& data);
    static std::vector<std::string> Split(const std::string& string, const std::string& regex);

    template <typename Ty>
    static Ty SwapEndianness(Ty value) {
        union {
            Ty m_val;
            std::array<std::uint8_t, sizeof(Ty)> m_raw;
        } source{value}, dest{};
        std::reverse_copy(source.m_raw.begin(), source.m_raw.end(), dest.m_raw.begin());
        return dest.m_val;
    }


    void EnableAcks();
    void DisableAcks();

    char ExpectAck();
    void SendAck() const;

    void NegotiateCapabilities(const std::vector<std::string>& capabilities);

    void SendRaw(const RspData& data) const;
    void SendPayload(const RspData& data) const;

    RspData ReceiveRspData() const;
    RspData TransmitAndReceive(const RspData& data, const std::string& expect = "ack_then_reply", bool async = false);
    void HandleAsyncPacket(const RspData& data);

    std::string GetXml(const std::string& name);
};