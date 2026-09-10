#pragma once

#include <utility>
#include <mutex>
#include <vector>
#include <cstdint>

#include "socket_handle.h"
#include <x2win_generated.h>

// A parsed x2win::Envelope is just a read-only view into a byte buffer (unlike a Protobuf
// message, it owns no state of its own) -- something has to keep that buffer alive for as long as
// the view is used. This pairs the two: Get()/BodyAs() are only valid while this object (or a
// copy of its `bytes`) is alive. An empty `bytes` (default-constructed, or a send/receive failure)
// is a valid "no message" state -- Get()/BodyAs() return nullptr rather than dereferencing a
// nonexistent buffer. Duplicated from core/adapters/x2winrpcadapter.h's identical helper rather
// than shared through a common header -- x2winstub is intentionally built independent of anything
// in core/ (see debug_types.h's comment on the same tradeoff), and this is small enough that
// duplicating it keeps that independence intact.
struct X2WinEnvelopeBuffer
{
    std::vector<uint8_t> bytes;

    const x2win::Envelope* Get() const
    {
        return bytes.empty() ? nullptr : x2win::GetEnvelope(bytes.data());
    }

    template <typename T>
    const T* BodyAs() const
    {
        const x2win::Envelope* envelope = Get();
        return envelope ? envelope->body_as<T>() : nullptr;
    }
};

class Connection{
    SocketHandle m_socket;
    std::mutex m_writeMutex;

    bool RecvAll(char* buf, int len);
    bool SendAll(const char* buf, int len);

    public:
    explicit Connection(SocketHandle&& socket) : m_socket(std::move(socket)){}

    bool ReadEnvelope(X2WinEnvelopeBuffer& out);
    bool WriteEnvelope(const flatbuffers::FlatBufferBuilder& builder);

};
