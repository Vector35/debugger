#include "connection.h"

#include <cstdint>
#include <string>

bool Connection::RecvAll(char* buf, int len){
    int received = 0;
    while (received < len) {
        int n = recv(m_socket.get(), buf + received, len - received, 0);
        if(n <= 0) return  false;
        received += n;
    }

    return true;
}

bool Connection::SendAll(const char *buf, int len){
    int sent = 0;
    while(sent < len){
        int n = send(m_socket.get(), buf+sent, len-sent, 0);
        if(n <= 0) return false;
        sent += n;
    }
    return true;
}

bool Connection::ReadEnvelope(X2WinEnvelopeBuffer &out){
    uint32_t bodyLen = 0;
    if(!RecvAll(reinterpret_cast<char*>(&bodyLen), sizeof(bodyLen))) return false;

    out.bytes.resize(bodyLen);
    if(bodyLen > 0 && !RecvAll(reinterpret_cast<char*>(out.bytes.data()), static_cast<int>(bodyLen))) return false;

    // Unlike Protobuf's ParseFromString, FlatBuffers does no validation on access by default --
    // Get()/BodyAs() below would just reinterpret these bytes as a table, and reading fields out
    // of a truncated/corrupted buffer is an out-of-bounds read, not a clean failure. Verifier is
    // what actually plays ParseFromString's role here: walking the buffer to confirm every
    // offset/vector/string is in-bounds before anything touches it.
    flatbuffers::Verifier verifier(out.bytes.data(), out.bytes.size());
    return x2win::VerifyEnvelopeBuffer(verifier);
}

bool Connection::WriteEnvelope(const flatbuffers::FlatBufferBuilder &builder){
    std::lock_guard<std::mutex> lock(m_writeMutex);

    uint32_t bodyLen = static_cast<uint32_t>(builder.GetSize());
    if(!SendAll(reinterpret_cast<const char*>(&bodyLen), sizeof(bodyLen))) return false;

    if(bodyLen > 0 && !SendAll(reinterpret_cast<const char*>(builder.GetBufferPointer()), static_cast<int>(bodyLen))) return false;

    return true;
}