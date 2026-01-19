/*
 * Minimal DEFLATE decompressor implementation
 * Based on RFC 1951
 *
 * Copyright 2020-2026 Vector 35 Inc.
 * Licensed under the Apache License, Version 2.0
 */

#include "mz_inflate.h"
#include "mz.h"
#include <cstring>
#include <algorithm>

namespace mz {

namespace {

/* Bit reader for reading variable-length bit fields */
class BitReader {
public:
    BitReader(const uint8_t* data, size_t size)
        : m_data(data), m_size(size), m_pos(0), m_bitBuf(0), m_bitCount(0) {}

    bool HasBits(int count) const {
        return m_pos < m_size || m_bitCount >= count;
    }

    uint32_t ReadBits(int count) {
        while (m_bitCount < count && m_pos < m_size) {
            m_bitBuf |= (uint32_t)m_data[m_pos++] << m_bitCount;
            m_bitCount += 8;
        }
        uint32_t value = m_bitBuf & ((1u << count) - 1);
        m_bitBuf >>= count;
        m_bitCount -= count;
        return value;
    }

    uint32_t PeekBits(int count) {
        while (m_bitCount < count && m_pos < m_size) {
            m_bitBuf |= (uint32_t)m_data[m_pos++] << m_bitCount;
            m_bitCount += 8;
        }
        return m_bitBuf & ((1u << count) - 1);
    }

    void DropBits(int count) {
        m_bitBuf >>= count;
        m_bitCount -= count;
    }

    void AlignToByte() {
        m_bitBuf >>= (m_bitCount & 7);
        m_bitCount &= ~7;
    }

    size_t BytePos() const { return m_pos; }
    const uint8_t* Data() const { return m_data; }
    size_t Size() const { return m_size; }

private:
    const uint8_t* m_data;
    size_t m_size;
    size_t m_pos;
    uint32_t m_bitBuf;
    int m_bitCount;
};

/* Huffman decoder */
class HuffmanDecoder {
public:
    static constexpr int MAX_BITS = 15;
    static constexpr int MAX_SYMBOLS = 288;

    HuffmanDecoder() : m_maxCode(0) {
        std::memset(m_counts, 0, sizeof(m_counts));
        std::memset(m_symbols, 0, sizeof(m_symbols));
        std::memset(m_firstCode, 0, sizeof(m_firstCode));
        std::memset(m_firstSymIdx, 0, sizeof(m_firstSymIdx));
    }

    bool Build(const uint8_t* lengths, int numSymbols) {
        std::memset(m_counts, 0, sizeof(m_counts));

        /* Count code lengths */
        for (int i = 0; i < numSymbols; i++) {
            if (lengths[i] > MAX_BITS) return false;
            m_counts[lengths[i]]++;
        }
        m_counts[0] = 0;

        /* Find max code length */
        m_maxCode = MAX_BITS;
        while (m_maxCode > 0 && m_counts[m_maxCode] == 0) m_maxCode--;

        /* Calculate first code for each length */
        uint32_t code = 0;
        int symIdx = 0;
        for (int len = 1; len <= m_maxCode; len++) {
            m_firstCode[len] = code;
            m_firstSymIdx[len] = symIdx;
            code += m_counts[len];
            symIdx += m_counts[len];
            code <<= 1;
        }

        /* Build symbol table sorted by code */
        std::memset(m_symbols, 0, sizeof(m_symbols));
        int nextIdx[MAX_BITS + 1];
        for (int i = 0; i <= MAX_BITS; i++) {
            nextIdx[i] = m_firstSymIdx[i];
        }

        for (int sym = 0; sym < numSymbols; sym++) {
            int len = lengths[sym];
            if (len > 0) {
                m_symbols[nextIdx[len]++] = sym;
            }
        }

        return true;
    }

    int Decode(BitReader& br) const {
        uint32_t code = 0;
        for (int len = 1; len <= m_maxCode; len++) {
            if (!br.HasBits(1)) return -1;
            code = (code << 1) | br.ReadBits(1);
            int count = m_counts[len];
            if (count > 0) {
                uint32_t first = m_firstCode[len];
                if (code >= first && code < first + count) {
                    return m_symbols[m_firstSymIdx[len] + (code - first)];
                }
            }
        }
        return -1;
    }

private:
    int m_counts[MAX_BITS + 1];
    int m_symbols[MAX_SYMBOLS];
    uint32_t m_firstCode[MAX_BITS + 1];
    int m_firstSymIdx[MAX_BITS + 1];
    int m_maxCode;
};

/* Fixed Huffman tables for literals/lengths */
static const uint8_t kFixedLitLenLengths[288] = {
    8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8, 8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
    8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8, 8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
    8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8, 8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
    8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8, 8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
    8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8, 9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,
    9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9, 9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,
    9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9, 9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,
    9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9, 9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7, 7,7,7,7,7,7,7,7,8,8,8,8,8,8,8,8
};

/* Fixed Huffman tables for distances */
static const uint8_t kFixedDistLengths[32] = {
    5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5, 5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5
};

/* Length code extra bits and base values */
static const uint8_t kLengthExtraBits[29] = {
    0,0,0,0,0,0,0,0, 1,1,1,1, 2,2,2,2, 3,3,3,3, 4,4,4,4, 5,5,5,5, 0
};
static const uint16_t kLengthBase[29] = {
    3,4,5,6,7,8,9,10, 11,13,15,17, 19,23,27,31, 35,43,51,59, 67,83,99,115, 131,163,195,227, 258
};

/* Distance code extra bits and base values */
static const uint8_t kDistExtraBits[30] = {
    0,0,0,0, 1,1,2,2, 3,3,4,4, 5,5,6,6, 7,7,8,8, 9,9,10,10, 11,11,12,12, 13,13
};
static const uint16_t kDistBase[30] = {
    1,2,3,4, 5,7,9,13, 17,25,33,49, 65,97,129,193, 257,385,513,769,
    1025,1537,2049,3073, 4097,6145,8193,12289, 16385,24577
};

/* Code length alphabet order */
static const uint8_t kCodeLengthOrder[19] = {
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15
};

int InflateBlock(BitReader& br, uint8_t* output, size_t outputSize, size_t& outPos,
                 const HuffmanDecoder& litLenDecoder, const HuffmanDecoder& distDecoder) {
    while (true) {
        int sym = litLenDecoder.Decode(br);
        if (sym < 0) return MZ_DATA_ERROR;

        if (sym < 256) {
            /* Literal byte */
            if (outPos >= outputSize) return MZ_DATA_ERROR;
            output[outPos++] = (uint8_t)sym;
        } else if (sym == 256) {
            /* End of block */
            return MZ_OK;
        } else {
            /* Length/distance pair */
            int lenIdx = sym - 257;
            if (lenIdx >= 29) return MZ_DATA_ERROR;

            int length = kLengthBase[lenIdx];
            int extraBits = kLengthExtraBits[lenIdx];
            if (extraBits > 0) {
                if (!br.HasBits(extraBits)) return MZ_DATA_ERROR;
                length += br.ReadBits(extraBits);
            }

            int distSym = distDecoder.Decode(br);
            if (distSym < 0 || distSym >= 30) return MZ_DATA_ERROR;

            int distance = kDistBase[distSym];
            extraBits = kDistExtraBits[distSym];
            if (extraBits > 0) {
                if (!br.HasBits(extraBits)) return MZ_DATA_ERROR;
                distance += br.ReadBits(extraBits);
            }

            /* Copy from back reference */
            if ((size_t)distance > outPos) return MZ_DATA_ERROR;
            if (outPos + length > outputSize) return MZ_DATA_ERROR;

            size_t srcPos = outPos - distance;
            for (int i = 0; i < length; i++) {
                output[outPos++] = output[srcPos++];
            }
        }
    }
}

} // anonymous namespace

int Inflate(const uint8_t* input, size_t inputSize,
            uint8_t* output, size_t outputSize,
            size_t* bytesWritten) {
    if (!input || !output || inputSize == 0 || outputSize == 0) {
        return MZ_PARAM_ERROR;
    }

    BitReader br(input, inputSize);
    size_t outPos = 0;
    bool finalBlock = false;

    while (!finalBlock) {
        if (!br.HasBits(3)) return MZ_DATA_ERROR;

        finalBlock = br.ReadBits(1) != 0;
        int blockType = br.ReadBits(2);

        if (blockType == 0) {
            /* Stored block (no compression) */
            br.AlignToByte();

            if (!br.HasBits(32)) return MZ_DATA_ERROR;
            uint16_t len = br.ReadBits(16);
            uint16_t nlen = br.ReadBits(16);

            if ((len ^ nlen) != 0xFFFF) return MZ_DATA_ERROR;

            size_t pos = br.BytePos();
            if (pos + len > br.Size()) return MZ_DATA_ERROR;
            if (outPos + len > outputSize) return MZ_DATA_ERROR;

            std::memcpy(output + outPos, br.Data() + pos, len);
            outPos += len;

            /* Skip past the stored data in bit reader */
            for (uint16_t i = 0; i < len; i++) {
                br.ReadBits(8);
            }
        } else if (blockType == 1) {
            /* Fixed Huffman codes */
            HuffmanDecoder litLenDecoder, distDecoder;

            if (!litLenDecoder.Build(kFixedLitLenLengths, 288)) return MZ_DATA_ERROR;
            if (!distDecoder.Build(kFixedDistLengths, 32)) return MZ_DATA_ERROR;

            int result = InflateBlock(br, output, outputSize, outPos, litLenDecoder, distDecoder);
            if (result != MZ_OK) return result;
        } else if (blockType == 2) {
            /* Dynamic Huffman codes */
            if (!br.HasBits(14)) return MZ_DATA_ERROR;

            int hlit = br.ReadBits(5) + 257;
            int hdist = br.ReadBits(5) + 1;
            int hclen = br.ReadBits(4) + 4;

            if (hlit > 286 || hdist > 30) return MZ_DATA_ERROR;

            /* Read code length code lengths */
            uint8_t codeLengthLengths[19] = {0};
            for (int i = 0; i < hclen; i++) {
                if (!br.HasBits(3)) return MZ_DATA_ERROR;
                codeLengthLengths[kCodeLengthOrder[i]] = br.ReadBits(3);
            }

            HuffmanDecoder codeLengthDecoder;
            if (!codeLengthDecoder.Build(codeLengthLengths, 19)) return MZ_DATA_ERROR;

            /* Read literal/length and distance code lengths */
            uint8_t lengths[286 + 30];
            int totalCodes = hlit + hdist;
            int i = 0;

            while (i < totalCodes) {
                int sym = codeLengthDecoder.Decode(br);
                if (sym < 0) return MZ_DATA_ERROR;

                if (sym < 16) {
                    lengths[i++] = sym;
                } else if (sym == 16) {
                    if (i == 0) return MZ_DATA_ERROR;
                    if (!br.HasBits(2)) return MZ_DATA_ERROR;
                    int repeat = br.ReadBits(2) + 3;
                    uint8_t prevLen = lengths[i - 1];
                    while (repeat-- > 0 && i < totalCodes) {
                        lengths[i++] = prevLen;
                    }
                } else if (sym == 17) {
                    if (!br.HasBits(3)) return MZ_DATA_ERROR;
                    int repeat = br.ReadBits(3) + 3;
                    while (repeat-- > 0 && i < totalCodes) {
                        lengths[i++] = 0;
                    }
                } else if (sym == 18) {
                    if (!br.HasBits(7)) return MZ_DATA_ERROR;
                    int repeat = br.ReadBits(7) + 11;
                    while (repeat-- > 0 && i < totalCodes) {
                        lengths[i++] = 0;
                    }
                } else {
                    return MZ_DATA_ERROR;
                }
            }

            HuffmanDecoder litLenDecoder, distDecoder;
            if (!litLenDecoder.Build(lengths, hlit)) return MZ_DATA_ERROR;
            if (!distDecoder.Build(lengths + hlit, hdist)) return MZ_DATA_ERROR;

            int result = InflateBlock(br, output, outputSize, outPos, litLenDecoder, distDecoder);
            if (result != MZ_OK) return result;
        } else {
            /* Reserved block type */
            return MZ_DATA_ERROR;
        }
    }

    if (bytesWritten) *bytesWritten = outPos;
    return MZ_OK;
}

} // namespace mz
