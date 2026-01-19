/*
 * Minimal DEFLATE decompressor
 * Based on RFC 1951
 *
 * Copyright 2020-2026 Vector 35 Inc.
 * Licensed under the Apache License, Version 2.0
 */

#ifndef MZ_INFLATE_H
#define MZ_INFLATE_H

#include <cstdint>
#include <cstddef>

namespace mz {

/*
 * Decompress DEFLATE compressed data
 *
 * @param input Pointer to compressed data
 * @param inputSize Size of compressed data in bytes
 * @param output Pointer to output buffer
 * @param outputSize Size of output buffer in bytes
 * @param bytesWritten Pointer to receive actual bytes written (optional)
 * @return 0 on success, negative error code on failure
 */
int Inflate(const uint8_t* input, size_t inputSize,
            uint8_t* output, size_t outputSize,
            size_t* bytesWritten = nullptr);

} // namespace mz

#endif /* MZ_INFLATE_H */
