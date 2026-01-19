/*
 * Minimal ZIP library for WinDbg installer
 * Based on ZIP file format specification
 *
 * Copyright 2020-2026 Vector 35 Inc.
 * Licensed under the Apache License, Version 2.0
 */

#ifndef MZ_H
#define MZ_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Error codes */
#define MZ_OK                   0
#define MZ_STREAM_ERROR         (-1)
#define MZ_DATA_ERROR           (-2)
#define MZ_MEM_ERROR            (-3)
#define MZ_END_ERROR            (-4)
#define MZ_OPEN_ERROR           (-5)
#define MZ_CLOSE_ERROR          (-6)
#define MZ_SEEK_ERROR           (-7)
#define MZ_EXIST_ERROR          (-8)
#define MZ_PARAM_ERROR          (-9)

/* Compression methods */
#define MZ_COMPRESS_METHOD_STORE    0
#define MZ_COMPRESS_METHOD_DEFLATE  8

/* ZIP signatures */
#define MZ_ZIP_SIGNATURE_LOCALHEADER    0x04034b50
#define MZ_ZIP_SIGNATURE_DATADESCRIPTOR 0x08074b50
#define MZ_ZIP_SIGNATURE_CENTRALDIR     0x02014b50
#define MZ_ZIP_SIGNATURE_ENDOFCENTRALDIR 0x06054b50

#ifdef __cplusplus
}
#endif

#endif /* MZ_H */
