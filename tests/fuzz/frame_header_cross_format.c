/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under both the BSD-style license (found in the
 * LICENSE file in the root directory of this source tree) and the GPLv2 (found
 * in the COPYING file in the root directory of this source tree).
 * You may select, at your option, one of the above-listed licenses.
 */

/**
 * This fuzz target validates that ZSTD_getFrameHeader_advanced() is consistent between
 * ZSTD_f_zstd1 format and ZSTD_f_zstd1_magicless format.
 */

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "fuzz_helpers.h"
#define ZSTD_STATIC_LINKING_ONLY
#include "zstd.h"
#include "fuzz_data_producer.h"

#include <stdio.h>
void prettyPrint(ZSTD_frameHeader* header) {
    printf("ZSTD_frameHeader:\n");
    printf("  frameContentSize: %llu\n", header->frameContentSize);
    printf("  windowSize: %llu\n", header->windowSize);
    printf("  blockSizeMax: %u\n", header->blockSizeMax);
    printf("  frameType: %s\n", header->frameType == ZSTD_frame ? "ZSTD_frame" : "ZSTD_skippableFrame");
    printf("  headerSize: %u\n", header->headerSize);
    printf("  dictID: %u\n", header->dictID);
    printf("  checksumFlag: %u\n", header->checksumFlag);
    printf("  _reserved1: %u\n", header->_reserved1);
    printf("  _reserved2: %u\n", header->_reserved2);
}

int LLVMFuzzerTestOneInput(const uint8_t *magiclessSrc, size_t magiclessSize)
{
    const int zstd_magic = ZSTD_MAGICNUMBER;
    FUZZ_ASSERT(sizeof(zstd_magic) == 4); // assume sizeof(int) == 4
    const size_t standardSize = sizeof(zstd_magic) + magiclessSize;
    void* standardSrc = FUZZ_malloc(standardSize);
    memcpy(standardSrc, &zstd_magic, sizeof(zstd_magic)); // assume fuzzing on little-endian machine
    memcpy(standardSrc + sizeof(zstd_magic), magiclessSrc, magiclessSize);
    
    ZSTD_frameHeader header_magicless;
    ZSTD_frameHeader header_standard;
    
    // TODO: use fuzz data producer here
    memset(&header_magicless, 0xAB, sizeof(ZSTD_frameHeader));
    memset(&header_standard, 0xCD, sizeof(ZSTD_frameHeader));

    const size_t magicless_ret = ZSTD_getFrameHeader_advanced(
                                    &header_magicless, magiclessSrc, magiclessSize, ZSTD_f_zstd1_magicless);
    const size_t standard_ret = ZSTD_getFrameHeader_advanced(
                                    &header_standard, standardSrc, standardSize, ZSTD_f_zstd1);
    
    // If magicless frame header is valid, then standard frame header should match
    if (magicless_ret == 0) {
        FUZZ_ASSERT(standard_ret == 0);

        // headerSize is not expected to be equal between formats
        FUZZ_ASSERT(header_magicless.headerSize + sizeof(zstd_magic) == header_standard.headerSize);

        // Assert that all other fields are equal
        header_magicless.headerSize = 0;
        header_standard.headerSize = 0;
        FUZZ_ASSERT(memcmp(&header_magicless, &header_standard, sizeof(ZSTD_frameHeader)) == 0);
    }

    free(standardSrc);
    return 0;
}
