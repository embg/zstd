#include "external_matchfinder.h"
#include <string.h>
#include "zstd_compress_internal.h"
#include <stdio.h>

#define HSIZE 1024
static U32 const HLOG = 10;
static U32 const MLS = 4;
static U32 const BADIDX = (1 << 31);

static size_t simpleExternalMatchFinder(
  void* externalMatchState,
  ZSTD_Sequence* outSeqs, size_t outSeqsCapacity,
  const void* src, size_t srcSize,
  const void* dict, size_t dictSize,
  int compressionLevel
) {
    const BYTE* const istart = (const BYTE*)src;
    const BYTE* const iend = istart + srcSize;
    const BYTE* ip = istart;
    const BYTE* anchor = istart;
    size_t seqCount = 0;
    U32 hashTable[HSIZE];

    (void)externalMatchState;
    (void)dict;
    (void)dictSize;
    (void)outSeqsCapacity;
    (void)compressionLevel;

    {   int i;
        for (i=0; i < HSIZE; i++) {
            hashTable[i] = BADIDX;
    }   }

    while (ip + 4 < iend) {
        size_t const hash = ZSTD_hashPtr(ip, HLOG, MLS);
        U32 const matchIndex = hashTable[hash];
        hashTable[hash] = ip - istart;

        if (matchIndex != BADIDX) {
            const BYTE* const match = istart + matchIndex;
            size_t const matchLen = ZSTD_count(ip, match, iend);
            if (matchLen >= ZSTD_MINMATCH_MIN) {
                U32 const litLen = ip - anchor;
                U32 const offset = ip - match;
                ZSTD_Sequence const seq = {
                    offset, litLen, matchLen, 0
                };
                outSeqs[seqCount++] = seq;
                ip += matchLen;
                anchor = ip;
                continue;
            }
        }

        ip++;
    }

    {   ZSTD_Sequence const finalSeq = {
            0, iend - anchor, 0, 0
        };
        outSeqs[seqCount++] = finalSeq;
    }

    return seqCount;
}

size_t zstreamExternalMatchFinder(
  void* externalMatchState,
  ZSTD_Sequence* outSeqs, size_t outSeqsCapacity,
  const void* src, size_t srcSize,
  const void* dict, size_t dictSize,
  int compressionLevel
) {
    EMF_testCase testCase = *((EMF_testCase*)externalMatchState);
    memset(outSeqs, 0, outSeqsCapacity);

    switch (testCase) {
        case EMF_ZERO_SEQS:
            return 0;
        case EMF_ONE_BIG_SEQ:
            outSeqs[0].offset = 0;
            outSeqs[0].matchLength = 0;
            outSeqs[0].litLength = srcSize;
            return 1;
         case EMF_LOTS_OF_SEQS:
            return simpleExternalMatchFinder(
                externalMatchState,
                outSeqs, outSeqsCapacity,
                src, srcSize,
                dict, dictSize,
                compressionLevel
            );
        case EMF_SMALL_ERROR:
            return outSeqsCapacity + 1;
        case EMF_BIG_ERROR:
        default:
            return ZSTD_EXTERNAL_MATCHFINDER_ERROR;
    }
}