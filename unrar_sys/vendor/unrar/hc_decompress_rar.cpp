// Standalone RAR3 decrypt + decompress from memory using a *pre-derived* AES-128
// key + CBC IV (instead of a password), returning the CRC-32 of the decompressed
// output for the caller to compare. Useful when the key has already been computed
// elsewhere and the archive is held in memory.
//
// Adapted to unrar 7.x: reads packed input from memory, chunked (so any packed
// size works), lets Unpack allocate its own window, and wraps DoUnpack in
// try/catch so a wrong-key garbage stream can't escape.
//
// CREDITS: the UnRAR decompressor belongs to the UnRAR project (rarlab.com);
// see license.txt. This file only orchestrates its public/extended API.

#include "rar.hpp"

// LZ window size for RAR3 (Unp.Init allocates internally). RAR 2.9/3.x supports
// dictionaries up to 4 MiB; using the max is always safe (back-references stay
// within the archive's actual, smaller-or-equal dictionary distance) and avoids
// needing the per-file dict-size flag.
#define HC_WINSIZE 0x400000

extern "C" unsigned int hc_decompress_rar(
  unsigned char *OutBuf,            // caller-provided, >= UnpackSize bytes
  const unsigned char *Input,       // packed (AES-CBC) bytes
  unsigned int PackSize,            // packed size (whole 16-byte blocks)
  unsigned int UnpackSize,          // expected decompressed size
  const unsigned char *Key,         // 16-byte AES-128 key
  const unsigned char *IV,          // 16-byte CBC IV
  unsigned int *unpack_failed)      // out: 1 if the output size didn't match
{
  *unpack_failed = 1;

  ComprDataIO DataIO;               // ctor calls Init() -> all flags cleared
  DataIO.EnableShowProgress(false);
  DataIO.InitRijindal((byte *) Key, (byte *) IV);     // Decryption=true + key/IV
  DataIO.SetPackedSizeToRead((int64) PackSize);
  DataIO.SetTestMode(false);
  DataIO.SetSkipUnpCRC(false);
  DataIO.UnpHash.Init(HASH_CRC32, 1);
  DataIO.SetUnpackFromMemory((byte *) Input, (size_t) PackSize);
  DataIO.SetUnpackToMemory(OutBuf, UnpackSize);

  unsigned int crc32 = 0;
  try
  {
    Unpack Unp(&DataIO);
    Unp.Init(HC_WINSIZE, false);
    Unp.SetDestSize((int64) UnpackSize);
    Unp.DoUnpack(VER_UNPACK, false);                  // VER_UNPACK = 29 (RAR3)

    *unpack_failed = (Unp.GetWrittenFileSize() != (int64) UnpackSize) ? 1u : 0u;
    crc32 = (unsigned int) DataIO.UnpHash.GetCRC32();
  }
  catch (...)
  {
    // Wrong key / corrupt stream: unrar throws RAR_EXIT under RARDLL. Treat as
    // a non-match rather than letting it propagate to the caller.
    *unpack_failed = 1;
    return 0;
  }

  return crc32;
}
