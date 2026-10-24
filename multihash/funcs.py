# py-multihash: Python implementation of the multihash specification

"""Enumeration of standard multihash functions, and function registry.

This module provides:
- Func: IntEnum of supported hash functions
- FuncReg: Registry for managing hash function implementations
- IdentityHash: hashlib-compatible identity hash
- ShakeHash: Wrapper for variable-length SHAKE hashes

The FuncReg class maintains a registry of hash functions that can be:
- Retrieved by code, name, or hashlib object
- Extended with custom app-specific functions (codes 0x01-0x0F)
- Used to create hashlib-compatible hash objects

Standard functions are pre-registered. App-specific functions can be
registered/unregistered at runtime.
"""

import hashlib
from collections import namedtuple
from collections.abc import Callable
from enum import IntEnum
from numbers import Integral
from typing import Any, ClassVar

import blake3
import mmh3

from .constants import HASH_CODES


def _is_app_specific_func(code: int) -> bool:
    """Is the given hash function integer `code` application-specific?"""
    return isinstance(code, Integral) and (0x01 <= code <= 0x0F)


class Func(IntEnum):
    """An enumeration of hash functions supported by multihash.

    The name of each member has its hyphens replaced by underscores.
    The value of each member corresponds to its integer code.

    >>> Func.sha2_512.value == 0x13
    True
    """

    # Standard multihash functions, sorted by name
    bcrypt_pbkdf = HASH_CODES["bcrypt-pbkdf"]  # 0xD00D
    bittorrent_pieces_root = HASH_CODES["bittorrent-pieces-root"]  # 0xB702
    blake2b_8 = HASH_CODES["blake2b-8"]  # 0xB201
    blake2b_16 = HASH_CODES["blake2b-16"]  # 0xB202
    blake2b_24 = HASH_CODES["blake2b-24"]  # 0xB203
    blake2b_32 = HASH_CODES["blake2b-32"]  # 0xB204
    blake2b_40 = HASH_CODES["blake2b-40"]  # 0xB205
    blake2b_48 = HASH_CODES["blake2b-48"]  # 0xB206
    blake2b_56 = HASH_CODES["blake2b-56"]  # 0xB207
    blake2b_64 = HASH_CODES["blake2b-64"]  # 0xB208
    blake2b_72 = HASH_CODES["blake2b-72"]  # 0xB209
    blake2b_80 = HASH_CODES["blake2b-80"]  # 0xB20A
    blake2b_88 = HASH_CODES["blake2b-88"]  # 0xB20B
    blake2b_96 = HASH_CODES["blake2b-96"]  # 0xB20C
    blake2b_104 = HASH_CODES["blake2b-104"]  # 0xB20D
    blake2b_112 = HASH_CODES["blake2b-112"]  # 0xB20E
    blake2b_120 = HASH_CODES["blake2b-120"]  # 0xB20F
    blake2b_128 = HASH_CODES["blake2b-128"]  # 0xB210
    blake2b_136 = HASH_CODES["blake2b-136"]  # 0xB211
    blake2b_144 = HASH_CODES["blake2b-144"]  # 0xB212
    blake2b_152 = HASH_CODES["blake2b-152"]  # 0xB213
    blake2b_160 = HASH_CODES["blake2b-160"]  # 0xB214
    blake2b_168 = HASH_CODES["blake2b-168"]  # 0xB215
    blake2b_176 = HASH_CODES["blake2b-176"]  # 0xB216
    blake2b_184 = HASH_CODES["blake2b-184"]  # 0xB217
    blake2b_192 = HASH_CODES["blake2b-192"]  # 0xB218
    blake2b_200 = HASH_CODES["blake2b-200"]  # 0xB219
    blake2b_208 = HASH_CODES["blake2b-208"]  # 0xB21A
    blake2b_216 = HASH_CODES["blake2b-216"]  # 0xB21B
    blake2b_224 = HASH_CODES["blake2b-224"]  # 0xB21C
    blake2b_232 = HASH_CODES["blake2b-232"]  # 0xB21D
    blake2b_240 = HASH_CODES["blake2b-240"]  # 0xB21E
    blake2b_248 = HASH_CODES["blake2b-248"]  # 0xB21F
    blake2b_256 = HASH_CODES["blake2b-256"]  # 0xB220
    blake2b_264 = HASH_CODES["blake2b-264"]  # 0xB221
    blake2b_272 = HASH_CODES["blake2b-272"]  # 0xB222
    blake2b_280 = HASH_CODES["blake2b-280"]  # 0xB223
    blake2b_288 = HASH_CODES["blake2b-288"]  # 0xB224
    blake2b_296 = HASH_CODES["blake2b-296"]  # 0xB225
    blake2b_304 = HASH_CODES["blake2b-304"]  # 0xB226
    blake2b_312 = HASH_CODES["blake2b-312"]  # 0xB227
    blake2b_320 = HASH_CODES["blake2b-320"]  # 0xB228
    blake2b_328 = HASH_CODES["blake2b-328"]  # 0xB229
    blake2b_336 = HASH_CODES["blake2b-336"]  # 0xB22A
    blake2b_344 = HASH_CODES["blake2b-344"]  # 0xB22B
    blake2b_352 = HASH_CODES["blake2b-352"]  # 0xB22C
    blake2b_360 = HASH_CODES["blake2b-360"]  # 0xB22D
    blake2b_368 = HASH_CODES["blake2b-368"]  # 0xB22E
    blake2b_376 = HASH_CODES["blake2b-376"]  # 0xB22F
    blake2b_384 = HASH_CODES["blake2b-384"]  # 0xB230
    blake2b_392 = HASH_CODES["blake2b-392"]  # 0xB231
    blake2b_400 = HASH_CODES["blake2b-400"]  # 0xB232
    blake2b_408 = HASH_CODES["blake2b-408"]  # 0xB233
    blake2b_416 = HASH_CODES["blake2b-416"]  # 0xB234
    blake2b_424 = HASH_CODES["blake2b-424"]  # 0xB235
    blake2b_432 = HASH_CODES["blake2b-432"]  # 0xB236
    blake2b_440 = HASH_CODES["blake2b-440"]  # 0xB237
    blake2b_448 = HASH_CODES["blake2b-448"]  # 0xB238
    blake2b_456 = HASH_CODES["blake2b-456"]  # 0xB239
    blake2b_464 = HASH_CODES["blake2b-464"]  # 0xB23A
    blake2b_472 = HASH_CODES["blake2b-472"]  # 0xB23B
    blake2b_480 = HASH_CODES["blake2b-480"]  # 0xB23C
    blake2b_488 = HASH_CODES["blake2b-488"]  # 0xB23D
    blake2b_496 = HASH_CODES["blake2b-496"]  # 0xB23E
    blake2b_504 = HASH_CODES["blake2b-504"]  # 0xB23F
    blake2b_512 = HASH_CODES["blake2b-512"]  # 0xB240
    blake2s_8 = HASH_CODES["blake2s-8"]  # 0xB241
    blake2s_16 = HASH_CODES["blake2s-16"]  # 0xB242
    blake2s_24 = HASH_CODES["blake2s-24"]  # 0xB243
    blake2s_32 = HASH_CODES["blake2s-32"]  # 0xB244
    blake2s_40 = HASH_CODES["blake2s-40"]  # 0xB245
    blake2s_48 = HASH_CODES["blake2s-48"]  # 0xB246
    blake2s_56 = HASH_CODES["blake2s-56"]  # 0xB247
    blake2s_64 = HASH_CODES["blake2s-64"]  # 0xB248
    blake2s_72 = HASH_CODES["blake2s-72"]  # 0xB249
    blake2s_80 = HASH_CODES["blake2s-80"]  # 0xB24A
    blake2s_88 = HASH_CODES["blake2s-88"]  # 0xB24B
    blake2s_96 = HASH_CODES["blake2s-96"]  # 0xB24C
    blake2s_104 = HASH_CODES["blake2s-104"]  # 0xB24D
    blake2s_112 = HASH_CODES["blake2s-112"]  # 0xB24E
    blake2s_120 = HASH_CODES["blake2s-120"]  # 0xB24F
    blake2s_128 = HASH_CODES["blake2s-128"]  # 0xB250
    blake2s_136 = HASH_CODES["blake2s-136"]  # 0xB251
    blake2s_144 = HASH_CODES["blake2s-144"]  # 0xB252
    blake2s_152 = HASH_CODES["blake2s-152"]  # 0xB253
    blake2s_160 = HASH_CODES["blake2s-160"]  # 0xB254
    blake2s_168 = HASH_CODES["blake2s-168"]  # 0xB255
    blake2s_176 = HASH_CODES["blake2s-176"]  # 0xB256
    blake2s_184 = HASH_CODES["blake2s-184"]  # 0xB257
    blake2s_192 = HASH_CODES["blake2s-192"]  # 0xB258
    blake2s_200 = HASH_CODES["blake2s-200"]  # 0xB259
    blake2s_208 = HASH_CODES["blake2s-208"]  # 0xB25A
    blake2s_216 = HASH_CODES["blake2s-216"]  # 0xB25B
    blake2s_224 = HASH_CODES["blake2s-224"]  # 0xB25C
    blake2s_232 = HASH_CODES["blake2s-232"]  # 0xB25D
    blake2s_240 = HASH_CODES["blake2s-240"]  # 0xB25E
    blake2s_248 = HASH_CODES["blake2s-248"]  # 0xB25F
    blake2s_256 = HASH_CODES["blake2s-256"]  # 0xB260
    blake3 = HASH_CODES["blake3"]  # 0x1E
    dbl_sha2_256 = HASH_CODES["dbl-sha2-256"]  # 0x56
    ed2k = HASH_CODES["ed2k"]  # 0xED20
    fr32_sha256_trunc254_padbintree = HASH_CODES["fr32-sha256-trunc254-padbintree"]  # 0x1011
    identity = HASH_CODES["identity"]  # 0x00
    keccak_224 = HASH_CODES["keccak-224"]  # 0x1A
    keccak_256 = HASH_CODES["keccak-256"]  # 0x1B
    keccak_384 = HASH_CODES["keccak-384"]  # 0x1C
    keccak_512 = HASH_CODES["keccak-512"]  # 0x1D
    kt_128 = HASH_CODES["kt-128"]  # 0x1D01
    kt_256 = HASH_CODES["kt-256"]  # 0x1D02
    md4 = HASH_CODES["md4"]  # 0xD4
    md5 = HASH_CODES["md5"]  # 0xD5
    murmur3_32 = HASH_CODES["murmur3-32"]  # 0x23
    murmur3_128 = HASH_CODES["murmur3-128"]  # 0x22
    poseidon_bls12_381_a2_fc1 = HASH_CODES["poseidon-bls12_381-a2-fc1"]  # 0xB401
    poseidon_bls12_381_a2_fc1_sc = HASH_CODES["poseidon-bls12_381-a2-fc1-sc"]  # 0xB402
    ripemd_128 = HASH_CODES["ripemd-128"]  # 0x1052
    ripemd_160 = HASH_CODES["ripemd-160"]  # 0x1053
    ripemd_256 = HASH_CODES["ripemd-256"]  # 0x1054
    ripemd_320 = HASH_CODES["ripemd-320"]  # 0x1055
    sha1 = HASH_CODES["sha1"]  # 0x11
    sha2_224 = HASH_CODES["sha2-224"]  # 0x1013
    sha2_256 = HASH_CODES["sha2-256"]  # 0x12
    sha2_256_chunked = HASH_CODES["sha2-256-chunked"]  # 0xB510
    sha2_256_trunc254_padded = HASH_CODES["sha2-256-trunc254-padded"]  # 0x1012
    sha2_384 = HASH_CODES["sha2-384"]  # 0x20
    sha2_512 = HASH_CODES["sha2-512"]  # 0x13
    sha2_512_224 = HASH_CODES["sha2-512-224"]  # 0x1014
    sha2_512_256 = HASH_CODES["sha2-512-256"]  # 0x1015
    sha3_224 = HASH_CODES["sha3-224"]  # 0x17
    sha3_256 = HASH_CODES["sha3-256"]  # 0x16
    sha3_384 = HASH_CODES["sha3-384"]  # 0x15
    sha3_512 = HASH_CODES["sha3-512"]  # 0x14
    shake_128 = HASH_CODES["shake-128"]  # 0x18
    shake_256 = HASH_CODES["shake-256"]  # 0x19
    skein256_8 = HASH_CODES["skein256-8"]  # 0xB301
    skein256_16 = HASH_CODES["skein256-16"]  # 0xB302
    skein256_24 = HASH_CODES["skein256-24"]  # 0xB303
    skein256_32 = HASH_CODES["skein256-32"]  # 0xB304
    skein256_40 = HASH_CODES["skein256-40"]  # 0xB305
    skein256_48 = HASH_CODES["skein256-48"]  # 0xB306
    skein256_56 = HASH_CODES["skein256-56"]  # 0xB307
    skein256_64 = HASH_CODES["skein256-64"]  # 0xB308
    skein256_72 = HASH_CODES["skein256-72"]  # 0xB309
    skein256_80 = HASH_CODES["skein256-80"]  # 0xB30A
    skein256_88 = HASH_CODES["skein256-88"]  # 0xB30B
    skein256_96 = HASH_CODES["skein256-96"]  # 0xB30C
    skein256_104 = HASH_CODES["skein256-104"]  # 0xB30D
    skein256_112 = HASH_CODES["skein256-112"]  # 0xB30E
    skein256_120 = HASH_CODES["skein256-120"]  # 0xB30F
    skein256_128 = HASH_CODES["skein256-128"]  # 0xB310
    skein256_136 = HASH_CODES["skein256-136"]  # 0xB311
    skein256_144 = HASH_CODES["skein256-144"]  # 0xB312
    skein256_152 = HASH_CODES["skein256-152"]  # 0xB313
    skein256_160 = HASH_CODES["skein256-160"]  # 0xB314
    skein256_168 = HASH_CODES["skein256-168"]  # 0xB315
    skein256_176 = HASH_CODES["skein256-176"]  # 0xB316
    skein256_184 = HASH_CODES["skein256-184"]  # 0xB317
    skein256_192 = HASH_CODES["skein256-192"]  # 0xB318
    skein256_200 = HASH_CODES["skein256-200"]  # 0xB319
    skein256_208 = HASH_CODES["skein256-208"]  # 0xB31A
    skein256_216 = HASH_CODES["skein256-216"]  # 0xB31B
    skein256_224 = HASH_CODES["skein256-224"]  # 0xB31C
    skein256_232 = HASH_CODES["skein256-232"]  # 0xB31D
    skein256_240 = HASH_CODES["skein256-240"]  # 0xB31E
    skein256_248 = HASH_CODES["skein256-248"]  # 0xB31F
    skein256_256 = HASH_CODES["skein256-256"]  # 0xB320
    skein512_8 = HASH_CODES["skein512-8"]  # 0xB321
    skein512_16 = HASH_CODES["skein512-16"]  # 0xB322
    skein512_24 = HASH_CODES["skein512-24"]  # 0xB323
    skein512_32 = HASH_CODES["skein512-32"]  # 0xB324
    skein512_40 = HASH_CODES["skein512-40"]  # 0xB325
    skein512_48 = HASH_CODES["skein512-48"]  # 0xB326
    skein512_56 = HASH_CODES["skein512-56"]  # 0xB327
    skein512_64 = HASH_CODES["skein512-64"]  # 0xB328
    skein512_72 = HASH_CODES["skein512-72"]  # 0xB329
    skein512_80 = HASH_CODES["skein512-80"]  # 0xB32A
    skein512_88 = HASH_CODES["skein512-88"]  # 0xB32B
    skein512_96 = HASH_CODES["skein512-96"]  # 0xB32C
    skein512_104 = HASH_CODES["skein512-104"]  # 0xB32D
    skein512_112 = HASH_CODES["skein512-112"]  # 0xB32E
    skein512_120 = HASH_CODES["skein512-120"]  # 0xB32F
    skein512_128 = HASH_CODES["skein512-128"]  # 0xB330
    skein512_136 = HASH_CODES["skein512-136"]  # 0xB331
    skein512_144 = HASH_CODES["skein512-144"]  # 0xB332
    skein512_152 = HASH_CODES["skein512-152"]  # 0xB333
    skein512_160 = HASH_CODES["skein512-160"]  # 0xB334
    skein512_168 = HASH_CODES["skein512-168"]  # 0xB335
    skein512_176 = HASH_CODES["skein512-176"]  # 0xB336
    skein512_184 = HASH_CODES["skein512-184"]  # 0xB337
    skein512_192 = HASH_CODES["skein512-192"]  # 0xB338
    skein512_200 = HASH_CODES["skein512-200"]  # 0xB339
    skein512_208 = HASH_CODES["skein512-208"]  # 0xB33A
    skein512_216 = HASH_CODES["skein512-216"]  # 0xB33B
    skein512_224 = HASH_CODES["skein512-224"]  # 0xB33C
    skein512_232 = HASH_CODES["skein512-232"]  # 0xB33D
    skein512_240 = HASH_CODES["skein512-240"]  # 0xB33E
    skein512_248 = HASH_CODES["skein512-248"]  # 0xB33F
    skein512_256 = HASH_CODES["skein512-256"]  # 0xB340
    skein512_264 = HASH_CODES["skein512-264"]  # 0xB341
    skein512_272 = HASH_CODES["skein512-272"]  # 0xB342
    skein512_280 = HASH_CODES["skein512-280"]  # 0xB343
    skein512_288 = HASH_CODES["skein512-288"]  # 0xB344
    skein512_296 = HASH_CODES["skein512-296"]  # 0xB345
    skein512_304 = HASH_CODES["skein512-304"]  # 0xB346
    skein512_312 = HASH_CODES["skein512-312"]  # 0xB347
    skein512_320 = HASH_CODES["skein512-320"]  # 0xB348
    skein512_328 = HASH_CODES["skein512-328"]  # 0xB349
    skein512_336 = HASH_CODES["skein512-336"]  # 0xB34A
    skein512_344 = HASH_CODES["skein512-344"]  # 0xB34B
    skein512_352 = HASH_CODES["skein512-352"]  # 0xB34C
    skein512_360 = HASH_CODES["skein512-360"]  # 0xB34D
    skein512_368 = HASH_CODES["skein512-368"]  # 0xB34E
    skein512_376 = HASH_CODES["skein512-376"]  # 0xB34F
    skein512_384 = HASH_CODES["skein512-384"]  # 0xB350
    skein512_392 = HASH_CODES["skein512-392"]  # 0xB351
    skein512_400 = HASH_CODES["skein512-400"]  # 0xB352
    skein512_408 = HASH_CODES["skein512-408"]  # 0xB353
    skein512_416 = HASH_CODES["skein512-416"]  # 0xB354
    skein512_424 = HASH_CODES["skein512-424"]  # 0xB355
    skein512_432 = HASH_CODES["skein512-432"]  # 0xB356
    skein512_440 = HASH_CODES["skein512-440"]  # 0xB357
    skein512_448 = HASH_CODES["skein512-448"]  # 0xB358
    skein512_456 = HASH_CODES["skein512-456"]  # 0xB359
    skein512_464 = HASH_CODES["skein512-464"]  # 0xB35A
    skein512_472 = HASH_CODES["skein512-472"]  # 0xB35B
    skein512_480 = HASH_CODES["skein512-480"]  # 0xB35C
    skein512_488 = HASH_CODES["skein512-488"]  # 0xB35D
    skein512_496 = HASH_CODES["skein512-496"]  # 0xB35E
    skein512_504 = HASH_CODES["skein512-504"]  # 0xB35F
    skein512_512 = HASH_CODES["skein512-512"]  # 0xB360
    skein1024_8 = HASH_CODES["skein1024-8"]  # 0xB361
    skein1024_16 = HASH_CODES["skein1024-16"]  # 0xB362
    skein1024_24 = HASH_CODES["skein1024-24"]  # 0xB363
    skein1024_32 = HASH_CODES["skein1024-32"]  # 0xB364
    skein1024_40 = HASH_CODES["skein1024-40"]  # 0xB365
    skein1024_48 = HASH_CODES["skein1024-48"]  # 0xB366
    skein1024_56 = HASH_CODES["skein1024-56"]  # 0xB367
    skein1024_64 = HASH_CODES["skein1024-64"]  # 0xB368
    skein1024_72 = HASH_CODES["skein1024-72"]  # 0xB369
    skein1024_80 = HASH_CODES["skein1024-80"]  # 0xB36A
    skein1024_88 = HASH_CODES["skein1024-88"]  # 0xB36B
    skein1024_96 = HASH_CODES["skein1024-96"]  # 0xB36C
    skein1024_104 = HASH_CODES["skein1024-104"]  # 0xB36D
    skein1024_112 = HASH_CODES["skein1024-112"]  # 0xB36E
    skein1024_120 = HASH_CODES["skein1024-120"]  # 0xB36F
    skein1024_128 = HASH_CODES["skein1024-128"]  # 0xB370
    skein1024_136 = HASH_CODES["skein1024-136"]  # 0xB371
    skein1024_144 = HASH_CODES["skein1024-144"]  # 0xB372
    skein1024_152 = HASH_CODES["skein1024-152"]  # 0xB373
    skein1024_160 = HASH_CODES["skein1024-160"]  # 0xB374
    skein1024_168 = HASH_CODES["skein1024-168"]  # 0xB375
    skein1024_176 = HASH_CODES["skein1024-176"]  # 0xB376
    skein1024_184 = HASH_CODES["skein1024-184"]  # 0xB377
    skein1024_192 = HASH_CODES["skein1024-192"]  # 0xB378
    skein1024_200 = HASH_CODES["skein1024-200"]  # 0xB379
    skein1024_208 = HASH_CODES["skein1024-208"]  # 0xB37A
    skein1024_216 = HASH_CODES["skein1024-216"]  # 0xB37B
    skein1024_224 = HASH_CODES["skein1024-224"]  # 0xB37C
    skein1024_232 = HASH_CODES["skein1024-232"]  # 0xB37D
    skein1024_240 = HASH_CODES["skein1024-240"]  # 0xB37E
    skein1024_248 = HASH_CODES["skein1024-248"]  # 0xB37F
    skein1024_256 = HASH_CODES["skein1024-256"]  # 0xB380
    skein1024_264 = HASH_CODES["skein1024-264"]  # 0xB381
    skein1024_272 = HASH_CODES["skein1024-272"]  # 0xB382
    skein1024_280 = HASH_CODES["skein1024-280"]  # 0xB383
    skein1024_288 = HASH_CODES["skein1024-288"]  # 0xB384
    skein1024_296 = HASH_CODES["skein1024-296"]  # 0xB385
    skein1024_304 = HASH_CODES["skein1024-304"]  # 0xB386
    skein1024_312 = HASH_CODES["skein1024-312"]  # 0xB387
    skein1024_320 = HASH_CODES["skein1024-320"]  # 0xB388
    skein1024_328 = HASH_CODES["skein1024-328"]  # 0xB389
    skein1024_336 = HASH_CODES["skein1024-336"]  # 0xB38A
    skein1024_344 = HASH_CODES["skein1024-344"]  # 0xB38B
    skein1024_352 = HASH_CODES["skein1024-352"]  # 0xB38C
    skein1024_360 = HASH_CODES["skein1024-360"]  # 0xB38D
    skein1024_368 = HASH_CODES["skein1024-368"]  # 0xB38E
    skein1024_376 = HASH_CODES["skein1024-376"]  # 0xB38F
    skein1024_384 = HASH_CODES["skein1024-384"]  # 0xB390
    skein1024_392 = HASH_CODES["skein1024-392"]  # 0xB391
    skein1024_400 = HASH_CODES["skein1024-400"]  # 0xB392
    skein1024_408 = HASH_CODES["skein1024-408"]  # 0xB393
    skein1024_416 = HASH_CODES["skein1024-416"]  # 0xB394
    skein1024_424 = HASH_CODES["skein1024-424"]  # 0xB395
    skein1024_432 = HASH_CODES["skein1024-432"]  # 0xB396
    skein1024_440 = HASH_CODES["skein1024-440"]  # 0xB397
    skein1024_448 = HASH_CODES["skein1024-448"]  # 0xB398
    skein1024_456 = HASH_CODES["skein1024-456"]  # 0xB399
    skein1024_464 = HASH_CODES["skein1024-464"]  # 0xB39A
    skein1024_472 = HASH_CODES["skein1024-472"]  # 0xB39B
    skein1024_480 = HASH_CODES["skein1024-480"]  # 0xB39C
    skein1024_488 = HASH_CODES["skein1024-488"]  # 0xB39D
    skein1024_496 = HASH_CODES["skein1024-496"]  # 0xB39E
    skein1024_504 = HASH_CODES["skein1024-504"]  # 0xB39F
    skein1024_512 = HASH_CODES["skein1024-512"]  # 0xB3A0
    skein1024_520 = HASH_CODES["skein1024-520"]  # 0xB3A1
    skein1024_528 = HASH_CODES["skein1024-528"]  # 0xB3A2
    skein1024_536 = HASH_CODES["skein1024-536"]  # 0xB3A3
    skein1024_544 = HASH_CODES["skein1024-544"]  # 0xB3A4
    skein1024_552 = HASH_CODES["skein1024-552"]  # 0xB3A5
    skein1024_560 = HASH_CODES["skein1024-560"]  # 0xB3A6
    skein1024_568 = HASH_CODES["skein1024-568"]  # 0xB3A7
    skein1024_576 = HASH_CODES["skein1024-576"]  # 0xB3A8
    skein1024_584 = HASH_CODES["skein1024-584"]  # 0xB3A9
    skein1024_592 = HASH_CODES["skein1024-592"]  # 0xB3AA
    skein1024_600 = HASH_CODES["skein1024-600"]  # 0xB3AB
    skein1024_608 = HASH_CODES["skein1024-608"]  # 0xB3AC
    skein1024_616 = HASH_CODES["skein1024-616"]  # 0xB3AD
    skein1024_624 = HASH_CODES["skein1024-624"]  # 0xB3AE
    skein1024_632 = HASH_CODES["skein1024-632"]  # 0xB3AF
    skein1024_640 = HASH_CODES["skein1024-640"]  # 0xB3B0
    skein1024_648 = HASH_CODES["skein1024-648"]  # 0xB3B1
    skein1024_656 = HASH_CODES["skein1024-656"]  # 0xB3B2
    skein1024_664 = HASH_CODES["skein1024-664"]  # 0xB3B3
    skein1024_672 = HASH_CODES["skein1024-672"]  # 0xB3B4
    skein1024_680 = HASH_CODES["skein1024-680"]  # 0xB3B5
    skein1024_688 = HASH_CODES["skein1024-688"]  # 0xB3B6
    skein1024_696 = HASH_CODES["skein1024-696"]  # 0xB3B7
    skein1024_704 = HASH_CODES["skein1024-704"]  # 0xB3B8
    skein1024_712 = HASH_CODES["skein1024-712"]  # 0xB3B9
    skein1024_720 = HASH_CODES["skein1024-720"]  # 0xB3BA
    skein1024_728 = HASH_CODES["skein1024-728"]  # 0xB3BB
    skein1024_736 = HASH_CODES["skein1024-736"]  # 0xB3BC
    skein1024_744 = HASH_CODES["skein1024-744"]  # 0xB3BD
    skein1024_752 = HASH_CODES["skein1024-752"]  # 0xB3BE
    skein1024_760 = HASH_CODES["skein1024-760"]  # 0xB3BF
    skein1024_768 = HASH_CODES["skein1024-768"]  # 0xB3C0
    skein1024_776 = HASH_CODES["skein1024-776"]  # 0xB3C1
    skein1024_784 = HASH_CODES["skein1024-784"]  # 0xB3C2
    skein1024_792 = HASH_CODES["skein1024-792"]  # 0xB3C3
    skein1024_800 = HASH_CODES["skein1024-800"]  # 0xB3C4
    skein1024_808 = HASH_CODES["skein1024-808"]  # 0xB3C5
    skein1024_816 = HASH_CODES["skein1024-816"]  # 0xB3C6
    skein1024_824 = HASH_CODES["skein1024-824"]  # 0xB3C7
    skein1024_832 = HASH_CODES["skein1024-832"]  # 0xB3C8
    skein1024_840 = HASH_CODES["skein1024-840"]  # 0xB3C9
    skein1024_848 = HASH_CODES["skein1024-848"]  # 0xB3CA
    skein1024_856 = HASH_CODES["skein1024-856"]  # 0xB3CB
    skein1024_864 = HASH_CODES["skein1024-864"]  # 0xB3CC
    skein1024_872 = HASH_CODES["skein1024-872"]  # 0xB3CD
    skein1024_880 = HASH_CODES["skein1024-880"]  # 0xB3CE
    skein1024_888 = HASH_CODES["skein1024-888"]  # 0xB3CF
    skein1024_896 = HASH_CODES["skein1024-896"]  # 0xB3D0
    skein1024_904 = HASH_CODES["skein1024-904"]  # 0xB3D1
    skein1024_912 = HASH_CODES["skein1024-912"]  # 0xB3D2
    skein1024_920 = HASH_CODES["skein1024-920"]  # 0xB3D3
    skein1024_928 = HASH_CODES["skein1024-928"]  # 0xB3D4
    skein1024_936 = HASH_CODES["skein1024-936"]  # 0xB3D5
    skein1024_944 = HASH_CODES["skein1024-944"]  # 0xB3D6
    skein1024_952 = HASH_CODES["skein1024-952"]  # 0xB3D7
    skein1024_960 = HASH_CODES["skein1024-960"]  # 0xB3D8
    skein1024_968 = HASH_CODES["skein1024-968"]  # 0xB3D9
    skein1024_976 = HASH_CODES["skein1024-976"]  # 0xB3DA
    skein1024_984 = HASH_CODES["skein1024-984"]  # 0xB3DB
    skein1024_992 = HASH_CODES["skein1024-992"]  # 0xB3DC
    skein1024_1000 = HASH_CODES["skein1024-1000"]  # 0xB3DD
    skein1024_1008 = HASH_CODES["skein1024-1008"]  # 0xB3DE
    skein1024_1016 = HASH_CODES["skein1024-1016"]  # 0xB3DF
    skein1024_1024 = HASH_CODES["skein1024-1024"]  # 0xB3E0
    sm3_256 = HASH_CODES["sm3-256"]  # 0x534D
    ssz_sha2_256_bmt = HASH_CODES["ssz-sha2-256-bmt"]  # 0xB502
    x11 = HASH_CODES["x11"]  # 0x1100


class IdentityHash:
    """hashlib-compatible algorithm where the input is the digest."""

    name: str = "identity"

    def __init__(self) -> None:
        self._data = b""

    @property
    def digest_size(self) -> int:
        return len(self._data)

    @property
    def block_size(self) -> int:
        return 1

    def update(self, data: bytes) -> None:
        self._data += data

    def digest(self) -> bytes:
        return self._data

    def hexdigest(self) -> str:
        return self._data.hex()

    def copy(self) -> "IdentityHash":
        c = IdentityHash()
        c._data = self._data
        return c


class _FuncRegMeta(type):
    _func_hash: dict

    def __contains__(cls, func) -> bool:
        """Return whether `func` is a registered function."""
        return func in cls._func_hash

    def __iter__(cls):
        """Iterate over registered functions."""
        return iter(cls._func_hash)


class ShakeHash:
    """Wrapper for SHAKE variable-length hash functions."""

    def __init__(self, shake_func, length: int):
        """Initialize SHAKE hash with specified output length.

        Args:
            shake_func: hashlib.shake_128 or hashlib.shake_256
            length: Output digest length in bytes
        """
        self._shake_func = shake_func
        self._hasher = shake_func()
        self._length = length
        self.digest_size = length
        self.name = self._hasher.name

    def update(self, data: bytes) -> None:
        """Update the hash with data."""
        self._hasher.update(data)

    def digest(self) -> bytes:
        """Return digest of specified length."""
        return self._hasher.digest(self._length)

    def hexdigest(self) -> str:
        """Return hex digest."""
        return self.digest().hex()

    def copy(self) -> "ShakeHash":
        """Create a copy of the hash state."""
        c = ShakeHash(self._shake_func, self._length)
        c._hasher = self._hasher.copy()
        return c


def _create_keccak_hash(digest_bits: int):
    """Create a hashlib-compatible Keccak wrapper for the given digest bit length."""
    try:
        from Crypto.Hash import keccak as _keccak_mod
    except ImportError:
        return None

    class KeccakHash:
        name = f"keccak-{digest_bits}"
        digest_size = digest_bits // 8
        block_size = 200 - 2 * (digest_bits // 8)

        def __init__(self) -> None:
            self._digest_bits = digest_bits
            self._data = bytearray()
            self._hasher = _keccak_mod.new(digest_bits=digest_bits)

        def update(self, data: bytes) -> None:
            self._data.extend(data)
            self._hasher.update(data)

        def digest(self) -> bytes:
            return self._hasher.digest()

        def hexdigest(self) -> str:
            return self._hasher.hexdigest()

        def copy(self) -> "KeccakHash":
            c = KeccakHash()
            if self._data:
                c.update(bytes(self._data))
            return c

    return KeccakHash


class Blake3Hash:
    """hashlib-compatible wrapper for Blake3 using official blake3 library.

    BLAKE3 supports variable-length output up to 128 bytes (default 32).

    Example:
        >>> from multihash import digest
        >>> mh = digest(b"hello world", "blake3")
        >>> mh.digest.hex()  # doctest: +ELLIPSIS
        '...'
        >>> # Or use the hash class directly:
        >>> h = Blake3Hash()
        >>> h.update(b"hello ")
        >>> h.update(b"world")
        >>> h.hexdigest()  # doctest: +ELLIPSIS
        '...'
    """

    MAX_SIZE = 128
    name: str = "blake3"
    block_size: int = 64

    def __init__(self, length: int = 32) -> None:
        if length <= 0 or length > self.MAX_SIZE:
            raise ValueError(f"blake3 length must be 1..{self.MAX_SIZE}, got {length}")
        self._hasher = blake3.blake3()
        self._length = length
        self.digest_size = length

    def update(self, data: bytes) -> None:
        """Update the hash with data."""
        self._hasher.update(data)

    def digest(self) -> bytes:
        """Return digest of the configured length."""
        return self._hasher.digest(self._length)

    def hexdigest(self) -> str:
        """Return hex digest."""
        return self.digest().hex()

    def copy(self) -> "Blake3Hash":
        """Create a copy of the hash state."""
        c = Blake3Hash(self._length)
        c._hasher = self._hasher.copy()
        return c


class Murmur3_128Hash:
    """hashlib-compatible wrapper for MurmurHash3 128-bit using official mmh3 library.

    MurmurHash3 is a fast, non-cryptographic hash function suitable for hash-based lookups.
    Note: Not suitable for cryptographic purposes.

    Example:
        >>> from multihash import digest
        >>> mh = digest(b"hello world", "murmur3-128")
        >>> mh.digest.hex()  # doctest: +ELLIPSIS
        '...'
        >>> # Or use the hash class directly with a custom seed:
        >>> h = Murmur3_128Hash(seed=42)
        >>> h.update(b"data")
        >>> h.hexdigest()  # doctest: +ELLIPSIS
        '...'
    """

    name: str = "murmur3-128"
    digest_size: int = 16
    block_size: int = 1

    def __init__(self, seed: int = 0) -> None:
        self._data = b""
        self._seed = seed

    def update(self, data: bytes) -> None:
        """Update the hash with data."""
        self._data += data

    def digest(self) -> bytes:
        """Return 128-bit digest."""
        # mmh3.hash128 returns a 128-bit integer
        hash_value = mmh3.hash128(self._data, seed=self._seed, signed=False)
        return hash_value.to_bytes(16, byteorder="little")

    def hexdigest(self) -> str:
        """Return hex digest."""
        return self.digest().hex()

    def copy(self) -> "Murmur3_128Hash":
        """Create a copy of the hash state."""
        c = Murmur3_128Hash(seed=self._seed)
        c._data = self._data
        return c


class Murmur3_32Hash:
    """hashlib-compatible wrapper for MurmurHash3 32-bit using official mmh3 library.

    MurmurHash3 32-bit variant is a fast, non-cryptographic hash function.
    Note: Not suitable for cryptographic purposes.

    Example:
        >>> from multihash import digest
        >>> mh = digest(b"hello world", "murmur3-32")
        >>> mh.digest.hex()  # doctest: +ELLIPSIS
        '...'
        >>> # Or use the hash class directly with a custom seed:
        >>> h = Murmur3_32Hash(seed=0)
        >>> h.update(b"data")
        >>> h.hexdigest()  # doctest: +ELLIPSIS
        '...'
    """

    name: str = "murmur3-32"
    digest_size: int = 4
    block_size: int = 1

    def __init__(self, seed: int = 0) -> None:
        self._data = b""
        self._seed = seed

    def update(self, data: bytes) -> None:
        """Update the hash with data."""
        self._data += data

    def digest(self) -> bytes:
        """Return 32-bit digest."""
        # mmh3.hash returns a 32-bit integer
        hash_value = mmh3.hash(self._data, seed=self._seed, signed=False)
        return hash_value.to_bytes(4, byteorder="little")

    def hexdigest(self) -> str:
        """Return hex digest."""
        return self.digest().hex()

    def copy(self) -> "Murmur3_32Hash":
        """Create a copy of the hash state."""
        c = Murmur3_32Hash(seed=self._seed)
        c._data = self._data
        return c


class DoubleSHA256Hash:
    """hashlib-compatible wrapper for double SHA2-256 (used in Bitcoin).

    Applies SHA-256 twice: SHA-256(SHA-256(data)). This is commonly used in Bitcoin
    and other cryptocurrencies for additional security.

    Example:
        >>> from multihash import digest
        >>> mh = digest(b"hello world", "dbl-sha2-256")
        >>> mh.digest.hex()  # doctest: +ELLIPSIS
        '...'
        >>> # Or use the hash class directly:
        >>> h = DoubleSHA256Hash()
        >>> h.update(b"data")
        >>> h.hexdigest()  # doctest: +ELLIPSIS
        '...'
    """

    name: str = "dbl-sha2-256"
    digest_size: int = 32
    block_size: int = 64

    def __init__(self) -> None:
        self._hasher = hashlib.sha256()

    def update(self, data: bytes) -> None:
        """Update the hash with data."""
        self._hasher.update(data)

    def digest(self) -> bytes:
        """Return digest (double SHA-256)."""
        first_hash = self._hasher.digest()
        return hashlib.sha256(first_hash).digest()

    def hexdigest(self) -> str:
        """Return hex digest."""
        return self.digest().hex()

    def copy(self) -> "DoubleSHA256Hash":
        """Create a copy of the hash state."""
        c = DoubleSHA256Hash()
        c._hasher = self._hasher.copy()
        return c


class SHA2_256_Trunc254_Padded_Hash:
    """hashlib-compatible wrapper for SHA2-256 truncated to 254 bits and padded."""

    name: str = "sha2-256-trunc254-padded"
    digest_size: int = 31  # 254 bits = 31.75 bytes, but we use 31 bytes
    block_size: int = 64

    def __init__(self) -> None:
        self._hasher = hashlib.sha256()

    def update(self, data: bytes) -> None:
        """Update the hash with data."""
        self._hasher.update(data)

    def digest(self) -> bytes:
        """Return digest (SHA-256 truncated to 254 bits = 31 bytes)."""
        full_hash = self._hasher.digest()
        # Truncate to 254 bits (31 bytes) by taking first 31 bytes
        return full_hash[:31]

    def hexdigest(self) -> str:
        """Return hex digest."""
        return self.digest().hex()

    def copy(self) -> "SHA2_256_Trunc254_Padded_Hash":
        """Create a copy of the hash state."""
        c = SHA2_256_Trunc254_Padded_Hash()
        c._hasher = self._hasher.copy()
        return c


def _create_blake2_variant(variant: str, digest_bytes: int):
    """Factory function to create Blake2 variant classes.

    Args:
        variant: Either 'blake2b' or 'blake2s'
        digest_bytes: Number of bytes in the digest (1-64 for blake2b, 1-32 for blake2s)

    Returns:
        A hashlib-compatible hash class for the specified Blake2 variant

    Example:
        >>> from multihash import digest
        >>> # Use BLAKE2b with 256-bit output
        >>> mh = digest(b"hello", "blake2b-256")
        >>>
        >>> # Use BLAKE2s with 128-bit output
        >>> mh = digest(b"hello", "blake2s-128")
        >>>
        >>> # All variants from 8 to 512 bits (blake2b) or 8 to 256 bits (blake2s) are supported
        >>> mh = digest(b"data", "blake2b-384")
    """

    class Blake2Variant:
        name: str = f"{variant}-{digest_bytes * 8}"
        digest_size: int = digest_bytes
        block_size: int = 128 if variant == "blake2b" else 64

        def __init__(self) -> None:
            hash_func = getattr(hashlib, variant)
            self._hasher = hash_func(digest_size=digest_bytes)

        def update(self, data: bytes) -> None:
            """Update the hash with data."""
            self._hasher.update(data)

        def digest(self) -> bytes:
            """Return digest."""
            return self._hasher.digest()

        def hexdigest(self) -> str:
            """Return hex digest."""
            return self._hasher.hexdigest()

        def copy(self) -> "Blake2Variant":
            """Create a copy of the hash state."""
            c = Blake2Variant()
            c._hasher = self._hasher.copy()
            return c

    return Blake2Variant


class FuncReg(metaclass=_FuncRegMeta):
    """Registry of supported hash functions.

    The FuncReg class maintains a registry of hash functions that can be:
    - Retrieved by code, name, or hashlib object
    - Extended with custom app-specific functions (codes 0x01-0x0F)
    - Used to create hashlib-compatible hash objects

    Standard functions are pre-registered. App-specific functions can be
    registered/unregistered at runtime.

    Example:
        Register an app-specific hash function:
        >>> FuncReg.register(0x05, "my-custom-hash", "myhash", lambda: MyHash())
        >>> func = FuncReg.get("my-custom-hash")
        >>> hash_obj = FuncReg.hash_from_func(func)

        Unregister an app-specific function:
        >>> FuncReg.unregister(0x05)
    """

    _hash = namedtuple("_hash", "name new")

    # Class-level registry attributes
    _func_from_name: ClassVar[dict] = {}
    _func_from_hash: ClassVar[dict] = {}
    _func_hash: ClassVar[dict] = {}
    default_lengths: ClassVar[dict[int, int]] = {}
    _variable_factories: ClassVar[dict[int, Callable]] = {}

    # Standard hash function data: (func, hashlib_name, constructor)
    _std_func_data: ClassVar[list] = [
        (Func.identity, "identity", IdentityHash),
        (Func.sha1, "sha1", hashlib.sha1),
        (Func.sha2_256, "sha256", hashlib.sha256),
        (Func.sha2_512, "sha512", hashlib.sha512),
        (Func.sha3_512, "sha3_512", hashlib.sha3_512),
        (Func.sha3_384, "sha3_384", hashlib.sha3_384),
        (Func.sha3_256, "sha3_256", hashlib.sha3_256),
        (Func.sha3_224, "sha3_224", hashlib.sha3_224),
        # SHAKE registered via register_variable_size in reset()
        (Func.blake2b_256, "blake2b", lambda: hashlib.blake2b(digest_size=32)),
        (Func.blake2b_512, "blake2b", lambda: hashlib.blake2b(digest_size=64)),
        (Func.blake2s_256, "blake2s", lambda: hashlib.blake2s(digest_size=32)),
        (Func.md5, "md5", hashlib.md5),
    ]

    # Additional hash functions (conditionally added if available)
    _optional_func_data: ClassVar[list] = [
        # SHA2 variants (if available in hashlib)
        (Func.sha2_224, "sha224", hashlib.sha224 if hasattr(hashlib, "sha224") else None),
        (Func.sha2_384, "sha384", hashlib.sha384 if hasattr(hashlib, "sha384") else None),
        # SHA2-512 truncated variants (Python 3.6+)
        (Func.sha2_512_224, "sha512_224", getattr(hashlib, "sha512_224", None)),
        (Func.sha2_512_256, "sha512_256", getattr(hashlib, "sha512_256", None)),
        # Blake3 registered via register_variable_size in reset()
        # Legacy Keccak (distinct from NIST SHA3) — requires pycryptodome
        (Func.keccak_224, "keccak-224", _create_keccak_hash(224)),
        (Func.keccak_256, "keccak-256", _create_keccak_hash(256)),
        (Func.keccak_384, "keccak-384", _create_keccak_hash(384)),
        (Func.keccak_512, "keccak-512", _create_keccak_hash(512)),
        # Murmur3 variants (using official mmh3 library)
        (Func.murmur3_128, "murmur3-128", Murmur3_128Hash),
        (Func.murmur3_32, "murmur3-32", Murmur3_32Hash),
        # Double SHA2-256 (always available, uses hashlib)
        (Func.dbl_sha2_256, "dbl-sha2-256", DoubleSHA256Hash),
        # SHA2-256 truncated and padded
        (Func.sha2_256_trunc254_padded, "sha2-256-trunc254-padded", SHA2_256_Trunc254_Padded_Hash),
        # Legacy hash functions - RIPEMD variants
        (Func.ripemd_128, "ripemd128", getattr(hashlib, "ripemd128", None)),
        (Func.ripemd_160, "ripemd160", getattr(hashlib, "ripemd160", None)),
        (Func.ripemd_256, "ripemd256", getattr(hashlib, "ripemd256", None)),
        (Func.ripemd_320, "ripemd320", getattr(hashlib, "ripemd320", None)),
        # MD4 (legacy, weak)
        (Func.md4, "md4", getattr(hashlib, "md4", None)),
    ]

    # Blake2 variants - generated programmatically
    @classmethod
    def _generate_blake2_variants(cls):
        """Generate all Blake2b and Blake2s variant registrations."""
        blake2_variants = []

        # Blake2b variants (8 to 512 bits, in 8-bit increments)
        # Skip 256 and 512 as they're already in std_func_data
        for bits in range(8, 520, 8):
            if bits in (256, 512):  # Skip already defined variants
                continue
            digest_bytes = bits // 8
            func_name = f"blake2b_{bits}"
            if hasattr(Func, func_name):
                func = getattr(Func, func_name)
                hash_name = f"blake2b-{bits}"
                hash_class = _create_blake2_variant("blake2b", digest_bytes)
                blake2_variants.append((func, hash_name, hash_class))

        # Blake2s variants (8 to 256 bits, in 8-bit increments)
        # Skip 256 as it's already in std_func_data
        for bits in range(8, 264, 8):
            if bits == 256:  # Skip already defined variant
                continue
            digest_bytes = bits // 8
            func_name = f"blake2s_{bits}"
            if hasattr(Func, func_name):
                func = getattr(Func, func_name)
                hash_name = f"blake2s-{bits}"
                hash_class = _create_blake2_variant("blake2s", digest_bytes)
                blake2_variants.append((func, hash_name, hash_class))

        return blake2_variants

    @classmethod
    def reset(cls) -> None:
        """Reset the registry to the standard multihash functions."""
        cls._func_from_name = {}
        cls._func_from_hash = {}
        cls._func_hash = {}
        cls.default_lengths = {}
        cls._variable_factories = {}

        for func, hash_name, hash_new in cls._std_func_data:
            cls._do_register(func, func.name, hash_name, hash_new)

        # Register optional functions if available
        for func, hash_name, hash_new in cls._optional_func_data:
            if hash_new is not None:
                try:
                    # Test that the function is actually available by creating an instance.
                    # We don't use the result, just verify it can be instantiated.
                    # The unused variable is intentional - we only care about the side effect
                    # of successful instantiation, not the hash object itself.
                    _ = hash_new()
                    cls._do_register(func, func.name, hash_name, hash_new)
                except (AttributeError, ValueError, TypeError):
                    # Function not available, skip
                    pass

        # Register Blake2 variants
        for func, hash_name, hash_class in cls._generate_blake2_variants():
            try:
                # Test instantiation
                _ = hash_class()
                cls._do_register(func, func.name, hash_name, hash_class)
            except (AttributeError, ValueError, TypeError):
                # Variant not available, skip
                pass

        # Variable-size SHAKE functions
        def shake_128_factory(size_hint: int):
            length = 32 if size_hint < 0 else size_hint
            if length <= 0:
                return None
            return ShakeHash(hashlib.shake_128, length)

        def shake_256_factory(size_hint: int):
            length = 64 if size_hint < 0 else size_hint
            if length <= 0:
                return None
            return ShakeHash(hashlib.shake_256, length)

        cls.register_variable_size(Func.shake_128, "shake_128", shake_128_factory, "shake_128")
        cls.register_variable_size(Func.shake_256, "shake_256", shake_256_factory, "shake_256")

        def blake3_factory(size_hint: int):
            length = 32 if size_hint < 0 else size_hint
            if length <= 0 or length > Blake3Hash.MAX_SIZE:
                return None
            return Blake3Hash(length)

        cls.register_variable_size(Func.blake3, "blake3", blake3_factory, "blake3")

    @classmethod
    def get(cls, func_hint: Func | str | int) -> Func | int:
        """Return a registered hash function matching the given hint."""
        if isinstance(func_hint, int):
            try:
                return Func(func_hint)
            except ValueError:
                pass
        if isinstance(func_hint, str) and func_hint in cls._func_from_name:
            return cls._func_from_name[func_hint]
        if isinstance(func_hint, int) and func_hint in cls._func_hash:
            return func_hint
        raise KeyError("unknown hash function", func_hint)

    @classmethod
    def _do_register(cls, code: int, name: str, hash_name: str | None = None, hash_new=None) -> None:
        """Add hash function data to the registry without checks.

        This method registers the function name in both hyphen and underscore
        variants (e.g., "sha2-256" and "sha2_256") to provide flexibility
        for users who may use either naming convention.
        """
        cls._func_from_name[name.replace("-", "_")] = code
        cls._func_from_name[name.replace("_", "-")] = code
        if hash_name:
            cls._func_from_hash[hash_name] = code
        cls._func_hash[code] = cls._hash(hash_name, hash_new)
        if hash_new is not None and int(code) not in cls._variable_factories:
            try:
                cls.default_lengths[int(code)] = hash_new().digest_size
            except (AttributeError, TypeError, ValueError):
                pass

    @classmethod
    def register_variable_size(
        cls,
        code: int,
        name: str,
        factory: Callable[[int], Any],
        hash_name: str | None = None,
    ) -> None:
        """Register a variable-size hash function factory.

        The factory receives a size hint in bytes. Pass ``-1`` to request the
        default output length. The factory should return a hashlib-compatible
        object, or ``None`` if the requested size is invalid.

        Args:
            code: Multihash function code
            name: Function name (hyphen or underscore form)
            factory: Callable ``(size_hint: int) -> hash_obj | None``
            hash_name: Optional hashlib-style name for reverse lookup
        """
        code = int(code)
        default_hasher = factory(-1)
        if default_hasher is None:
            raise ValueError(f"variable-size factory for {name} rejected default size hint -1")
        cls._variable_factories[code] = factory
        cls.default_lengths[code] = default_hasher.digest_size
        cls._do_register(code, name, hash_name or name, None)

    @classmethod
    def is_variable_size(cls, func: Func | int) -> bool:
        """Return True if ``func`` was registered via :meth:`register_variable_size`."""
        return int(func) in cls._variable_factories

    @classmethod
    def register(cls, code: int, name: str, hash_name: str | None = None, hash_new=None) -> None:
        """Add a function to the registry.

        For standard functions already registered, this updates the hash_new
        if provided. For app-specific functions (0x01-0x0f), replaces existing.
        """
        # Check if this is a standard function
        try:
            Func(code)
            is_std_func = True
        except ValueError:
            is_std_func = False

        # For standard functions, just update hash_new if provided
        if is_std_func and code in cls._func_hash:
            if hash_new is not None:
                old_hash = cls._func_hash[code]
                cls._func_hash[code] = cls._hash(old_hash.name or hash_name, hash_new)
            return

        # Check for name conflicts
        for mapping, nameinmap, errmsg in [
            (cls._func_from_name, name, "function name already registered"),
            (cls._func_from_hash, hash_name, "hashlib name already registered"),
        ]:
            if nameinmap is None:
                continue
            existing = mapping.get(nameinmap, code)
            if existing != code:
                raise ValueError(errmsg, existing)

        # Unregister app-specific if existing
        if code in cls._func_hash and _is_app_specific_func(code):
            cls.unregister(code)

        cls._do_register(code, name, hash_name, hash_new)

    @classmethod
    def unregister(cls, code: int) -> None:
        """Remove an application-specific function from the registry."""
        if not _is_app_specific_func(code):
            raise ValueError("only application-specific functions can be unregistered")

        func_names = {n for n, f in cls._func_from_name.items() if f == code}
        for func_name in func_names:
            del cls._func_from_name[func_name]

        hash_data = cls._func_hash.pop(code)
        if hash_data.name:
            del cls._func_from_hash[hash_data.name]
        cls.default_lengths.pop(code, None)
        cls._variable_factories.pop(code, None)

    @classmethod
    def func_from_hash(cls, hash_obj) -> Func | int:
        """Return the multihash Func for a hashlib-compatible hash object.

        Args:
            hash_obj: Hashlib-compatible hash object

        Returns:
            Func enum or int code

        Raises:
            KeyError: If hash object name is not registered
        """
        try:
            return cls._func_from_hash[hash_obj.name]
        except KeyError:
            raise KeyError(f"unknown hash object name: {hash_obj.name}")

    @classmethod
    def hash_from_func(cls, func: Func | int, length: int | None = None):
        """Return a hashlib-compatible object for the multihash func.

        Args:
            func: Hash function code or Func enum
            length: Optional output length for variable-size hashes

        Returns:
            Hash object or None if not available

        Note:
            For variable-size functions, ``None`` returns ``None`` (caller must
            supply a length or use ``-1`` for the default). ``-1`` requests the
            default length from :attr:`default_lengths`.
        """
        code = int(func)
        if code in cls._variable_factories:
            if length is None:
                return None
            size_hint = -1 if length == -1 else length
            return cls._variable_factories[code](size_hint)

        new = cls._func_hash[func].new
        if new is None:
            return None
        return new()


# Initialize the function hash registry.
FuncReg.reset()
