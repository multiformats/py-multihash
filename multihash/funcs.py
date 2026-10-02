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
from enum import IntEnum
from numbers import Integral
from typing import ClassVar

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

    identity = HASH_CODES["identity"]  # 0X0
    sha1 = HASH_CODES["sha1"]  # 0X11
    sha2_256 = HASH_CODES["sha2-256"]  # 0X12
    sha2_512 = HASH_CODES["sha2-512"]  # 0X13
    sha3_512 = HASH_CODES["sha3-512"]  # 0X14
    sha3_384 = HASH_CODES["sha3-384"]  # 0X15
    sha3_256 = HASH_CODES["sha3-256"]  # 0X16
    sha3_224 = HASH_CODES["sha3-224"]  # 0X17
    shake_128 = HASH_CODES["shake-128"]  # 0X18
    shake_256 = HASH_CODES["shake-256"]  # 0X19
    keccak_224 = HASH_CODES["keccak-224"]  # 0X1A
    keccak_256 = HASH_CODES["keccak-256"]  # 0X1B
    keccak_384 = HASH_CODES["keccak-384"]  # 0X1C
    keccak_512 = HASH_CODES["keccak-512"]  # 0X1D
    blake3 = HASH_CODES["blake3"]  # 0X1E
    sha2_384 = HASH_CODES["sha2-384"]  # 0X20
    murmur3_128 = HASH_CODES["murmur3-128"]  # 0X22
    murmur3_32 = HASH_CODES["murmur3-32"]  # 0X23
    dbl_sha2_256 = HASH_CODES["dbl-sha2-256"]  # 0X56
    md4 = HASH_CODES["md4"]  # 0XD4
    md5 = HASH_CODES["md5"]  # 0XD5
    fr32_sha256_trunc254_padbintree = HASH_CODES["fr32-sha256-trunc254-padbintree"]  # 0X1011
    sha2_256_trunc254_padded = HASH_CODES["sha2-256-trunc254-padded"]  # 0X1012
    sha2_224 = HASH_CODES["sha2-224"]  # 0X1013
    sha2_512_224 = HASH_CODES["sha2-512-224"]  # 0X1014
    sha2_512_256 = HASH_CODES["sha2-512-256"]  # 0X1015
    ripemd_128 = HASH_CODES["ripemd-128"]  # 0X1052
    ripemd_160 = HASH_CODES["ripemd-160"]  # 0X1053
    ripemd_256 = HASH_CODES["ripemd-256"]  # 0X1054
    ripemd_320 = HASH_CODES["ripemd-320"]  # 0X1055
    x11 = HASH_CODES["x11"]  # 0X1100
    kt_128 = HASH_CODES["kt-128"]  # 0X1D01
    kt_256 = HASH_CODES["kt-256"]  # 0X1D02
    sm3_256 = HASH_CODES["sm3-256"]  # 0X534D
    blake2b_8 = HASH_CODES["blake2b-8"]  # 0XB201
    blake2b_16 = HASH_CODES["blake2b-16"]  # 0XB202
    blake2b_24 = HASH_CODES["blake2b-24"]  # 0XB203
    blake2b_32 = HASH_CODES["blake2b-32"]  # 0XB204
    blake2b_40 = HASH_CODES["blake2b-40"]  # 0XB205
    blake2b_48 = HASH_CODES["blake2b-48"]  # 0XB206
    blake2b_56 = HASH_CODES["blake2b-56"]  # 0XB207
    blake2b_64 = HASH_CODES["blake2b-64"]  # 0XB208
    blake2b_72 = HASH_CODES["blake2b-72"]  # 0XB209
    blake2b_80 = HASH_CODES["blake2b-80"]  # 0XB20A
    blake2b_88 = HASH_CODES["blake2b-88"]  # 0XB20B
    blake2b_96 = HASH_CODES["blake2b-96"]  # 0XB20C
    blake2b_104 = HASH_CODES["blake2b-104"]  # 0XB20D
    blake2b_112 = HASH_CODES["blake2b-112"]  # 0XB20E
    blake2b_120 = HASH_CODES["blake2b-120"]  # 0XB20F
    blake2b_128 = HASH_CODES["blake2b-128"]  # 0XB210
    blake2b_136 = HASH_CODES["blake2b-136"]  # 0XB211
    blake2b_144 = HASH_CODES["blake2b-144"]  # 0XB212
    blake2b_152 = HASH_CODES["blake2b-152"]  # 0XB213
    blake2b_160 = HASH_CODES["blake2b-160"]  # 0XB214
    blake2b_168 = HASH_CODES["blake2b-168"]  # 0XB215
    blake2b_176 = HASH_CODES["blake2b-176"]  # 0XB216
    blake2b_184 = HASH_CODES["blake2b-184"]  # 0XB217
    blake2b_192 = HASH_CODES["blake2b-192"]  # 0XB218
    blake2b_200 = HASH_CODES["blake2b-200"]  # 0XB219
    blake2b_208 = HASH_CODES["blake2b-208"]  # 0XB21A
    blake2b_216 = HASH_CODES["blake2b-216"]  # 0XB21B
    blake2b_224 = HASH_CODES["blake2b-224"]  # 0XB21C
    blake2b_232 = HASH_CODES["blake2b-232"]  # 0XB21D
    blake2b_240 = HASH_CODES["blake2b-240"]  # 0XB21E
    blake2b_248 = HASH_CODES["blake2b-248"]  # 0XB21F
    blake2b_256 = HASH_CODES["blake2b-256"]  # 0XB220
    blake2b_264 = HASH_CODES["blake2b-264"]  # 0XB221
    blake2b_272 = HASH_CODES["blake2b-272"]  # 0XB222
    blake2b_280 = HASH_CODES["blake2b-280"]  # 0XB223
    blake2b_288 = HASH_CODES["blake2b-288"]  # 0XB224
    blake2b_296 = HASH_CODES["blake2b-296"]  # 0XB225
    blake2b_304 = HASH_CODES["blake2b-304"]  # 0XB226
    blake2b_312 = HASH_CODES["blake2b-312"]  # 0XB227
    blake2b_320 = HASH_CODES["blake2b-320"]  # 0XB228
    blake2b_328 = HASH_CODES["blake2b-328"]  # 0XB229
    blake2b_336 = HASH_CODES["blake2b-336"]  # 0XB22A
    blake2b_344 = HASH_CODES["blake2b-344"]  # 0XB22B
    blake2b_352 = HASH_CODES["blake2b-352"]  # 0XB22C
    blake2b_360 = HASH_CODES["blake2b-360"]  # 0XB22D
    blake2b_368 = HASH_CODES["blake2b-368"]  # 0XB22E
    blake2b_376 = HASH_CODES["blake2b-376"]  # 0XB22F
    blake2b_384 = HASH_CODES["blake2b-384"]  # 0XB230
    blake2b_392 = HASH_CODES["blake2b-392"]  # 0XB231
    blake2b_400 = HASH_CODES["blake2b-400"]  # 0XB232
    blake2b_408 = HASH_CODES["blake2b-408"]  # 0XB233
    blake2b_416 = HASH_CODES["blake2b-416"]  # 0XB234
    blake2b_424 = HASH_CODES["blake2b-424"]  # 0XB235
    blake2b_432 = HASH_CODES["blake2b-432"]  # 0XB236
    blake2b_440 = HASH_CODES["blake2b-440"]  # 0XB237
    blake2b_448 = HASH_CODES["blake2b-448"]  # 0XB238
    blake2b_456 = HASH_CODES["blake2b-456"]  # 0XB239
    blake2b_464 = HASH_CODES["blake2b-464"]  # 0XB23A
    blake2b_472 = HASH_CODES["blake2b-472"]  # 0XB23B
    blake2b_480 = HASH_CODES["blake2b-480"]  # 0XB23C
    blake2b_488 = HASH_CODES["blake2b-488"]  # 0XB23D
    blake2b_496 = HASH_CODES["blake2b-496"]  # 0XB23E
    blake2b_504 = HASH_CODES["blake2b-504"]  # 0XB23F
    blake2b_512 = HASH_CODES["blake2b-512"]  # 0XB240
    blake2s_8 = HASH_CODES["blake2s-8"]  # 0XB241
    blake2s_16 = HASH_CODES["blake2s-16"]  # 0XB242
    blake2s_24 = HASH_CODES["blake2s-24"]  # 0XB243
    blake2s_32 = HASH_CODES["blake2s-32"]  # 0XB244
    blake2s_40 = HASH_CODES["blake2s-40"]  # 0XB245
    blake2s_48 = HASH_CODES["blake2s-48"]  # 0XB246
    blake2s_56 = HASH_CODES["blake2s-56"]  # 0XB247
    blake2s_64 = HASH_CODES["blake2s-64"]  # 0XB248
    blake2s_72 = HASH_CODES["blake2s-72"]  # 0XB249
    blake2s_80 = HASH_CODES["blake2s-80"]  # 0XB24A
    blake2s_88 = HASH_CODES["blake2s-88"]  # 0XB24B
    blake2s_96 = HASH_CODES["blake2s-96"]  # 0XB24C
    blake2s_104 = HASH_CODES["blake2s-104"]  # 0XB24D
    blake2s_112 = HASH_CODES["blake2s-112"]  # 0XB24E
    blake2s_120 = HASH_CODES["blake2s-120"]  # 0XB24F
    blake2s_128 = HASH_CODES["blake2s-128"]  # 0XB250
    blake2s_136 = HASH_CODES["blake2s-136"]  # 0XB251
    blake2s_144 = HASH_CODES["blake2s-144"]  # 0XB252
    blake2s_152 = HASH_CODES["blake2s-152"]  # 0XB253
    blake2s_160 = HASH_CODES["blake2s-160"]  # 0XB254
    blake2s_168 = HASH_CODES["blake2s-168"]  # 0XB255
    blake2s_176 = HASH_CODES["blake2s-176"]  # 0XB256
    blake2s_184 = HASH_CODES["blake2s-184"]  # 0XB257
    blake2s_192 = HASH_CODES["blake2s-192"]  # 0XB258
    blake2s_200 = HASH_CODES["blake2s-200"]  # 0XB259
    blake2s_208 = HASH_CODES["blake2s-208"]  # 0XB25A
    blake2s_216 = HASH_CODES["blake2s-216"]  # 0XB25B
    blake2s_224 = HASH_CODES["blake2s-224"]  # 0XB25C
    blake2s_232 = HASH_CODES["blake2s-232"]  # 0XB25D
    blake2s_240 = HASH_CODES["blake2s-240"]  # 0XB25E
    blake2s_248 = HASH_CODES["blake2s-248"]  # 0XB25F
    blake2s_256 = HASH_CODES["blake2s-256"]  # 0XB260
    skein256_8 = HASH_CODES["skein256-8"]  # 0XB301
    skein256_16 = HASH_CODES["skein256-16"]  # 0XB302
    skein256_24 = HASH_CODES["skein256-24"]  # 0XB303
    skein256_32 = HASH_CODES["skein256-32"]  # 0XB304
    skein256_40 = HASH_CODES["skein256-40"]  # 0XB305
    skein256_48 = HASH_CODES["skein256-48"]  # 0XB306
    skein256_56 = HASH_CODES["skein256-56"]  # 0XB307
    skein256_64 = HASH_CODES["skein256-64"]  # 0XB308
    skein256_72 = HASH_CODES["skein256-72"]  # 0XB309
    skein256_80 = HASH_CODES["skein256-80"]  # 0XB30A
    skein256_88 = HASH_CODES["skein256-88"]  # 0XB30B
    skein256_96 = HASH_CODES["skein256-96"]  # 0XB30C
    skein256_104 = HASH_CODES["skein256-104"]  # 0XB30D
    skein256_112 = HASH_CODES["skein256-112"]  # 0XB30E
    skein256_120 = HASH_CODES["skein256-120"]  # 0XB30F
    skein256_128 = HASH_CODES["skein256-128"]  # 0XB310
    skein256_136 = HASH_CODES["skein256-136"]  # 0XB311
    skein256_144 = HASH_CODES["skein256-144"]  # 0XB312
    skein256_152 = HASH_CODES["skein256-152"]  # 0XB313
    skein256_160 = HASH_CODES["skein256-160"]  # 0XB314
    skein256_168 = HASH_CODES["skein256-168"]  # 0XB315
    skein256_176 = HASH_CODES["skein256-176"]  # 0XB316
    skein256_184 = HASH_CODES["skein256-184"]  # 0XB317
    skein256_192 = HASH_CODES["skein256-192"]  # 0XB318
    skein256_200 = HASH_CODES["skein256-200"]  # 0XB319
    skein256_208 = HASH_CODES["skein256-208"]  # 0XB31A
    skein256_216 = HASH_CODES["skein256-216"]  # 0XB31B
    skein256_224 = HASH_CODES["skein256-224"]  # 0XB31C
    skein256_232 = HASH_CODES["skein256-232"]  # 0XB31D
    skein256_240 = HASH_CODES["skein256-240"]  # 0XB31E
    skein256_248 = HASH_CODES["skein256-248"]  # 0XB31F
    skein256_256 = HASH_CODES["skein256-256"]  # 0XB320
    skein512_8 = HASH_CODES["skein512-8"]  # 0XB321
    skein512_16 = HASH_CODES["skein512-16"]  # 0XB322
    skein512_24 = HASH_CODES["skein512-24"]  # 0XB323
    skein512_32 = HASH_CODES["skein512-32"]  # 0XB324
    skein512_40 = HASH_CODES["skein512-40"]  # 0XB325
    skein512_48 = HASH_CODES["skein512-48"]  # 0XB326
    skein512_56 = HASH_CODES["skein512-56"]  # 0XB327
    skein512_64 = HASH_CODES["skein512-64"]  # 0XB328
    skein512_72 = HASH_CODES["skein512-72"]  # 0XB329
    skein512_80 = HASH_CODES["skein512-80"]  # 0XB32A
    skein512_88 = HASH_CODES["skein512-88"]  # 0XB32B
    skein512_96 = HASH_CODES["skein512-96"]  # 0XB32C
    skein512_104 = HASH_CODES["skein512-104"]  # 0XB32D
    skein512_112 = HASH_CODES["skein512-112"]  # 0XB32E
    skein512_120 = HASH_CODES["skein512-120"]  # 0XB32F
    skein512_128 = HASH_CODES["skein512-128"]  # 0XB330
    skein512_136 = HASH_CODES["skein512-136"]  # 0XB331
    skein512_144 = HASH_CODES["skein512-144"]  # 0XB332
    skein512_152 = HASH_CODES["skein512-152"]  # 0XB333
    skein512_160 = HASH_CODES["skein512-160"]  # 0XB334
    skein512_168 = HASH_CODES["skein512-168"]  # 0XB335
    skein512_176 = HASH_CODES["skein512-176"]  # 0XB336
    skein512_184 = HASH_CODES["skein512-184"]  # 0XB337
    skein512_192 = HASH_CODES["skein512-192"]  # 0XB338
    skein512_200 = HASH_CODES["skein512-200"]  # 0XB339
    skein512_208 = HASH_CODES["skein512-208"]  # 0XB33A
    skein512_216 = HASH_CODES["skein512-216"]  # 0XB33B
    skein512_224 = HASH_CODES["skein512-224"]  # 0XB33C
    skein512_232 = HASH_CODES["skein512-232"]  # 0XB33D
    skein512_240 = HASH_CODES["skein512-240"]  # 0XB33E
    skein512_248 = HASH_CODES["skein512-248"]  # 0XB33F
    skein512_256 = HASH_CODES["skein512-256"]  # 0XB340
    skein512_264 = HASH_CODES["skein512-264"]  # 0XB341
    skein512_272 = HASH_CODES["skein512-272"]  # 0XB342
    skein512_280 = HASH_CODES["skein512-280"]  # 0XB343
    skein512_288 = HASH_CODES["skein512-288"]  # 0XB344
    skein512_296 = HASH_CODES["skein512-296"]  # 0XB345
    skein512_304 = HASH_CODES["skein512-304"]  # 0XB346
    skein512_312 = HASH_CODES["skein512-312"]  # 0XB347
    skein512_320 = HASH_CODES["skein512-320"]  # 0XB348
    skein512_328 = HASH_CODES["skein512-328"]  # 0XB349
    skein512_336 = HASH_CODES["skein512-336"]  # 0XB34A
    skein512_344 = HASH_CODES["skein512-344"]  # 0XB34B
    skein512_352 = HASH_CODES["skein512-352"]  # 0XB34C
    skein512_360 = HASH_CODES["skein512-360"]  # 0XB34D
    skein512_368 = HASH_CODES["skein512-368"]  # 0XB34E
    skein512_376 = HASH_CODES["skein512-376"]  # 0XB34F
    skein512_384 = HASH_CODES["skein512-384"]  # 0XB350
    skein512_392 = HASH_CODES["skein512-392"]  # 0XB351
    skein512_400 = HASH_CODES["skein512-400"]  # 0XB352
    skein512_408 = HASH_CODES["skein512-408"]  # 0XB353
    skein512_416 = HASH_CODES["skein512-416"]  # 0XB354
    skein512_424 = HASH_CODES["skein512-424"]  # 0XB355
    skein512_432 = HASH_CODES["skein512-432"]  # 0XB356
    skein512_440 = HASH_CODES["skein512-440"]  # 0XB357
    skein512_448 = HASH_CODES["skein512-448"]  # 0XB358
    skein512_456 = HASH_CODES["skein512-456"]  # 0XB359
    skein512_464 = HASH_CODES["skein512-464"]  # 0XB35A
    skein512_472 = HASH_CODES["skein512-472"]  # 0XB35B
    skein512_480 = HASH_CODES["skein512-480"]  # 0XB35C
    skein512_488 = HASH_CODES["skein512-488"]  # 0XB35D
    skein512_496 = HASH_CODES["skein512-496"]  # 0XB35E
    skein512_504 = HASH_CODES["skein512-504"]  # 0XB35F
    skein512_512 = HASH_CODES["skein512-512"]  # 0XB360
    skein1024_8 = HASH_CODES["skein1024-8"]  # 0XB361
    skein1024_16 = HASH_CODES["skein1024-16"]  # 0XB362
    skein1024_24 = HASH_CODES["skein1024-24"]  # 0XB363
    skein1024_32 = HASH_CODES["skein1024-32"]  # 0XB364
    skein1024_40 = HASH_CODES["skein1024-40"]  # 0XB365
    skein1024_48 = HASH_CODES["skein1024-48"]  # 0XB366
    skein1024_56 = HASH_CODES["skein1024-56"]  # 0XB367
    skein1024_64 = HASH_CODES["skein1024-64"]  # 0XB368
    skein1024_72 = HASH_CODES["skein1024-72"]  # 0XB369
    skein1024_80 = HASH_CODES["skein1024-80"]  # 0XB36A
    skein1024_88 = HASH_CODES["skein1024-88"]  # 0XB36B
    skein1024_96 = HASH_CODES["skein1024-96"]  # 0XB36C
    skein1024_104 = HASH_CODES["skein1024-104"]  # 0XB36D
    skein1024_112 = HASH_CODES["skein1024-112"]  # 0XB36E
    skein1024_120 = HASH_CODES["skein1024-120"]  # 0XB36F
    skein1024_128 = HASH_CODES["skein1024-128"]  # 0XB370
    skein1024_136 = HASH_CODES["skein1024-136"]  # 0XB371
    skein1024_144 = HASH_CODES["skein1024-144"]  # 0XB372
    skein1024_152 = HASH_CODES["skein1024-152"]  # 0XB373
    skein1024_160 = HASH_CODES["skein1024-160"]  # 0XB374
    skein1024_168 = HASH_CODES["skein1024-168"]  # 0XB375
    skein1024_176 = HASH_CODES["skein1024-176"]  # 0XB376
    skein1024_184 = HASH_CODES["skein1024-184"]  # 0XB377
    skein1024_192 = HASH_CODES["skein1024-192"]  # 0XB378
    skein1024_200 = HASH_CODES["skein1024-200"]  # 0XB379
    skein1024_208 = HASH_CODES["skein1024-208"]  # 0XB37A
    skein1024_216 = HASH_CODES["skein1024-216"]  # 0XB37B
    skein1024_224 = HASH_CODES["skein1024-224"]  # 0XB37C
    skein1024_232 = HASH_CODES["skein1024-232"]  # 0XB37D
    skein1024_240 = HASH_CODES["skein1024-240"]  # 0XB37E
    skein1024_248 = HASH_CODES["skein1024-248"]  # 0XB37F
    skein1024_256 = HASH_CODES["skein1024-256"]  # 0XB380
    skein1024_264 = HASH_CODES["skein1024-264"]  # 0XB381
    skein1024_272 = HASH_CODES["skein1024-272"]  # 0XB382
    skein1024_280 = HASH_CODES["skein1024-280"]  # 0XB383
    skein1024_288 = HASH_CODES["skein1024-288"]  # 0XB384
    skein1024_296 = HASH_CODES["skein1024-296"]  # 0XB385
    skein1024_304 = HASH_CODES["skein1024-304"]  # 0XB386
    skein1024_312 = HASH_CODES["skein1024-312"]  # 0XB387
    skein1024_320 = HASH_CODES["skein1024-320"]  # 0XB388
    skein1024_328 = HASH_CODES["skein1024-328"]  # 0XB389
    skein1024_336 = HASH_CODES["skein1024-336"]  # 0XB38A
    skein1024_344 = HASH_CODES["skein1024-344"]  # 0XB38B
    skein1024_352 = HASH_CODES["skein1024-352"]  # 0XB38C
    skein1024_360 = HASH_CODES["skein1024-360"]  # 0XB38D
    skein1024_368 = HASH_CODES["skein1024-368"]  # 0XB38E
    skein1024_376 = HASH_CODES["skein1024-376"]  # 0XB38F
    skein1024_384 = HASH_CODES["skein1024-384"]  # 0XB390
    skein1024_392 = HASH_CODES["skein1024-392"]  # 0XB391
    skein1024_400 = HASH_CODES["skein1024-400"]  # 0XB392
    skein1024_408 = HASH_CODES["skein1024-408"]  # 0XB393
    skein1024_416 = HASH_CODES["skein1024-416"]  # 0XB394
    skein1024_424 = HASH_CODES["skein1024-424"]  # 0XB395
    skein1024_432 = HASH_CODES["skein1024-432"]  # 0XB396
    skein1024_440 = HASH_CODES["skein1024-440"]  # 0XB397
    skein1024_448 = HASH_CODES["skein1024-448"]  # 0XB398
    skein1024_456 = HASH_CODES["skein1024-456"]  # 0XB399
    skein1024_464 = HASH_CODES["skein1024-464"]  # 0XB39A
    skein1024_472 = HASH_CODES["skein1024-472"]  # 0XB39B
    skein1024_480 = HASH_CODES["skein1024-480"]  # 0XB39C
    skein1024_488 = HASH_CODES["skein1024-488"]  # 0XB39D
    skein1024_496 = HASH_CODES["skein1024-496"]  # 0XB39E
    skein1024_504 = HASH_CODES["skein1024-504"]  # 0XB39F
    skein1024_512 = HASH_CODES["skein1024-512"]  # 0XB3A0
    skein1024_520 = HASH_CODES["skein1024-520"]  # 0XB3A1
    skein1024_528 = HASH_CODES["skein1024-528"]  # 0XB3A2
    skein1024_536 = HASH_CODES["skein1024-536"]  # 0XB3A3
    skein1024_544 = HASH_CODES["skein1024-544"]  # 0XB3A4
    skein1024_552 = HASH_CODES["skein1024-552"]  # 0XB3A5
    skein1024_560 = HASH_CODES["skein1024-560"]  # 0XB3A6
    skein1024_568 = HASH_CODES["skein1024-568"]  # 0XB3A7
    skein1024_576 = HASH_CODES["skein1024-576"]  # 0XB3A8
    skein1024_584 = HASH_CODES["skein1024-584"]  # 0XB3A9
    skein1024_592 = HASH_CODES["skein1024-592"]  # 0XB3AA
    skein1024_600 = HASH_CODES["skein1024-600"]  # 0XB3AB
    skein1024_608 = HASH_CODES["skein1024-608"]  # 0XB3AC
    skein1024_616 = HASH_CODES["skein1024-616"]  # 0XB3AD
    skein1024_624 = HASH_CODES["skein1024-624"]  # 0XB3AE
    skein1024_632 = HASH_CODES["skein1024-632"]  # 0XB3AF
    skein1024_640 = HASH_CODES["skein1024-640"]  # 0XB3B0
    skein1024_648 = HASH_CODES["skein1024-648"]  # 0XB3B1
    skein1024_656 = HASH_CODES["skein1024-656"]  # 0XB3B2
    skein1024_664 = HASH_CODES["skein1024-664"]  # 0XB3B3
    skein1024_672 = HASH_CODES["skein1024-672"]  # 0XB3B4
    skein1024_680 = HASH_CODES["skein1024-680"]  # 0XB3B5
    skein1024_688 = HASH_CODES["skein1024-688"]  # 0XB3B6
    skein1024_696 = HASH_CODES["skein1024-696"]  # 0XB3B7
    skein1024_704 = HASH_CODES["skein1024-704"]  # 0XB3B8
    skein1024_712 = HASH_CODES["skein1024-712"]  # 0XB3B9
    skein1024_720 = HASH_CODES["skein1024-720"]  # 0XB3BA
    skein1024_728 = HASH_CODES["skein1024-728"]  # 0XB3BB
    skein1024_736 = HASH_CODES["skein1024-736"]  # 0XB3BC
    skein1024_744 = HASH_CODES["skein1024-744"]  # 0XB3BD
    skein1024_752 = HASH_CODES["skein1024-752"]  # 0XB3BE
    skein1024_760 = HASH_CODES["skein1024-760"]  # 0XB3BF
    skein1024_768 = HASH_CODES["skein1024-768"]  # 0XB3C0
    skein1024_776 = HASH_CODES["skein1024-776"]  # 0XB3C1
    skein1024_784 = HASH_CODES["skein1024-784"]  # 0XB3C2
    skein1024_792 = HASH_CODES["skein1024-792"]  # 0XB3C3
    skein1024_800 = HASH_CODES["skein1024-800"]  # 0XB3C4
    skein1024_808 = HASH_CODES["skein1024-808"]  # 0XB3C5
    skein1024_816 = HASH_CODES["skein1024-816"]  # 0XB3C6
    skein1024_824 = HASH_CODES["skein1024-824"]  # 0XB3C7
    skein1024_832 = HASH_CODES["skein1024-832"]  # 0XB3C8
    skein1024_840 = HASH_CODES["skein1024-840"]  # 0XB3C9
    skein1024_848 = HASH_CODES["skein1024-848"]  # 0XB3CA
    skein1024_856 = HASH_CODES["skein1024-856"]  # 0XB3CB
    skein1024_864 = HASH_CODES["skein1024-864"]  # 0XB3CC
    skein1024_872 = HASH_CODES["skein1024-872"]  # 0XB3CD
    skein1024_880 = HASH_CODES["skein1024-880"]  # 0XB3CE
    skein1024_888 = HASH_CODES["skein1024-888"]  # 0XB3CF
    skein1024_896 = HASH_CODES["skein1024-896"]  # 0XB3D0
    skein1024_904 = HASH_CODES["skein1024-904"]  # 0XB3D1
    skein1024_912 = HASH_CODES["skein1024-912"]  # 0XB3D2
    skein1024_920 = HASH_CODES["skein1024-920"]  # 0XB3D3
    skein1024_928 = HASH_CODES["skein1024-928"]  # 0XB3D4
    skein1024_936 = HASH_CODES["skein1024-936"]  # 0XB3D5
    skein1024_944 = HASH_CODES["skein1024-944"]  # 0XB3D6
    skein1024_952 = HASH_CODES["skein1024-952"]  # 0XB3D7
    skein1024_960 = HASH_CODES["skein1024-960"]  # 0XB3D8
    skein1024_968 = HASH_CODES["skein1024-968"]  # 0XB3D9
    skein1024_976 = HASH_CODES["skein1024-976"]  # 0XB3DA
    skein1024_984 = HASH_CODES["skein1024-984"]  # 0XB3DB
    skein1024_992 = HASH_CODES["skein1024-992"]  # 0XB3DC
    skein1024_1000 = HASH_CODES["skein1024-1000"]  # 0XB3DD
    skein1024_1008 = HASH_CODES["skein1024-1008"]  # 0XB3DE
    skein1024_1016 = HASH_CODES["skein1024-1016"]  # 0XB3DF
    skein1024_1024 = HASH_CODES["skein1024-1024"]  # 0XB3E0
    poseidon_bls12_381_a2_fc1 = HASH_CODES["poseidon-bls12_381-a2-fc1"]  # 0XB401
    poseidon_bls12_381_a2_fc1_sc = HASH_CODES["poseidon-bls12_381-a2-fc1-sc"]  # 0XB402
    ssz_sha2_256_bmt = HASH_CODES["ssz-sha2-256-bmt"]  # 0XB502
    sha2_256_chunked = HASH_CODES["sha2-256-chunked"]  # 0XB510
    bittorrent_pieces_root = HASH_CODES["bittorrent-pieces-root"]  # 0XB702
    bcrypt_pbkdf = HASH_CODES["bcrypt-pbkdf"]  # 0XD00D
    ed2k = HASH_CODES["ed2k"]  # 0XED20


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


class Blake3Hash:
    """hashlib-compatible wrapper for Blake3 using official blake3 library.

    BLAKE3 is a cryptographic hash function that is much faster than MD5, SHA-1, SHA-2,
    and SHA-3, yet is just as secure as the latest standard SHA-3.

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

    name: str = "blake3"
    digest_size: int = 32
    block_size: int = 64

    def __init__(self) -> None:
        self._hasher = blake3.blake3()

    def update(self, data: bytes) -> None:
        """Update the hash with data."""
        self._hasher.update(data)

    def digest(self) -> bytes:
        """Return digest."""
        return self._hasher.digest()

    def hexdigest(self) -> str:
        """Return hex digest."""
        return self._hasher.hexdigest()

    def copy(self) -> "Blake3Hash":
        """Create a copy of the hash state."""
        c = Blake3Hash()
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
        (Func.shake_128, "shake_128", None),  # Variable length - use ShakeHash wrapper
        (Func.shake_256, "shake_256", None),  # Variable length - use ShakeHash wrapper
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
        # Blake3 (using official blake3 library)
        (Func.blake3, "blake3", Blake3Hash),
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
            length: Optional length for SHAKE hashes. Required for SHAKE. Returns None if None for SHAKE.

        Returns:
            Hash object or None if not available

        Note:
            SHAKE functions (shake_128, shake_256) require a length parameter
            to specify the output digest size. If length is None for SHAKE
            functions, this method returns None.
        """
        new = cls._func_hash[func].new
        if new is None:
            # Handle SHAKE functions with variable length
            if func == Func.shake_128:
                if length is None:
                    return None
                return ShakeHash(hashlib.shake_128, length)
            elif func == Func.shake_256:
                if length is None:
                    return None
                return ShakeHash(hashlib.shake_256, length)
            return None
        return new()


# Initialize the function hash registry.
FuncReg.reset()
