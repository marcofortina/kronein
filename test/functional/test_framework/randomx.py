#!/usr/bin/env python3
# Copyright (c) 2026 The Kronein Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Thin ctypes binding to Kronein's vendored RandomX v2.0.1 implementation."""

import ctypes
import hashlib
import os


REGTEST_SEED = hashlib.sha256(b"Kronein/RandomX/v2/regtest/fixed-seed").digest()
_library = None


def _load_library():
    global _library
    if _library is not None:
        return _library

    library_path = os.getenv("KRONEIN_RANDOMX_LIBRARY")
    if not library_path:
        raise RuntimeError("KRONEIN_RANDOMX_LIBRARY is not set; build the randomx_test_bridge target")
    try:
        library = ctypes.CDLL(library_path)
    except OSError as error:
        raise RuntimeError(f"Unable to load the RandomX test bridge at {library_path}: {error}") from error

    function = library.kronein_randomx_v2_hash
    byte_pointer = ctypes.POINTER(ctypes.c_ubyte)
    function.argtypes = [byte_pointer, ctypes.c_size_t, byte_pointer, ctypes.c_size_t, byte_pointer]
    function.restype = ctypes.c_int
    _library = library
    return library


def hash_v2(data, key=REGTEST_SEED):
    """Return the raw 32-byte RandomX v2 hash for data and key."""
    if not key or not data:
        raise ValueError("RandomX key and input must not be empty")
    library = _load_library()
    key_buffer = (ctypes.c_ubyte * len(key)).from_buffer_copy(key)
    data_buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    output = (ctypes.c_ubyte * 32)()
    if library.kronein_randomx_v2_hash(key_buffer, len(key), data_buffer, len(data), output) != 1:
        raise RuntimeError("RandomX v2 hashing failed")
    return bytes(output)
