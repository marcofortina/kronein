#!/usr/bin/env python3
# Copyright (c) 2026 The Kronein Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Persistent native worker for Kronein's vendored RandomX v2.0.1 implementation."""

import atexit
import hashlib
import os
import subprocess
import threading


REGTEST_SEED = hashlib.sha256(b"Kronein/RandomX/v2/regtest/fixed-seed").digest()
_worker = None
_lock = threading.Lock()


def _get_worker():
    global _worker
    if _worker is not None:
        return _worker

    helper_path = os.getenv("KRONEIN_RANDOMX_HELPER")
    if not helper_path:
        raise RuntimeError("KRONEIN_RANDOMX_HELPER is not set; build the randomx_test_bridge target")
    try:
        # Inherit stderr so sanitizer findings fail the functional test too.
        _worker = subprocess.Popen([helper_path], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   text=True, encoding="ascii")
    except OSError as error:
        raise RuntimeError(f"Unable to start the RandomX test bridge at {helper_path}: {error}") from error
    return _worker


def _stop_worker():
    global _worker
    if _worker is None:
        return
    worker, _worker = _worker, None
    try:
        worker.stdin.close()
    except BrokenPipeError:
        pass
    try:
        status = worker.wait(timeout=10)
    except subprocess.TimeoutExpired:
        worker.kill()
        worker.wait()
        raise RuntimeError("RandomX test bridge did not stop after EOF") from None
    finally:
        worker.stdout.close()
    if status != 0:
        raise RuntimeError(f"RandomX test bridge exited with status {status}")


atexit.register(_stop_worker)


def hash_v2(data, key=REGTEST_SEED):
    """Return the raw 32-byte RandomX v2 hash for data and key."""
    if not key or not data:
        raise ValueError("RandomX key and input must not be empty")
    with _lock:
        worker = _get_worker()
        try:
            worker.stdin.write(f"{key.hex()}\n{data.hex()}\n")
            worker.stdin.flush()
            response = worker.stdout.readline(66)
        except (OSError, UnicodeError) as error:
            raise RuntimeError("RandomX test bridge communication failed") from error
        if len(response) != 65 or response[-1] != "\n":
            raise RuntimeError("RandomX test bridge returned no complete hash")
        try:
            result = bytes.fromhex(response[:-1])
        except ValueError as error:
            raise RuntimeError("RandomX test bridge returned an invalid hash") from error
        if len(result) != 32:
            raise RuntimeError("RandomX test bridge returned an invalid hash size")
        return result
