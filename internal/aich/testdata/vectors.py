"""Writes vectors.json: AICH roots and one part's recovery data.

A transcription of aMule's CAICHHashTree recursion (SHAHashSet.cpp FindHash,
CreatePartRecoveryData, WriteLowestLevelHashs) with hashlib, written apart
from the Go code. Data byte i is i % 251. Run: python3 vectors.py > vectors.json
"""
import base64
import hashlib
import json

PART = 9_728_000
BLOCK = 184_320


def data(size):
    pattern = bytes(i % 251 for i in range(251))
    return (pattern * (size // 251 + 1))[:size]


def base_of(size):
    return BLOCK if size <= PART else PART


def split(size, is_left):
    base = base_of(size)
    blocks = -(-size // base)
    left = ((blocks + 1 if is_left else blocks) // 2) * base
    return left, size - left


def node_hash(buf, begin, size, is_left):
    if size <= BLOCK:
        return hashlib.sha1(buf[begin:begin + size]).digest()
    left, right = split(size, is_left)
    return hashlib.sha1(
        node_hash(buf, begin, left, True) + node_hash(buf, begin + left, right, False)
    ).digest()


def leaves(buf, begin, size, is_left, ident, out):
    ident = ident << 1 | is_left
    if size <= BLOCK:
        out.append((ident, hashlib.sha1(buf[begin:begin + size]).digest()))
        return
    left, right = split(size, is_left)
    leaves(buf, begin, left, True, ident, out)
    leaves(buf, begin + left, right, False, ident, out)


def recovery(buf, part):
    size = len(buf)
    part_begin = part * PART
    part_size = min(PART, size - part_begin)
    out = []
    begin, node_size, is_left, ident = 0, size, True, 0
    while not (begin == part_begin and node_size == part_size):
        ident = ident << 1 | is_left
        left, right = split(node_size, is_left)
        if part_begin < begin + left:
            out.append((ident << 1 | 0, node_hash(buf, begin + left, right, False)))
            node_size, is_left = left, True
        else:
            out.append((ident << 1 | 1, node_hash(buf, begin, left, True)))
            begin, node_size, is_left = begin + left, right, False
    leaves(buf, begin, node_size, is_left, ident, out)
    return out


def to_base32(digest):
    return base64.b32encode(digest).decode().rstrip("=")


roots = []
for size in [100, BLOCK, BLOCK + 1, 2_000_000, PART, PART + 1, 3 * PART + 500_000]:
    roots.append({"size": size, "root": to_base32(node_hash(data(size), 0, size, True))})

size, part = 3 * PART + 500_000, 1
recovered = [{"ident": i, "hash": h.hex().upper()} for i, h in recovery(data(size), part)]
print(json.dumps({"roots": roots, "recovery": {"size": size, "part": part, "entries": recovered}}, indent=1))
