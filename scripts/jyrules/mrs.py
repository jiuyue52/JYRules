from __future__ import annotations

import io
import struct
from array import array

import zstandard

from .errors import BuildError


MAX_DECOMPRESSED_MRS_BYTES = 256 * 1024 * 1024
MAX_DOMAIN_KEY_BYTES = 4096
MAX_DOMAIN_NODES = 10_000_000
MRS_MAGIC = b"MRS\x01"
DOMAIN_BEHAVIOR = 0


class _BinaryReader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.view = memoryview(data)
        self.offset = 0

    def take_view(self, size: int) -> memoryview:
        if size < 0 or size > len(self.data) - self.offset:
            raise BuildError("truncated domain MRS payload")
        start = self.offset
        self.offset += size
        return self.view[start : start + size]

    def take(self, size: int) -> bytes:
        return bytes(self.take_view(size))

    def int64(self) -> int:
        return struct.unpack(">q", self.take(8))[0]

    def uint64_array(self, count: int) -> memoryview:
        if count < 1 or count > (len(self.data) - self.offset) // 8:
            raise BuildError("invalid domain MRS array length")
        return self.take_view(count * 8)


def _decompress(data: bytes) -> bytes:
    try:
        with zstandard.ZstdDecompressor().stream_reader(io.BytesIO(data)) as stream:
            decoded = stream.read(MAX_DECOMPRESSED_MRS_BYTES + 1)
    except (OSError, zstandard.ZstdError) as exc:
        raise BuildError(f"invalid zstd-compressed MRS: {exc}") from exc
    if len(decoded) > MAX_DECOMPRESSED_MRS_BYTES:
        raise BuildError(
            f"decompressed MRS exceeds {MAX_DECOMPRESSED_MRS_BYTES} bytes"
        )
    return decoded


def _bit(words: memoryview, index: int) -> int:
    word_count = len(words) // 8
    if index < 0 or index >= word_count * 64:
        raise BuildError("domain MRS bitmap index is out of range")
    word_index = index >> 6
    bit_in_word = index & 63
    byte_index = word_index * 8 + 7 - (bit_in_word >> 3)
    return (words[byte_index] >> (bit_in_word & 7)) & 1


def _one_positions(words: memoryview) -> array[int]:
    positions = array("I")
    for word_index in range(len(words) // 8):
        start = word_index * 8
        value = int.from_bytes(words[start : start + 8], "big")
        while value:
            lowest = value & -value
            positions.append(word_index * 64 + lowest.bit_length() - 1)
            value ^= lowest
    return positions


def _domain_set_keys(
    leaves: memoryview,
    label_bitmap: memoryview,
    labels: memoryview,
) -> tuple[str, ...]:
    node_count = len(labels) + 1
    if node_count > MAX_DOMAIN_NODES:
        raise BuildError(
            f"domain MRS exceeds the {MAX_DOMAIN_NODES} trie-node limit"
        )
    leaves_word_count = len(leaves) // 8
    label_word_count = len(label_bitmap) // 8
    if leaves_word_count != (node_count + 63) // 64:
        raise BuildError("domain MRS leaves bitmap has an invalid length")
    label_bit_count = len(labels) * 2 + 1
    if label_word_count != (label_bit_count + 63) // 64:
        raise BuildError("domain MRS label bitmap has an invalid length")
    if any(
        _bit(leaves, index)
        for index in range(node_count, leaves_word_count * 64)
    ):
        raise BuildError("domain MRS leaves bitmap has out-of-range entries")

    terminators = _one_positions(label_bitmap)
    if len(terminators) != node_count or terminators[-1] != len(labels) * 2:
        raise BuildError("domain MRS label bitmap is malformed")

    edge_count = 0
    for node_id in range(node_count):
        start = 0 if node_id == 0 else terminators[node_id - 1] + 1
        end = terminators[node_id]
        for bitmap_index in range(start, end):
            if _bit(label_bitmap, bitmap_index):
                raise BuildError("domain MRS label bitmap is malformed")
            label_index = bitmap_index - node_id
            if label_index != edge_count or not 0 <= label_index < len(labels):
                raise BuildError("domain MRS label index is out of range")
            child_id = label_index + 1
            if child_id <= node_id:
                raise BuildError("domain MRS node ordering is malformed")
            edge_count += 1
    if edge_count != node_count - 1:
        raise BuildError("domain MRS tree is disconnected")

    keys: list[str] = []
    stack: list[tuple[int, bytes]] = [(0, b"")]
    while stack:
        node_id, reversed_key = stack.pop()
        if _bit(leaves, node_id):
            try:
                key = reversed_key.decode("utf-8")[::-1]
            except UnicodeDecodeError as exc:
                raise BuildError("domain MRS contains an invalid UTF-8 key") from exc
            keys.append(key)
        start = 0 if node_id == 0 else terminators[node_id - 1] + 1
        end = terminators[node_id]
        for bitmap_index in range(end - 1, start - 1, -1):
            label_index = bitmap_index - node_id
            child_id = label_index + 1
            next_key = reversed_key + bytes((labels[label_index],))
            if len(next_key) > MAX_DOMAIN_KEY_BYTES:
                raise BuildError("domain MRS contains an oversized domain key")
            stack.append((child_id, next_key))

    return tuple(sorted(keys))


def decode_domain_mrs(data: bytes) -> tuple[str, ...]:
    """Decode domain MRS without Mihomo's lossy .domain text projection."""

    reader = _BinaryReader(_decompress(data))
    if reader.take(4) != MRS_MAGIC:
        raise BuildError("invalid MRS magic bytes")
    if reader.take(1) != bytes((DOMAIN_BEHAVIOR,)):
        raise BuildError("MRS behavior does not match domain task")

    count = reader.int64()
    if count < 1:
        raise BuildError("domain MRS rule count is invalid")
    extra_length = reader.int64()
    if extra_length < 0:
        raise BuildError("domain MRS extra length is invalid")
    reader.take(extra_length)

    if reader.take(1) != b"\x01":
        raise BuildError("unsupported domain-set binary version")
    leaves = reader.uint64_array(reader.int64())
    label_bitmap = reader.uint64_array(reader.int64())
    labels_length = reader.int64()
    if labels_length < 1:
        raise BuildError("invalid domain MRS labels length")
    labels = reader.take_view(labels_length)
    if reader.offset != len(reader.data):
        raise BuildError("domain MRS contains trailing binary data")

    keys = _domain_set_keys(leaves, label_bitmap, labels)
    exact_keys = {key for key in keys if not key.startswith("+.")}
    plus_bases = {key[2:] for key in keys if key.startswith("+.")}

    rules = [key for key in exact_keys if key not in plus_bases]
    for base in plus_bases:
        rules.append(f"+.{base}" if base in exact_keys else f".{base}")
    normalized_rules = tuple(sorted(rules))
    if count < len(normalized_rules):
        raise BuildError("domain MRS count is smaller than its matching set")
    return normalized_rules


__all__ = ["decode_domain_mrs"]
