from typing import Union, List, Tuple


class RLPDecodeError(ValueError):
    pass


RLPItem = Union[bytes, List["RLPItem"]]


def decode_rlp(data: bytes, strict: bool = True) -> RLPItem:
    """Decodes raw bytes into nested byte arrays and lists."""
    item, consumed = decode_rlp_with_offset(data, 0, strict=strict)
    if strict and consumed != len(data):
        raise RLPDecodeError(f"trailing unparsed bytes in payload at offset {consumed}")
    return item


def decode_rlp_with_offset(buf: bytes, pos: int = 0, strict: bool = True) -> Tuple[RLPItem, int]:
    # FIXME: support depth limit check so malicious nesting doesn't blow recursion stack
    if pos >= len(buf):
        raise RLPDecodeError(f"unexpected EOF at offset {pos}")

    prefix = buf[pos]

    # single byte in [0x00, 0x7f]
    if prefix <= 0x7f:
        return bytes([prefix]), pos + 1

    # string 0-55 bytes long
    if prefix <= 0xb7:
        str_len = prefix - 0x80
        pos += 1
        if str_len == 1 and pos < len(buf) and buf[pos] <= 0x7f and strict:
            # canonical RLP check: single byte < 0x80 must be encoded as itself
            raise RLPDecodeError(f"non-canonical single byte encoding at offset {pos - 1}")
        if pos + str_len > len(buf):
            raise RLPDecodeError(f"string length {str_len} exceeds buffer at {pos}")
        # print(f"DEBUG: pos={pos} prefix={prefix:#x} payload_len={str_len}")
        return buf[pos:pos + str_len], pos + str_len

    # string > 55 bytes
    if prefix <= 0xbf:
        len_of_len = prefix - 0xb7
        pos += 1
        if pos + len_of_len > len(buf):
            raise RLPDecodeError("length-of-length extends past EOF")
        len_bytes = buf[pos:pos + len_of_len]
        if strict and len_bytes.startswith(b"\x00"):
            raise RLPDecodeError("leading zero in RLP length prefix")
        str_len = int.from_bytes(len_bytes, "big")
        if strict and str_len <= 55:
            raise RLPDecodeError(f"non-canonical long string length {str_len}")
        pos += len_of_len
        if pos + str_len > len(buf):
            raise RLPDecodeError(f"string payload truncated, expected {str_len} bytes")
        return buf[pos:pos + str_len], pos + str_len

    # list 0-55 bytes of total payload
    if prefix <= 0xf7:
        list_len = prefix - 0xc0
        pos += 1
        end_pos = pos + list_len
        if end_pos > len(buf):
            raise RLPDecodeError(f"list payload truncated at offset {pos}")
        items: List[RLPItem] = []
        while pos < end_pos:
            elem, pos = decode_rlp_with_offset(buf, pos, strict=strict)
            items.append(elem)
        if pos != end_pos:
            raise RLPDecodeError(f"list item length mismatch: pos {pos} != end {end_pos}")
        return items, pos

    # list > 55 bytes
    len_of_len = prefix - 0xf7
    pos += 1
    if pos + len_of_len > len(buf):
        raise RLPDecodeError("list length-of-length extends past EOF")
    len_bytes = buf[pos:pos + len_of_len]
    if strict and len_bytes.startswith(b"\x00"):
        raise RLPDecodeError("leading zero in list length prefix")
    list_len = int.from_bytes(len_bytes, "big")
    if strict and list_len <= 55:
        raise RLPDecodeError(f"non-canonical long list length {list_len}")
    pos += len_of_len
    end_pos = pos + list_len
    if end_pos > len(buf):
        raise RLPDecodeError(f"long list payload truncated at offset {pos}")
    items = []
    while pos < end_pos:
        elem, pos = decode_rlp_with_offset(buf, pos, strict=strict)
        items.append(elem)
    if pos != end_pos:
        raise RLPDecodeError(f"long list item length mismatch: pos {pos} != end {end_pos}")
    return items, pos


def decode_uint(raw: bytes) -> int:
    if not raw:
        return 0
    return int.from_bytes(raw, "big")
