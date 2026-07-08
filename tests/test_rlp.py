import pytest
from evm_tx_decoder.rlp import decode_rlp, RLPDecodeError


def test_decode_single_byte():
    # 0x00 - 0x7f are their own encoding
    val, rem = decode_rlp(b"\x00")
    assert val == b"\x00"
    assert rem == b""

    val, rem = decode_rlp(b"\x42")
    assert val == b"\x42"
    assert rem == b""

    val, rem = decode_rlp(b"\x7f")
    assert val == b"\x7f"
    assert rem == b""


def test_decode_short_string():
    # "dog" -> 0x83 'd' 'o' 'g'
    raw = b"\x83dog"
    val, rem = decode_rlp(raw)
    assert val == b"dog"
    assert rem == b""

    # empty string -> 0x80
    val, rem = decode_rlp(b"\x80")
    assert val == b""
    assert rem == b""


def test_decode_long_string():
    payload = b"a" * 60
    # 0xb8 + length (0x3c) = 0xb8 0x3c
    raw = b"\xb8\x3c" + payload
    val, rem = decode_rlp(raw)
    assert val == payload
    assert rem == b""


def test_decode_list_of_strings():
    # ["cat", "dog"] -> 0xc8 0x83 'c' 'a' 't' 0x83 'd' 'o' 'g'
    raw = bytes.fromhex("c88363617483646f67")
    val, rem = decode_rlp(raw)
    assert val == [b"cat", b"dog"]
    assert rem == b""

    # empty list -> 0xc0
    val, rem = decode_rlp(b"\xc0")
    assert val == []
    assert rem == b""


def test_decode_nested_list():
    # [ [], [[]] ] -> 0xc4 0xc0 0xc2 0xc0
    raw = bytes.fromhex("c4c0c2c0")
    val, rem = decode_rlp(raw)
    assert val == [[], [[]]]
    assert rem == b""


def test_decode_with_trailing_remainder():
    raw = b"\x83dogextradata"
    val, rem = decode_rlp(raw)
    assert val == b"dog"
    assert rem == b"extradata"


def test_decode_empty_input_raises():
    with pytest.raises(RLPDecodeError, match="Empty input"):
        decode_rlp(b"")


def test_decode_truncated_string():
    # claims 4 bytes, only gives 2
    raw = b"\x84ab"
    with pytest.raises(RLPDecodeError, match="Input too short"):
        decode_rlp(raw)


def test_decode_truncated_long_string_length():
    # 0xb9 says length takes 2 bytes, but payload only has 1 byte
    raw = b"\xb9\x01"
    with pytest.raises(RLPDecodeError, match="Input too short for length payload"):
        decode_rlp(raw)


def test_decode_truncated_list_contents():
    # 0xc8 means 8 bytes total, but only 3 supplied
    raw = b"\xc8\x83abc"
    with pytest.raises(RLPDecodeError, match="Input too short for list"):
        decode_rlp(raw)


def test_decode_leading_zero_in_long_length():
    # length 5 encoded as 2 bytes with leading zero (0xb9 0x00 0x05) is invalid RLP
    raw = b"\xb9\x00\x05hello"
    with pytest.raises(RLPDecodeError, match="Leading zero in length"):
        decode_rlp(raw)


def test_decode_non_canonical_short_string_as_long():
    # long-form prefix for length < 56 is illegal
    raw = b"\xb8\x05hello"
    with pytest.raises(RLPDecodeError, match="Non-canonical length encoding"):
        decode_rlp(raw)
