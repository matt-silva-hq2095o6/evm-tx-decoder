import pytest
from evm_tx_decoder.calldata import (
    split_calldata,
    decode_basic_abi,
    resolve_selector,
    SelectorCache,
)

# ERC-20 transfer(address to, uint256 amount)
TRANSFER_HEX = (
    "0xa9059cbb"
    "000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa96045"
    "0000000000000000000000000000000000000000000000056bc75e2d63100000"
)

# Uniswap swapExactTokensForTokens
SWAP_HEX = "0x38ed17390000000000000000000000000000000000000000000000000000000000000001"


def test_split_calldata():
    selector, chunks = split_calldata(TRANSFER_HEX)
    assert selector == "0xa9059cbb"
    assert len(chunks) == 2
    assert chunks[0] == "000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa96045"
    assert chunks[1] == "0000000000000000000000000000000000000000000000056bc75e2d63100000"


def test_empty_calldata():
    selector, chunks = split_calldata(b"")
    assert selector is None
    assert chunks == []


def test_short_calldata_under_4_bytes():
    selector, chunks = split_calldata("0x1234")
    # Shorter than standard 4-byte selector
    assert selector == "0x1234"
    assert chunks == []


def test_unaligned_calldata_tail():
    # 4 bytes selector + 32 bytes word + 4 stray bytes
    raw = "0x11223344" + ("00" * 32) + "deadbeef"
    selector, chunks = split_calldata(raw)
    assert selector == "0x11223344"
    assert len(chunks) == 2
    assert chunks[1] == "deadbeef"  # trailing unpadded remnant


def test_decode_basic_transfer():
    decoded = decode_basic_abi(TRANSFER_HEX)
    assert decoded["selector"] == "0xa9059cbb"
    assert len(decoded["params"]) == 2
    # Address strips leading zeros down to 20 bytes
    assert decoded["params"][0]["as_address"] == "0xd8da6bf26964af9d7eed9e03e53415d37aa96045"
    # 100 * 10**18 in wei
    assert decoded["params"][1]["as_uint"] == 100000000000000000000


def test_builtin_selector_resolution():
    sig = resolve_selector("0xa9059cbb")
    assert sig == "transfer(address,uint256)"


def test_custom_selector_cache(tmp_path):
    cache_file = tmp_path / "signatures.json"
    cache_file.write_text('{"0xdeadbeef": "pwn()"}', encoding="utf-8")

    cache = SelectorCache(local_path=cache_file)
    assert cache.lookup("0xdeadbeef") == "pwn()"
    assert cache.lookup("0x00000000") is None

    # write back new signature
    cache.add("0x12345678", "customMethod(uint256)")
    assert cache.lookup("0x12345678") == "customMethod(uint256)"
