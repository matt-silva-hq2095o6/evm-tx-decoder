import pytest
from evm_tx_decoder.envelope import parse_envelope, recover_sender
from evm_tx_decoder.types import TxType

# Mainnet legacy tx (EIP-155 replay protected, chain_id = 1)
# Transfer 0.01 ETH
LEGACY_TX_HEX = (
    "0xf86c098504a817c80082520894353b300b810d0f553aebfb72865e012f0" 
    "a0bfb61872386f26fc100008025a028ef61340ec96d091a7e00f51e92001" 
    "8b6fb404b0eef9a6835549d8e2a16df14a002c23c0d0d92b523674fad615" 
    "45d9129da82306099bee526038656f43dd95" 
)

# Pre-EIP155 tx (v = 27)
PRE_EIP155_TX_HEX = (
    "0xf861808082520894353b300b810d0f553aebfb72865e012f0a0bfb618080"
    "1ba028ef61340ec96d091a7e00f51e920018b6fb404b0eef9a6835549d8e2a16df14"
    "a002c23c0d0d92b523674fad61545d9129da82306099bee526038656f43dd95"
)

# EIP-2930 (type 1) with an access list entry
EIP2930_TX_HEX = (
    "0x01f86601018504a817c80082520894353b300b810d0f553aebfb72865e012f0a0bfb61"
    "8080f838f7941111111111111111111111111111111111111111e1a00000000000000000"
    "00000000000000000000000000000000000000000000000180a0c9519f4f2b30335884581"
    "971573db96d43e6dfb4ec567d1d63a4ba641f313b16a063b466230f3e1fad6fa7355f802"
    "1c5247b3e6479532938ac83777b7895e34747"
)

# Arbitrum / mainnet style EIP-1559 type-2 tx
EIP1559_TX_HEX = (
    "0x02f8700103843b9aca008502540be400825208940000000000000000000000000000000000000000"
    "8080c080a0c9519f4f2b30335884581971573db96d43e6dfb4ec567d1d63a4ba641f313b16"
    "a063b466230f3e1fad6fa7355f8021c5247b3e6479532938ac83777b7895e34747"
)

# EIP-4844 (type 3) blob tx
EIP4844_TX_HEX = (
    "0x03f8880101843b9aca008502540be400825208940000000000000000000000000000000000000000"
    "8080c085012a05f200e1a00100000000000000000000000000000000000000000000000000000000000001"
    "80a0c9519f4f2b30335884581971573db96d43e6dfb4ec567d1d63a4ba641f313b16"
    "a063b466230f3e1fad6fa7355f8021c5247b3e6479532938ac83777b7895e34747"
)


def test_parse_legacy_tx():
    tx = parse_envelope(LEGACY_TX_HEX)
    assert tx.tx_type == TxType.LEGACY
    assert tx.chain_id == 1
    assert tx.nonce == 9
    assert tx.gas_price == 20000000000
    assert tx.gas_limit == 21000
    assert tx.to_address == "0x353b300b810d0f553aebfb72865e012f0a0bfb61"
    assert tx.value == 10000000000000000
    assert tx.data == b""


def test_parse_pre_eip155_legacy_tx():
    tx = parse_envelope(PRE_EIP155_TX_HEX)
    assert tx.tx_type == TxType.LEGACY
    assert tx.chain_id is None
    assert tx.v == 27


def test_parse_eip2930_tx():
    tx = parse_envelope(EIP2930_TX_HEX)
    assert tx.tx_type == TxType.EIP2930
    assert tx.chain_id == 1
    assert tx.gas_price == 20000000000
    assert len(tx.access_list) == 1
    assert tx.access_list[0][0] == "0x1111111111111111111111111111111111111111"
    assert len(tx.access_list[0][1]) == 1


def test_parse_eip1559_tx():
    tx = parse_envelope(EIP1559_TX_HEX)
    assert tx.tx_type == TxType.EIP1559
    assert tx.chain_id == 1
    assert tx.nonce == 3
    assert tx.max_priority_fee_per_gas == 1000000000
    assert tx.max_fee_per_gas == 10000000000
    assert tx.gas_limit == 21000
    assert tx.to_address == "0x0000000000000000000000000000000000000000"
    assert tx.access_list == []


def test_parse_eip4844_tx():
    tx = parse_envelope(EIP4844_TX_HEX)
    assert tx.tx_type == TxType.EIP4844
    assert tx.chain_id == 1
    assert tx.max_fee_per_blob_gas == 5000000000
    assert len(tx.blob_versioned_hashes) == 1
    assert tx.blob_versioned_hashes[0].hex().startswith("01")


def test_recover_signer_legacy():
    tx = parse_envelope(LEGACY_TX_HEX)
    sender = recover_sender(tx)
    # Known sender for this fixture
    assert sender.lower() == "0x9b33a01397b14068565b9fc078e4d3db26998d36".lower()


def test_invalid_prefix_fails():
    # Type 0x05 not in spec
    bad_hex = "0x05f85001"
    with pytest.raises(ValueError, match="Unsupported transaction type prefix: 0x05"):
        parse_envelope(bad_hex)


def test_truncated_payload_raises():
    with pytest.raises(ValueError):
        parse_envelope("0x02")
