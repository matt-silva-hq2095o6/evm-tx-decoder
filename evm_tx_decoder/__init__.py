"""Quick hex parsing and decoding for raw EVM transactions."""

__version__ = "0.3.0"

from evm_tx_decoder.calldata import parse_calldata_words
from evm_tx_decoder.envelope import decode_raw_tx, parse_envelope
from evm_tx_decoder.types import (
    BlobTransaction,
    FeeMarketTransaction,
    AccessListTransaction,
    LegacyTransaction,
    Transaction,
)


def decode(raw_hex: str | bytes) -> Transaction:
    """Decode raw transaction bytes or hex string into a typed transaction object."""
    if isinstance(raw_hex, str):
        raw_hex = raw_hex.strip()
        if raw_hex.startswith(("0x", "0X")):
            raw_hex = raw_hex[2:]
        data = bytes.fromhex(raw_hex)
    else:
        data = raw_hex
    return decode_raw_tx(data)


__all__ = [
    "decode",
    "decode_raw_tx",
    "parse_envelope",
    "parse_calldata_words",
    "Transaction",
    "LegacyTransaction",
    "AccessListTransaction",
    "FeeMarketTransaction",
    "BlobTransaction",
    "__version__",
]
