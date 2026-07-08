from dataclasses import dataclass, field
from typing import Optional, List, Tuple, Any


@dataclass
class Signature:
    v: int
    r: int
    s: int
    y_parity: Optional[int] = None


@dataclass
class AccessTuple:
    address: bytes
    storage_keys: List[bytes] = field(default_factory=list)


@dataclass
class CalldataParam:
    name: Optional[str]
    type_str: str
    value: Any
    offset: int


@dataclass
class DecodedCalldata:
    selector: bytes
    signature: Optional[str]
    params: List[CalldataParam] = field(default_factory=list)
    raw_input: bytes = field(default=b"")


@dataclass
class TxData:
    txtype: int  # legacy=0, 2930=1, 1559=2, 4844=3
    nonce: int
    to: Optional[bytes]
    value: int
    data: bytes
    gas_limit: int
    gas_price: Optional[int] = None
    max_priority_fee_per_gas: Optional[int] = None
    max_fee_per_gas: Optional[int] = None
    max_fee_per_blob_gas: Optional[int] = None
    blob_versioned_hashes: List[bytes] = field(default_factory=list)
    access_list: List[AccessTuple] = field(default_factory=list)
    chain_id: Optional[int] = None
    sig: Optional[Signature] = None
    decoded_calldata: Optional[DecodedCalldata] = None
    raw_bytes: bytes = field(default=b"")
