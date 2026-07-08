from dataclasses import dataclass
from typing import Any, Optional
import json
import urllib.request
import urllib.error


@dataclass
class DecodedCall:
    selector: str
    signature: Optional[str]
    params: dict[str, Any]
    raw_words: list[str]


# Common ERC20 / WETH / ERC721 / Uniswap selectors
KNOWN_SELECTORS: dict[str, tuple[str, list[tuple[str, str]]]] = {
    "0xa9059cbb": ("transfer(address,uint256)", [("recipient", "address"), ("amount", "uint256")]),
    "0x095ea7b3": ("approve(address,uint256)", [("spender", "address"), ("amount", "uint256")]),
    "0x23b872dd": (
        "transferFrom(address,address,uint256)",
        [("sender", "address"), ("recipient", "address"), ("amount", "uint256")],
    ),
    "0xd0e30db0": ("deposit()", []),
    "0x2e1a7d4d": ("withdraw(uint256)", [("wad", "uint256")]),
    "0x70a08231": ("balanceOf(address)", [("account", "address")]),
    "0x42842e0e": ("safeTransferFrom(address,address,uint256)", [("from", "address"), ("to", "address"), ("id", "uint256")]),
    "0x3593564c": ("execute(bytes,bytes[],uint256)", [("commands", "bytes"), ("inputs", "bytes[]"), ("deadline", "uint256")]),
}

# in-memory cache for online lookups to avoid hammering 4byte directory
_SIGNATURE_CACHE: dict[str, str] = {}


def extract_selector(data: bytes) -> Optional[str]:
    if len(data) < 4:
        return None
    return "0x" + data[:4].hex()


def split_words(data: bytes) -> list[bytes]:
    payload = data[4:] if len(data) >= 4 else data
    words = []
    for i in range(0, len(payload), 32):
        chunk = payload[i : i + 32]
        if len(chunk) < 32:
            chunk = chunk.ljust(32, b"\x00")
        words.append(chunk)
    return words


def _decode_dynamic_string(payload: bytes, offset: int) -> str:
    # sanity check on offsets to prevent huge memory allocations on bogus data
    if offset < 0 or offset + 32 > len(payload):
        return "<offset out of bounds>"
    length = int.from_bytes(payload[offset : offset + 32], byteorder="big")
    if length > len(payload):
        return "<invalid string length>"
    str_start = offset + 32
    str_end = str_start + length
    if str_end > len(payload):
        return "<truncated string>"
    raw = payload[str_start:str_end]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return "0x" + raw.hex()


def _decode_dynamic_bytes(payload: bytes, offset: int) -> str:
    if offset < 0 or offset + 32 > len(payload):
        return "0x"
    length = int.from_bytes(payload[offset : offset + 32], byteorder="big")
    if length > len(payload):
        return "0x" + payload[offset + 32:].hex()
    start = offset + 32
    return "0x" + payload[start : start + length].hex()


def _decode_address_array(payload: bytes, offset: int) -> list[str]:
    if offset < 0 or offset + 32 > len(payload):
        return []
    count = int.from_bytes(payload[offset : offset + 32], byteorder="big")
    if count > 500:  # safety cap against malformed calldata
        return []
    res = []
    curr = offset + 32
    for _ in range(count):
        if curr + 32 > len(payload):
            break
        # addresses are right-aligned in 32 byte words
        res.append("0x" + payload[curr + 12 : curr + 32].hex())
        curr += 32
    return res


def decode_static_param(val_bytes: bytes, type_name: str) -> Any:
    if type_name == "address":
        return "0x" + val_bytes[12:].hex()
    elif type_name in ("uint256", "uint8", "uint128", "uint64"):
        return int.from_bytes(val_bytes, byteorder="big")
    elif type_name in ("int256", "int128"):
        return int.from_bytes(val_bytes, byteorder="big", signed=True)
    elif type_name == "bool":
        return int.from_bytes(val_bytes, byteorder="big") != 0
    elif type_name.startswith("bytes32"):
        return "0x" + val_bytes.hex()
    return "0x" + val_bytes.hex()


def lookup_4byte_online(selector: str, timeout: float = 1.5) -> Optional[str]:
    if selector in _SIGNATURE_CACHE:
        return _SIGNATURE_CACHE[selector]

    clean_sel = selector.lower().removeprefix("0x")
    url = f"https://www.4byte.directory/api/v1/signatures/?hex_signature=0x{clean_sel}"
    
    req = urllib.request.Request(url, headers={"User-Agent": "evm-tx-decoder-cli"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                body = json.loads(resp.read().decode("utf-8"))
                results = body.get("results", [])
                if results:
                    # earliest submission is usually the canonical one
                    results.sort(key=lambda r: r.get("id", 9999999))
                    text_sig = results[0].get("text_signature")
                    if text_sig:
                        _SIGNATURE_CACHE[selector] = text_sig
                        return text_sig
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        pass

    return None


def decode_calldata(data: bytes, fetch_online: bool = False) -> DecodedCall:
    """Attempts to extract selector and unpack arguments using built-in ABI table."""
    selector = extract_selector(data)
    if not selector:
        return DecodedCall(selector="", signature=None, params={}, raw_words=[])

    payload = data[4:]
    words = split_words(data)
    raw_hex_words = ["0x" + w.hex() for w in words]

    sig: Optional[str] = None
    schema: list[tuple[str, str]] = []

    if selector in KNOWN_SELECTORS:
        sig, schema = KNOWN_SELECTORS[selector]
    elif fetch_online:
        sig = lookup_4byte_online(selector)

    if not schema:
        return DecodedCall(
            selector=selector,
            signature=sig,
            params={},
            raw_words=raw_hex_words,
        )

    params: dict[str, Any] = {}
    # FIXME: handle nested dynamic tuples properly if anyone actually passes them
    for i, (param_name, param_type) in enumerate(schema):
        if i >= len(words):
            params[param_name] = None
            continue

        # print(f"decoding {param_name} ({param_type}) from word {i}")
        if param_type in ("string", "bytes"):
            offset = int.from_bytes(words[i], byteorder="big")
            if param_type == "string":
                params[param_name] = _decode_dynamic_string(payload, offset)
            else:
                params[param_name] = _decode_dynamic_bytes(payload, offset)
        elif param_type == "address[]":
            offset = int.from_bytes(words[i], byteorder="big")
            params[param_name] = _decode_address_array(payload, offset)
        else:
            params[param_name] = decode_static_param(words[i], param_type)

    return DecodedCall(
        selector=selector,
        signature=sig,
        params=params,
        raw_words=raw_hex_words,
    )
