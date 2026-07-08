import json
from typing import Any, Dict, Optional
from evm_tx_decoder.types import ParsedTx


def _format_wei(val: Optional[int]) -> str:
    if val is None:
        return "n/a"
    if val == 0:
        return "0 ETH"
    if val < 10**9:
        return f"{val} wei"
    if val < 10**15:
        gwei = val / 10**9
        return f"{gwei:.4f}".rstrip("0").rstrip(".") + " gwei"
    eth = val / 10**18
    return f"{eth:.6f}".rstrip("0").rstrip(".") + " ETH"


def _format_gwei(val: Optional[int]) -> str:
    if val is None:
        return "n/a"
    gwei = val / 10**9
    if gwei == int(gwei):
        return f"{int(gwei)} gwei"
    return f"{gwei:.3f}".rstrip("0").rstrip(".") + " gwei"


def format_json(tx: ParsedTx, indent: int = 2) -> str:
    """Convert parsed transaction into formatted JSON string."""
    payload: Dict[str, Any] = {
        "tx_type": tx.tx_type.name.lower(),
        "type_id": tx.tx_type.value,
        "hash": tx.tx_hash,
        "chain_id": tx.chain_id,
        "nonce": tx.nonce,
        "from": tx.sender,
        "to": tx.to,
        "value_wei": tx.value,
        "value_formatted": _format_wei(tx.value),
        "gas_limit": tx.gas_limit,
    }

    if tx.gas_price is not None:
        payload["gas_price_wei"] = tx.gas_price
        payload["gas_price_gwei"] = _format_gwei(tx.gas_price)
    if tx.max_fee_per_gas is not None:
        payload["max_fee_per_gas_wei"] = tx.max_fee_per_gas
        payload["max_fee_per_gas_gwei"] = _format_gwei(tx.max_fee_per_gas)
    if tx.max_priority_fee_per_gas is not None:
        payload["max_priority_fee_per_gas_wei"] = tx.max_priority_fee_per_gas
        payload["max_priority_fee_per_gas_gwei"] = _format_gwei(tx.max_priority_fee_per_gas)

    if tx.max_fee_per_blob_gas is not None:
        payload["max_fee_per_blob_gas_wei"] = tx.max_fee_per_blob_gas
        payload["max_fee_per_blob_gas_gwei"] = _format_gwei(tx.max_fee_per_blob_gas)
    if tx.blob_versioned_hashes:
        payload["blob_versioned_hashes"] = ["0x" + h.hex() for h in tx.blob_versioned_hashes]

    payload["data"] = "0x" + tx.data.hex() if tx.data else "0x"
    payload["data_bytes"] = len(tx.data)

    if tx.access_list:
        payload["access_list"] = [
            {"address": item.address, "storage_keys": item.storage_keys}
            for item in tx.access_list
        ]

    payload["sig"] = {
        "v": tx.v,
        "r": hex(tx.r),
        "s": hex(tx.s),
    }
    return json.dumps(payload, indent=indent)


def format_table(
    tx: ParsedTx,
    selector_hint: Optional[str] = None,
    dump_calldata: bool = False,
) -> str:
    lines = []
    header = f"--- EVM Transaction ({tx.tx_type.name}) ---"
    lines.append(header)
    lines.append(f"{'Hash:':<24} {tx.tx_hash}")
    lines.append(f"{'From:':<24} {tx.sender or 'unknown'}")
    lines.append(f"{'To:':<24} {tx.to or '[Contract Creation]'}")
    lines.append(f"{'Nonce:':<24} {tx.nonce}")
    lines.append(f"{'Value:':<24} {_format_wei(tx.value)} ({tx.value} wei)")
    lines.append(f"{'Chain ID:':<24} {tx.chain_id if tx.chain_id is not None else 'legacy (no eip-155)'}")
    lines.append(f"{'Gas Limit:':<24} {tx.gas_limit:,}")

    if tx.gas_price is not None:
        lines.append(f"{'Gas Price:':<24} {_format_gwei(tx.gas_price)}")
    if tx.max_fee_per_gas is not None:
        lines.append(f"{'Max Fee / Gas:':<24} {_format_gwei(tx.max_fee_per_gas)}")
    if tx.max_priority_fee_per_gas is not None:
        lines.append(f"{'Max Priority / Gas:':<24} {_format_gwei(tx.max_priority_fee_per_gas)}")
    if tx.max_fee_per_blob_gas is not None:
        lines.append(f"{'Max Fee / Blob Gas:':<24} {_format_gwei(tx.max_fee_per_blob_gas)}")
    if tx.blob_versioned_hashes:
        lines.append(f"{'Blob Hashes:':<24} {len(tx.blob_versioned_hashes)} blobs")
        for i, bh in enumerate(tx.blob_versioned_hashes):
            lines.append(f"  [{i}] 0x{bh.hex()}")

    if tx.access_list:
        lines.append(f"{'Access List:':<24} {len(tx.access_list)} accounts")
        for item in tx.access_list:
            lines.append(f"  - {item.address} ({len(item.storage_keys)} keys)")

    calldata_len = len(tx.data)
    if calldata_len == 0:
        lines.append(f"{'Calldata:':<24} 0 bytes")
    else:
        raw_hex = tx.data.hex()
        preview = raw_hex[:48] + ("..." if calldata_len > 24 else "")
        lines.append(f"{'Calldata:':<24} {calldata_len} bytes (0x{preview})")
        if selector_hint:
            lines.append(f"{'Method:':<24} {selector_hint}")
        elif calldata_len >= 4:
            lines.append(f"{'Selector:':<24} 0x{raw_hex[:8]}")

        # FIXME: multi-line calldata dump wraps badly on 80-col terminals without padding
        if dump_calldata and calldata_len > 0:
            lines.append("Calldata Hex:")
            # print(f"DEBUG: dumping {calldata_len} bytes of calldata")
            for offset in range(0, calldata_len, 32):
                chunk = tx.data[offset:offset + 32]
                hex_part = chunk.hex()
                lines.append(f"  [{offset:04x}] {hex_part}")

    lines.append(f"{'Signature:':<24} v={tx.v} r={hex(tx.r)[:14]}... s={hex(tx.s)[:14]}...")
    lines.append("-" * len(header))
    return "\n".join(lines)
