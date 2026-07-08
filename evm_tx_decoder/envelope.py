from evm_tx_decoder.rlp import decode as rlp_decode, RlpError
from evm_tx_decoder.types import ParsedTransaction, TxEnvelopeType


def _keccak256(data: bytes) -> bytes:
    try:
        from Crypto.Hash import keccak
        k = keccak.new(digest_bits=256)
        k.update(data)
        return k.digest()
    except ImportError:
        import sha3  # type: ignore
        k = sha3.keccak_256()
        k.update(data)
        return k.digest()


def _to_int(b: bytes) -> int:
    if not b:
        return 0
    return int.from_bytes(b, byteorder="big")


def _parse_access_list(raw_list):
    if not isinstance(raw_list, list):
        return []
    out = []
    for item in raw_list:
        if not isinstance(item, list) or len(item) != 2:
            continue
        addr_b, storage_keys_b = item
        addr = "0x" + addr_b.hex() if isinstance(addr_b, bytes) else ""
        keys = ["0x" + k.hex() for k in storage_keys_b if isinstance(k, bytes)]
        out.append({"address": addr, "storage_keys": keys})
    return out


def _parse_authorization_list(raw_list):
    # EIP-7702 authorization items: [[chain_id, address, nonce, y_parity, r, s], ...]
    if not isinstance(raw_list, list):
        return []
    auths = []
    for entry in raw_list:
        if not isinstance(entry, list) or len(entry) < 6:
            continue
        auths.append({
            "chain_id": _to_int(entry[0]),
            "address": "0x" + entry[1].hex() if entry[1] else "0x",
            "nonce": _to_int(entry[2]),
            "y_parity": _to_int(entry[3]),
            "r": _to_int(entry[4]),
            "s": _to_int(entry[5]),
        })
    return auths


def parse_raw_tx(raw: bytes) -> ParsedTransaction:
    """Dissects raw EVM transaction bytes into a structured envelope."""
    if not raw:
        raise ValueError("Empty raw transaction data")

    # print(f"DEBUG: raw envelope byte={raw[0]:02x}")
    tx_hash = "0x" + _keccak256(raw).hex()
    first_byte = raw[0]

    # EIP-2718 typed transaction envelope prefixes are 0x00 to 0x7f
    if first_byte < 0x80:
        tx_type_int = first_byte
        payload = raw[1:]
        decoded = rlp_decode(payload)

        if not isinstance(decoded, list):
            raise ValueError(f"Invalid RLP payload in typed transaction (type {tx_type_int})")

        if tx_type_int == 1:
            # EIP-2930: [chain_id, nonce, gas_price, gas_limit, to, value, data, access_list, y_parity, r, s]
            if len(decoded) < 11:
                raise ValueError(f"EIP-2930 payload too short: {len(decoded)} items")
            
            return ParsedTransaction(
                tx_hash=tx_hash,
                envelope_type=TxEnvelopeType.EIP2930,
                type_byte=1,
                chain_id=_to_int(decoded[0]),
                nonce=_to_int(decoded[1]),
                gas_price=_to_int(decoded[2]),
                gas_limit=_to_int(decoded[3]),
                to="0x" + decoded[4].hex() if decoded[4] else None,
                value=_to_int(decoded[5]),
                data=decoded[6],
                access_list=_parse_access_list(decoded[7]),
                v=_to_int(decoded[8]),
                r=_to_int(decoded[9]),
                s=_to_int(decoded[10]),
                raw_bytes=raw,
            )

        elif tx_type_int == 2:
            # EIP-1559: [chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to, value, data, access_list, y_parity, r, s]
            if len(decoded) < 11:
                raise ValueError(f"EIP-1559 payload too short: {len(decoded)} items")

            return ParsedTransaction(
                tx_hash=tx_hash,
                envelope_type=TxEnvelopeType.EIP1559,
                type_byte=2,
                chain_id=_to_int(decoded[0]),
                nonce=_to_int(decoded[1]),
                max_priority_fee_per_gas=_to_int(decoded[2]),
                max_fee_per_gas=_to_int(decoded[3]),
                gas_limit=_to_int(decoded[4]),
                to="0x" + decoded[5].hex() if decoded[5] else None,
                value=_to_int(decoded[6]),
                data=decoded[7],
                access_list=_parse_access_list(decoded[8]),
                v=_to_int(decoded[9]),
                r=_to_int(decoded[10]),
                s=_to_int(decoded[11]),
                raw_bytes=raw,
            )

        elif tx_type_int == 3:
            # EIP-4844: [chain_id, nonce, max_priority_fee, max_fee, gas_limit, to, value, data,
            #            access_list, max_fee_per_blob_gas, blob_versioned_hashes, y_parity, r, s]
            # TODO: handle network wrapper wrapper for blob txs (with sidecars: blobs, commitments, proofs)
            if len(decoded) < 14:
                raise ValueError(f"EIP-4844 payload too short: {len(decoded)} items")

            blob_hashes = ["0x" + h.hex() for h in decoded[10] if isinstance(h, bytes)] if isinstance(decoded[10], list) else []
            return ParsedTransaction(
                tx_hash=tx_hash,
                envelope_type=TxEnvelopeType.EIP4844,
                type_byte=3,
                chain_id=_to_int(decoded[0]),
                nonce=_to_int(decoded[1]),
                max_priority_fee_per_gas=_to_int(decoded[2]),
                max_fee_per_gas=_to_int(decoded[3]),
                gas_limit=_to_int(decoded[4]),
                to="0x" + decoded[5].hex() if decoded[5] else None,
                value=_to_int(decoded[6]),
                data=decoded[7],
                access_list=_parse_access_list(decoded[8]),
                max_fee_per_blob_gas=_to_int(decoded[9]),
                blob_versioned_hashes=blob_hashes,
                v=_to_int(decoded[11]),
                r=_to_int(decoded[12]),
                s=_to_int(decoded[13]),
                raw_bytes=raw,
            )

        elif tx_type_int == 4:
            # EIP-7702: [chain_id, nonce, max_priority_fee, max_fee, gas_limit, to, value, data,
            #            access_list, authorization_list, y_parity, r, s]
            if len(decoded) < 13:
                raise ValueError(f"EIP-7702 payload too short: {len(decoded)} items")

            return ParsedTransaction(
                tx_hash=tx_hash,
                envelope_type=TxEnvelopeType.EIP7702,
                type_byte=4,
                chain_id=_to_int(decoded[0]),
                nonce=_to_int(decoded[1]),
                max_priority_fee_per_gas=_to_int(decoded[2]),
                max_fee_per_gas=_to_int(decoded[3]),
                gas_limit=_to_int(decoded[4]),
                to="0x" + decoded[5].hex() if decoded[5] else None,
                value=_to_int(decoded[6]),
                data=decoded[7],
                access_list=_parse_access_list(decoded[8]),
                authorization_list=_parse_authorization_list(decoded[9]),
                v=_to_int(decoded[10]),
                r=_to_int(decoded[11]),
                s=_to_int(decoded[12]),
                raw_bytes=raw,
            )
        else:
            raise ValueError(f"Unsupported EIP-2718 transaction type: 0x{tx_type_int:02x}")

    # Legacy transaction: RLP list [nonce, gas_price, gas_limit, to, value, data, v, r, s]
    decoded = rlp_decode(raw)
    if not isinstance(decoded, list) or len(decoded) < 9:
        raise ValueError("Malformed legacy transaction RLP sequence")

    v_raw = _to_int(decoded[6])
    # EIP-155 replay protection chain ID calculation
    if v_raw >= 35:
        chain_id = (v_raw - 35) // 2
    else:
        chain_id = None

    return ParsedTransaction(
        tx_hash=tx_hash,
        envelope_type=TxEnvelopeType.LEGACY,
        type_byte=None,
        chain_id=chain_id,
        nonce=_to_int(decoded[0]),
        gas_price=_to_int(decoded[1]),
        gas_limit=_to_int(decoded[2]),
        to="0x" + decoded[3].hex() if decoded[3] else None,
        value=_to_int(decoded[4]),
        data=decoded[5],
        access_list=[],
        v=v_raw,
        r=_to_int(decoded[7]),
        s=_to_int(decoded[8]),
        raw_bytes=raw,
    )
