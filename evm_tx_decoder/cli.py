import argparse
import sys
import json
from evm_tx_decoder.envelope import decode_tx_envelope
from evm_tx_decoder.calldata import try_decode_calldata
from evm_tx_decoder.formatters import format_tx_human, format_tx_dict


def sanitize_hex(val: str) -> str:
    val = val.strip()
    # handle json wrapped strings or quotes from mempool curl pastes
    if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
        val = val[1:-1].strip()
    if val.startswith("0x") or val.startswith("0X"):
        val = val[2:]
    # remove intra-payload whitespaces/newlines from wrapped logs
    return "".join(val.split())


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="evm-tx-decoder",
        description="Inspect and dissect raw EVM transaction hex dumps."
    )
    parser.add_argument("hex_data", nargs="?", help="Raw hex transaction string (or pipe via stdin)")
    parser.add_argument("-j", "--json", action="store_true", help="Output in structured JSON format")
    parser.add_argument("--no-calldata", action="store_true", help="Skip calldata selector lookup and decoding")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print raw field offsets and internal rlp debug info")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    raw_input = args.hex_data
    if not raw_input:
        if not sys.stdin.isatty():
            raw_input = sys.stdin.read()
        else:
            parser.print_help(sys.stderr)
            return 1

    cleaned = sanitize_hex(raw_input)
    if not cleaned:
        sys.stderr.write("error: empty transaction payload\n")
        return 1

    try:
        tx_bytes = bytes.fromhex(cleaned)
    except ValueError as err:
        sys.stderr.write(f"error: invalid hex input ({err})\n")
        return 1

    try:
        tx = decode_tx_envelope(tx_bytes)
    except Exception as err:
        sys.stderr.write(f"error decoding transaction envelope: {err}\n")
        return 2

    if not args.no_calldata and tx.data:
        try:
            tx.decoded_calldata = try_decode_calldata(tx.data)
        except Exception:
            # calldata parsing isn't fatal for top-level inspection
            pass

    if args.json:
        out = format_tx_dict(tx)
        sys.stdout.write(json.dumps(out, indent=2) + "\n")
    else:
        formatted = format_tx_human(tx, verbose=args.verbose)
        sys.stdout.write(formatted + "\n")

    return 0
