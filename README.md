# evm-tx-decoder

I got tired of spinning up heavy node runtimes or web3.py scripts just to see
what a stuck pending transaction in the mempool is actually trying to do.

`txdec` takes raw hex strings from stdin or CLI arguments and unpacks the
envelope structure (legacy, EIP-2930, EIP-1559, EIP-4844) without connecting
to any RPC provider.

## Install

```bash
pip install .
```

Or run it in place with pip editable mode:

```bash
pip install -e .
```

## Quick usage

Pass the raw hex directly:

```bash
txdec 0x02f8710183021f1c843b9aca008504a817c80082520894dac17f958d2ee523a2206206994597c13d831ec78084a9059cbb80c0
```

Or pipe from `cast` / `curl` / clipboard:

```bash
pbpaste | txdec
```

Format calldata word by word (splits method id and 32-byte chunks):

```bash
txdec --calldata 0xa9059cbb000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec70000000000000000000000000000000000000000000000000000000000000064
```

Output clean JSON if you want to pipe into `jq`:

```bash
txdec --json 0x02f87... | jq '.to, .value'
```

<!-- refreshed: 2026-09-11 -->
