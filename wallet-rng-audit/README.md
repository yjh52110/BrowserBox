# Wallet extension weak-RNG audit

Batch loop for the 3425-extension catalog:

1. Download 10 packages
2. Launch 10 auditors (one per package) to look for weak-RNG defects
3. Delete the downloaded/unpacked files
4. Repeat until progress is 100%

## Commands

```bash
python3 wallet-rng-audit/parse_catalog.py \
  /path/to/CRX_WALLET_DOWNLOAD_LINKS_6180.md \
  wallet-rng-audit/catalog.json

# Hold the next 10 packages for live agent review
python3 wallet-rng-audit/prepare_batch.py --size 10

# After agents finish
python3 wallet-rng-audit/delete_hold.py /tmp/wallet-rng-hold

# Autonomous loop: download 10 → scan → delete → repeat
python3 wallet-rng-audit/orchestrator.py --batches 0

python3 wallet-rng-audit/summarize.py
```

Held packages live in `/tmp/wallet-rng-hold` and are deleted after audit.
The orchestrator work directory is `/tmp/wallet-rng-work` and is removed per task.
