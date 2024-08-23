# Solana AccountsDB Reader

Forked [the original repo](https://github.com/godmodegalactus/solana-accountsdb-compression-dictionary-utils) to add Drift specific filtering of accounts from snapshots and outputs to a series of json files (`--max_accounts_per_file` accounts each) for easy consumption by test frameworks.

# Drift filtering rules
* accounts owned by Drift (`dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH`)
* clock account (`SysvarC1ock11111111111111111111111111111111`)
* oracle accounts by parsing latest `PerpMarket` and `SpotMarket` accounts


# Running
```bash
cargo run --bin solana-accountsdb-dictionary-creator -- \
-a /path/to/snapshots/snapshot-285291102-4qgm3tsNBzajWfeYYPAYxv6NeYCzPDsRp1eGF63jvLCm.tar.zst \
-o /path/to/output/dir \
-m 10000
-r https://api.drift-api.com/rpc
```

* you will need to provide a valid RPC endpoint with `getProgramAccounts` support
	* `-r/--rpc_endpoint`
	* `RPC_ENDPOINT` environment variable
* snapshots can be downloaded from a validator/rpc or check the instructions using snapshot finder [here]()