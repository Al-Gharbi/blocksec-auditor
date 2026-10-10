# BlockSec Auditor

[![CI](https://github.com/Al-Gharbi/blocksec-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/Al-Gharbi/blocksec-auditor/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A read-only security auditor for Ethereum / EVM nodes. It inspects a node's JSON-RPC
endpoint and/or its configuration file and reports infrastructure-level
misconfigurations. Written in Go; the only third-party dependency is a TOML parser.

> **Scope.** This tool checks *node infrastructure*. It does not analyse smart contracts
> (see [smart-audit](https://github.com/Al-Gharbi/smart-audit) for that) and it is not a
> replacement for a penetration test.

## What it checks

| ID | Check | Default risk |
|----|-------|--------------|
| BSA-ADM-001 | `admin_*` / `personal_*` methods reachable on the RPC endpoint | CRITICAL |
| BSA-RPC-001 | RPC answers without authentication (as seen from where you scan) | HIGH |
| BSA-ACC-001 | `eth_accounts` lists node-held accounts; unlocked state via `personal_listWallets` when available | HIGH |
| BSA-TLS-001 | RPC reached over plain HTTP (loopback excepted) | HIGH |
| BSA-COR-001 | CORS allows `*`, `null` or a reflected arbitrary origin | MEDIUM |
| BSA-VER-001 | Client version matches a published advisory (Geth only, see below) | by advisory |
| BSA-P2P-001 | Peer count below `--min-peers` (a health signal) | LOW |
| BSA-CFG-001 | Geth TOML / Nethermind JSON config: public bind, dangerous modules, wildcard vhosts/CORS | by finding |

Design rules that every check follows:

* **Read-only.** Only calls that cannot change node state are sent
  (`net_version`, `web3_clientVersion`, `net_peerCount`, `eth_accounts`, `admin_nodeInfo`,
  `admin_peers`, `personal_listWallets`, `personal_listAccounts`). A test enforces this allow-list.
* **Honest outcomes.** Each check ends as `PASS`, `FAIL`, `ERROR` (could not determine) or
  `SKIPPED` (not applicable). Only `PASS` means "checked and fine"; an unreachable node is an
  error, never a clean report.
* **Loopback-aware.** A node on `127.0.0.1` cannot be "publicly exposed" from the machine it runs
  on: those checks are skipped, and findings that only matter remotely are capped at MEDIUM.
  Run the scan from another host to assess real exposure.

## Install and run

Requires Go 1.21+ (or use Docker).

```bash
git clone https://github.com/Al-Gharbi/blocksec-auditor.git
cd blocksec-auditor
make build

./blocksec-auditor audit --rpc-url https://rpc.example.org
./blocksec-auditor audit --config-file /etc/geth/config.toml
./blocksec-auditor audit --rpc-url http://10.0.0.5:8545 --output json --fail-on high
```

```
Options:
  --rpc-url         JSON-RPC endpoint (http or https)
  --config-file     Geth (TOML) or Nethermind (JSON) config file; format detected from content
  --output          text (default) | json | html
  --output-file     write the report to a file (mode 0600) instead of stdout
  --fail-on         none (default) | low | medium | high | critical
  --timeout         per-request timeout (default 10s)
  --min-peers       peer count below which BSA-P2P-001 fails (default 3)
```

Exit codes: `0` success, `1` a finding at or above `--fail-on`, `2` usage error or the audit
could not run (e.g. endpoint unreachable). `ERROR` / `SKIPPED` results never trigger `1`.

Docker (note that `localhost` inside a container is the container itself):

```bash
docker build -t blocksec-auditor .
docker run --rm --network host blocksec-auditor audit --rpc-url http://127.0.0.1:8545
```

## Vulnerability data: scope and limits

BSA-VER-001 compares the node's `web3_clientVersion` with a **small curated list**
(`internal/vulndb/data.json`, 10 Geth advisories). Every entry names its source and was
checked against a primary one (Geth's own `vulnerabilities.json`, or OSV). Versions are compared
numerically as `X.Y.Z`; build suffixes (`-stable-…`, `+commit`) are ignored.

* Only **Geth** is covered. For any other client the check reports `SKIPPED`
  ("no verified advisory data"), which is **not** evidence that the client is up to date.
* The list is not a complete advisory feed. Treat a clean result as "no match in this list".
* Entries that depend on the Go runtime version, or are disputed or have no fixed release, are
  deliberately excluded.

## Validation

See [docs/VALIDATION.md](docs/VALIDATION.md) for what was verified against real data
(241 real Geth release versions, 91 real Nethermind configs), what was only tested with mocks,
and what was not verified at all (notably: **no live node was scanned**).

## Development

```bash
make test     # go test -race ./...
make lint     # gofmt + go vet
go run ./tools/validate-vulndb vulnerabilities.json tags.txt   # see docs/VALIDATION.md
```

## License

MIT, see [LICENSE](LICENSE).
