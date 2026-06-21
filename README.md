# 🔍 BlockSec Auditor

[![Go Report Card](https://goreportcard.com/badge/github.com/Al-Gharbi/blocksec-auditor)](https://goreportcard.com/report/github.com/Al-Gharbi/blocksec-auditor)
[![CI](https://github.com/Al-Gharbi/blocksec-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/Al-Gharbi/blocksec-auditor/actions)

BlockSec Auditor is a security tool for auditing Ethereum and EVM-based nodes. It checks for common misconfigurations and security vulnerabilities in node endpoints and configuration files.

## Features

- **Direct Audit**: Connects to JSON-RPC endpoints to check for exposure, unlocked accounts, and admin API access.
- **Config Analysis**: Analyzes Geth (TOML) and Nethermind (JSON) configuration files.
- **Vulnerability Database**: Checks client versions against a built-in database of known CVEs.
- **Reports**: Generates detailed reports in JSON and HTML formats.

## Installation

```bash
make build
```

## Usage

```bash
./blocksec-auditor audit --rpc-url http://localhost:8545
```

## License

MIT
