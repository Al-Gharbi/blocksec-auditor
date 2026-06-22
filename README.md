# BlockSec Auditor

BlockSec Auditor is a security tool designed for auditing Ethereum and EVM-compatible nodes. It helps developers and node operators identify common misconfigurations and security vulnerabilities in their infrastructure.

## Key Features

- **RPC Security Scanning**: Tests JSON-RPC endpoints for public exposure, authentication requirements, and insecure CORS settings.
- **Node Configuration Analysis**: Scans Geth (TOML) and Nethermind (JSON) configuration files for potential weaknesses.
- **Vulnerability Assessment**: Compares client versions against known CVE databases to identify outdated software.
- **Detailed Reporting**: Generates comprehensive security reports in both JSON and HTML formats.

## Getting Started

### Prerequisites

- Go 1.21 or higher

### Installation

Clone the repository and build the binary:

```bash
git clone https://github.com/Al-Gharbi/blocksec-auditor.git
cd blocksec-auditor
make build
```

## Usage

To run a security audit against a live node:

```bash
./blocksec-auditor audit --rpc-url http://localhost:8545
```

To analyze a configuration file:

```bash
./blocksec-auditor audit --config-file path/to/config.toml
```

## License

This project is licensed under the MIT License.
