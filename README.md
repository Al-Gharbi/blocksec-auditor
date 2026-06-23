# BlockSec Auditor

[![Go Report Card](https://goreportcard.com/badge/github.com/Al-Gharbi/blocksec-auditor)](https://goreportcard.com/report/github.com/Al-Gharbi/blocksec-auditor)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**BlockSec Auditor** is a high-performance, security-focused auditing tool designed for Ethereum and EVM-compatible blockchain nodes. Built with Go, it provides node operators and security researchers with a comprehensive suite of checks to identify infrastructure-level vulnerabilities, misconfigurations, and outdated software.

## 🛡️ Key Security Features

### 1. RPC & Network Security
- **Public Exposure Detection**: Verifies if JSON-RPC endpoints are accessible without proper authentication.
- **Administrative API Audit**: Checks for exposed dangerous methods (e.g., `admin_*`, `personal_*`) on public interfaces.
- **CORS Misconfiguration**: Identifies insecure `Access-Control-Allow-Origin` settings that could lead to Cross-Origin attacks.
- **TLS/SSL Verification**: Ensures that data in transit is encrypted via HTTPS/TLS.

### 2. P2P & Infrastructure Analysis
- **Eclipse Attack Prevention**: Monitors peer counts (`net_peerCount`) to ensure the node is connected to a healthy number of peers, mitigating isolation risks.
- **Account Security**: Scans for unlocked accounts (`eth_accounts`) on the node that could be targeted for unauthorized fund withdrawals.
- **Configuration File Auditing**: Static analysis of Geth (TOML) and Nethermind (JSON) configuration files to detect insecure binding or module exposure.

### 3. Vulnerability Intelligence
- **CVE Matching**: Integrates a built-in vulnerability database (VulnDB) updated with 2024 CVEs.
- **Client Version Fingerprinting**: Automatically identifies the node client and version to match against known security advisories.

## 🚀 Getting Started

### Using Docker (Recommended)
The fastest way to run the auditor without installing dependencies:
```bash
docker build -t blocksec-auditor .
docker run blocksec-auditor audit --rpc-url http://your-node-ip:8545
```

### Manual Installation
Requires **Go 1.21+**:
```bash
git clone https://github.com/Al-Gharbi/blocksec-auditor.git
cd blocksec-auditor
make build
./blocksec-auditor audit --rpc-url http://localhost:8545
```

## 📊 Reporting
BlockSec Auditor generates professional-grade reports in multiple formats:
- **JSON**: For automated pipelines and integration with other security tools.
- **HTML**: Clean, human-readable dashboards for security audits and management reviews.

## 🛠️ Built With
- **Go**: For concurrency and performance.
- **Cobra**: Powering the CLI interface.
- **Docker**: For seamless deployment and isolation.

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
