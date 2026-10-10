# Validation

What was checked, against what, and what was **not**. Dates are 2026-10; commands are in the
repository so every number below can be reproduced.

## 1. Vulnerability list vs Geth's own advisory data (real data)

`tools/validate-vulndb` evaluates, for every stable Geth release tag, the `check` regular
expression of each entry in Geth's `vulnerabilities.json` (the file behind `geth version-check`)
and compares the result with this project's version-range matcher.

| Input | Value |
|-------|-------|
| Advisory source | `cmd/geth/testdata/vcheck/vulnerabilities.json` at go-ethereum `v1.14.0` (10 entries) |
| Release versions | 241 stable tags `vX.Y.Z` of `ethereum/go-ethereum` (279 tags in total; pre-releases excluded) |
| CVEs compared | 8 (those present in both the file and `data.json`) |
| Result | **241 / 241 identical** |

Sensitivity: three deliberate mutations of `data.json` (a fixed version off by one, an
introduced version off by one, and an invalid range) were each caught (1 differing tag, 1 differing
tag, load error), so the comparison is not vacuous.

Limits:
* The build strings are *synthesised* from the tag (`Geth/vX.Y.Z-stable-0123abcd/linux-amd64/go1.21.0`);
  real nodes report their own commit hash and Go version. Matching ignores both.
* The advisory file is the snapshot embedded in `v1.14.0`; newer advisories are absent from it.
* CVE-2023-40591 and CVE-2024-32972 are **not** in that file. They come from OSV
  (fixed in 1.12.1 and 1.13.15) and were read from there, not cross-checked by this tool.
* Two entries in Geth's file were deliberately left out: GETH-2020-02 (depends on the Go runtime
  version) and GETH-2021-01 (no CVE; testnet fork readiness).
* Severities of Geth-sourced entries are Geth's own ratings; OSV-sourced ones are derived from the
  published CVSS vector. Severity of a finding is not a measure of risk to your deployment.

CVE metadata that was corrected from the original data was read from NVD and OSV on the same day:
CVE-2024-21503 (Python `black` ReDoS), CVE-2023-42319 (Geth GraphQL, disputed, "up to and including
1.13.4"), CVE-2022-23328 (Geth, "all versions").

## 2. Config audit vs real Nethermind configs (real data)

All 91 files in `src/Nethermind/Nethermind.Runner/configs` of `NethermindEth/nethermind` were
audited with the CLI.

| Outcome | Files |
|---------|-------|
| parsed without error | 91 / 91 |
| `PASS` | 89 |
| `FAIL` | 2 (`spaceneth.json`, `spaceneth_persistent.json`: Admin, Debug, Personal modules enabled; `Host` is `127.0.0.1`, reported as `CFG-002` LOW "loopback only") |

This is the expected result: those two are single-node development configs. Of the 80 files with a
`JsonRpc` section only 11 set `Host` (all `127.0.0.1`); 5 use `AdditionalRpcUrls` (all
`localhost`). **No real config in the corpus binds a public address**, so the positive path
(`CFG-001`, `CFG-003`, `CFG-004`) is covered only by hand-written fixtures in `testdata/`.

The Geth TOML parser was written from `node.Config` in go-ethereum (`HTTPHost`, `HTTPModules`,
`HTTPVirtualHosts`, `HTTPCors`, `WSHost`, `WSModules`, `WSOrigins`, all in the `[Node]` table)
and tested on fixtures shaped like `geth dumpconfig`; it was not run on a file produced by a real
`geth` binary.

## 3. RPC checks (mocks only)

The seven RPC checks are covered by unit tests against an in-process JSON-RPC server that answers
unknown methods with Geth's real "method not found" error (code -32601, text from
`rpc/errors.go`). Covered: read-only allow-list, exposed / absent / denied / invalid-params
classification, unlocked / locked / unknown accounts, CORS variants, TLS, version matching,
peer-count parsing, an unreachable node never yielding `PASS`, HTML escaping of node-controlled
strings, terminal control-character stripping, bounded response size, no redirect following.

**Not verified:** no real node (Geth, Nethermind, Erigon, Besu, Hardhat, Anvil) was scanned. The
sandbox used for development could not install or download one. Behaviour against real servers
that differ from the mock (error codes for unauthorised calls, `personal_listWallets` payloads on
other clients, gateways that rewrite errors) is untested. Do not rely on BSA-ADM-001,
BSA-ACC-001 and BSA-RPC-001 outcomes without confirming them manually on your own node.

## 4. Other things not verified

* Docker image build and the GitHub Actions workflow were not executed.
* Go 1.21 specifically: tests ran on the local toolchain (1.24) with `go 1.21` language version.
* Windows/macOS builds.

## Reproducing

```bash
git clone --depth 1 --filter=blob:none --sparse https://github.com/ethereum/go-ethereum.git geth
git -C geth fetch --depth 1 origin refs/tags/v1.14.0:refs/tags/v1.14.0
git -C geth show v1.14.0:cmd/geth/testdata/vcheck/vulnerabilities.json > vulnerabilities.json
git -C geth ls-remote --tags origin | sed 's#.*refs/tags/##' | grep -v '\^{}' > tags.txt
go run ./tools/validate-vulndb vulnerabilities.json tags.txt

git clone --depth 1 --filter=blob:none --sparse https://github.com/NethermindEth/nethermind.git
git -C nethermind sparse-checkout set --skip-checks src/Nethermind/Nethermind.Runner/configs
for f in nethermind/src/Nethermind/Nethermind.Runner/configs/*.json; do ./blocksec-auditor audit --config-file "$f" --output json; done
```
