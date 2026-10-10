# Changelog

## [0.2.0]

### Fixed
- **The scanner changed node state.** The admin check called `personal_newAccount`, which creates
  an account and writes a keystore file on the target. Probes are now read-only and a test
  enforces an allow-list of methods.
- **Unreachable or failing checks counted as passes.** An unreachable endpoint produced a report
  full of green checks. Results now carry `PASS` / `FAIL` / `ERROR` / `SKIPPED`; the CLI exits
  with code 2 when the endpoint is not a JSON-RPC server.
- **Wrong vulnerability data.** CVE-2024-21503 is a Python `black` issue, not Erigon;
  CVE-2023-42319 is a (disputed) Geth GraphQL issue, not Nethermind; CVE-2022-23328 has no fixed
  version; CVE-2022-29177 was fixed in 1.10.17, not 1.10.19; CVE-2021-39137 is HIGH, not
  CRITICAL. The list was rebuilt from primary sources (Geth, OSV) and validated, with
  Nethermind/Erigon entries removed because none could be verified.
- **Version comparison was lexical** (`"1.10.9" > "1.10.17"`). Versions are now parsed and compared
  numerically; errors loading the database are no longer swallowed.
- **Config checks could panic** on unexpected value types and only recognised `0.0.0.0`; they now
  handle `::`, `[::]`, LAN and hostname binds, `HTTPCors`, `WSOrigins`, WebSocket modules and
  Nethermind `AdditionalRpcUrls`, with case-insensitive Nethermind keys and content-based format
  detection (Nethermind configs are JSON regardless of extension).
- **HTML report injected unescaped data** (`text/template`); now `html/template`. Terminal output
  strips control characters from node-supplied strings.
- **JSON output was mixed with coloured text** on stdout; report output is now clean, and results
  are ordered deterministically instead of by goroutine completion.
- `go.mod` required Go 1.25 while CI and Docker used 1.21; aligned on 1.21.
- Probe Origin is `https://blocksec-auditor-probe.invalid` (reserved TLD) instead of a real domain.

### Changed
- `eth_accounts` check renamed "Node-Held Accounts Reachable Over RPC": the method lists keystore
  accounts whether or not they are unlocked; unlocked state is read from `personal_listWallets`
  when the node supports it.
- RPC exposure severity is HIGH (was CRITICAL); admin API exposure remains CRITICAL.
- Default `--output` is `text` (was `json`). Use `--output json` for pipelines.
- Dependencies reduced to `BurntSushi/toml` (Cobra and fatih/color replaced by the standard library).
- Docker image runs as a non-root user.

### Added
- `--fail-on`, `--timeout`, `--min-peers`, `--output-file` (0600), `version` command.
- Real-data validation tool `tools/validate-vulndb` and a CI job that runs it; `docs/VALIDATION.md`.
- 76 tests (was 1).

### Removed
- `ankr_scan.html` (a stray HTML report file committed by mistake).
