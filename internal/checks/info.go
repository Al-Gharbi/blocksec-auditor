package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/Al-Gharbi/blocksec-auditor/internal/scanner"
	"github.com/Al-Gharbi/blocksec-auditor/internal/vulndb"
)

// ---- Client version / known vulnerabilities --------------------------------

type clientVersion struct{ base }

func NewClientVersion() Check {
	return clientVersion{base{
		id: "BSA-VER-001", name: "Client Version Matches Known Vulnerabilities", risk: RiskMedium,
		desc:        "Reads web3_clientVersion and matches it against a curated list of published client advisories",
		remediation: "Upgrade the client to a release at or above the fixed version listed for each advisory.",
	}}
}

func (c clientVersion) Run(ctx context.Context, cl *scanner.Client, _ Options) CheckResult {
	raw, err := cl.Call(ctx, "web3_clientVersion")
	if err != nil {
		if scanner.IsMethodNotFound(err) {
			return c.skipped("node does not implement web3_clientVersion")
		}
		return c.errored(err)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return c.errored(err)
	}
	db, err := vulndb.Default()
	if err != nil {
		return c.errored(err)
	}
	info, err := vulndb.ParseClient(s)
	if err != nil {
		return c.result(StatusSkipped, c.risk, map[string]string{"client_version": s, "reason": "version string not understood"})
	}
	if !db.Covers(info.Name) {
		return c.result(StatusSkipped, c.risk, map[string]interface{}{
			"client_version": s,
			"reason":         "no verified advisory data for client " + info.Name + "; this is NOT evidence that it is up to date",
			"covered":        db.Clients(),
		})
	}
	vulns := db.Match(info)
	d := map[string]interface{}{"client_version": s, "parsed_version": info.Version.String(), "vulnerabilities": vulns}
	if len(vulns) == 0 {
		return c.pass(d)
	}
	worst := RiskLow
	fixed := ""
	for _, v := range vulns {
		if r := RiskLevel(v.Severity); r.Rank() > worst.Rank() {
			worst = r
		}
		fv, _ := vulndb.ParseVersion(v.Fixed)
		if cur, _ := vulndb.ParseVersion(fixed); fixed == "" || fv.Compare(cur) > 0 {
			fixed = v.Fixed
		}
	}
	d["upgrade_to_at_least"] = fixed
	return c.fail(worst, d)
}

// ---- Peer count --------------------------------------------------------------

type peerCount struct{ base }

func NewPeerCount() Check {
	return peerCount{base{
		id: "BSA-P2P-001", name: "Low Peer Count", risk: RiskLow,
		desc:        "Flags a node connected to very few peers (a health signal; few peers also make eclipse attacks easier)",
		remediation: "Check connectivity, firewall rules for the P2P port and discovery settings.",
	}}
}

func (c peerCount) Run(ctx context.Context, cl *scanner.Client, o Options) CheckResult {
	raw, err := cl.Call(ctx, "net_peerCount")
	if err != nil {
		if scanner.IsMethodNotFound(err) || scanner.IsAccessDenied(err) {
			return c.skipped("net_peerCount is not available: " + err.Error())
		}
		return c.errored(err)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return c.errored(err)
	}
	n, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(s), "0x"), 16, 32)
	if err != nil {
		return c.errored(fmt.Errorf("unparseable peer count %q", s))
	}
	d := map[string]interface{}{"peer_count": n, "minimum": o.MinPeers}
	if int(n) < o.MinPeers {
		return c.fail(RiskLow, d)
	}
	return c.pass(d)
}
