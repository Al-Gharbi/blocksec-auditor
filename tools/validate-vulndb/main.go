// validate-vulndb cross-checks the embedded vulnerability list against Geth's
// own machine-readable advisory file (vulnerabilities.json) over real release
// version strings.
//
// Usage:
//
//	validate-vulndb <vulnerabilities.json> <tags.txt>
//
// tags.txt holds one release tag per line (e.g. from `git tag`). For each
// stable tag X.Y.Z a build string of the form Geth/vX.Y.Z-stable-<hash>/... is
// synthesised, then both sides are asked which advisories apply:
//   - Geth: the "check" regular expression of each entry, as geth's own
//     `version-check` command evaluates it;
//   - blocksec-auditor: vulndb.Match.
//
// Entries are compared by CVE. Any disagreement is printed; the exit status
// is 1 if there is one that is not listed in the known-quirks table.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/Al-Gharbi/blocksec-auditor/internal/vulndb"
)

type gethEntry struct {
	UID   string `json:"uid"`
	CVE   string `json:"CVE"`
	Check string `json:"check"`
	Intro string `json:"introduced"`
	Fixed string `json:"fixed"`
}

var stable = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: validate-vulndb <vulnerabilities.json> <tags.txt>")
		os.Exit(2)
	}
	raw, err := os.ReadFile(os.Args[1])
	must(err)
	var geth []gethEntry
	must(json.Unmarshal(raw, &geth))
	tagsRaw, err := os.ReadFile(os.Args[2])
	must(err)

	db, err := vulndb.Default()
	must(err)

	type rx struct {
		cve string
		re  *regexp.Regexp
	}
	var checks []rx
	for _, g := range geth {
		if g.CVE == "" || g.CVE == "None" || strings.Contains(g.Check, "go1.") {
			continue // no CVE to key on, or depends on the Go runtime version
		}
		checks = append(checks, rx{g.CVE, regexp.MustCompile(g.Check)})
	}
	// Only entries present on both sides can be compared. Entries sourced from
	// OSV rather than from Geth's file (see "source" in data.json) are reported
	// as not cross-checked.
	ours := map[string]bool{}
	inGeth := map[string]bool{}
	for _, c := range checks {
		inGeth[c.cve] = true
	}
	var notCompared []string
	for _, e := range db.Entries() {
		if inGeth[e.CVE] {
			ours[e.CVE] = true
		} else {
			notCompared = append(notCompared, e.CVE)
		}
	}

	tested, agree := 0, 0
	var diffs []string
	for _, tag := range strings.Fields(string(tagsRaw)) {
		if !stable.MatchString(tag) {
			continue
		}
		build := fmt.Sprintf("Geth/%s-stable-0123abcd/linux-amd64/go1.21.0", tag)
		info, err := vulndb.ParseClient(build)
		must(err)
		mine := map[string]bool{}
		for _, v := range db.Match(info) {
			if ours[v.CVE] {
				mine[v.CVE] = true
			}
		}
		theirs := map[string]bool{}
		for _, c := range checks {
			if c.re.MatchString(build) && ours[c.cve] {
				theirs[c.cve] = true
			}
		}
		tested++
		if same(mine, theirs) {
			agree++
			continue
		}
		diffs = append(diffs, fmt.Sprintf("%-10s ours=%v geth=%v", tag, keys(mine), keys(theirs)))
	}
	fmt.Printf("compared CVEs: %d, not in Geth's file (not cross-checked): %v\n", len(ours), notCompared)
	fmt.Printf("release tags tested: %d, identical results: %d, differing: %d\n", tested, agree, len(diffs))
	for _, d := range diffs {
		fmt.Println("  DIFF", d)
	}
	if len(diffs) > 0 {
		os.Exit(1)
	}
}

func same(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
}
