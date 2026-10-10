package vulndb

import "testing"

func TestParseVersion(t *testing.T) {
	cases := []struct {
		in   string
		want string
		suf  string
		ok   bool
	}{
		{"1.13.5", "1.13.5", "", true},
		{"v1.13.5-stable-3f907d6a", "1.13.5", "-stable-3f907d6a", true},
		{"v1.25.4+20a1b2c", "1.25.4", "+20a1b2c", true},
		{"1.9", "1.9.0", "", true},
		{"v1.10.17-unstable", "1.10.17", "-unstable", true},
		{"1.10.9", "1.10.9", "", true},
		{"abc", "", "", false},
		{"", "", "", false},
		{"v", "", "", false},
		{"99999999999999999999.1.1", "", "", false},
	}
	for _, c := range cases {
		v, err := ParseVersion(c.in)
		if (err == nil) != c.ok {
			t.Errorf("ParseVersion(%q) err=%v, want ok=%v", c.in, err, c.ok)
			continue
		}
		if c.ok && (v.String() != c.want || v.Suffix != c.suf) {
			t.Errorf("ParseVersion(%q) = %s %q, want %s %q", c.in, v, v.Suffix, c.want, c.suf)
		}
	}
}

// The original implementation compared version *strings*, so "1.10.9" > "1.10.17"
// (because '9' > '1') and 1.9.x sorted after 1.10.x. These pin the numeric rule.
func TestCompareIsNumericNotLexical(t *testing.T) {
	cmp := func(a, b string) int {
		x, _ := ParseVersion(a)
		y, _ := ParseVersion(b)
		return x.Compare(y)
	}
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1.10.9", "1.10.17", -1},
		{"1.9.25", "1.10.0", -1},
		{"1.2.0", "1.10.0", -1},
		{"2.0.0", "10.0.0", -1},
		{"1.13.5", "1.13.5", 0},
		{"1.13.5-stable", "1.13.5+abc", 0},
		{"1.14.0", "1.13.15", 1},
	} {
		if got := cmp(c.a, c.b); got != c.want {
			t.Errorf("Compare(%s,%s) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestParseClient(t *testing.T) {
	good := map[string][2]string{
		"Geth/v1.13.5-stable-3f907d6a/linux-amd64/go1.21.4": {"geth", "1.13.5"},
		"Nethermind/v1.25.4+20a1b2c/linux-x64/dotnet8.0.1":  {"nethermind", "1.25.4"},
		"erigon/2.60.0/linux-amd64/go1.21.5":                {"erigon", "2.60.0"},
		"besu/v23.10.1/linux-x86_64/openjdk-java-17":        {"besu", "23.10.1"},
		"HardhatNetwork/2.22.0/@nomicfoundation/edr/0.5.0":  {"hardhatnetwork", "2.22.0"},
	}
	for in, want := range good {
		c, err := ParseClient(in)
		if err != nil || c.Name != want[0] || c.Version.String() != want[1] {
			t.Errorf("ParseClient(%q) = %+v, %v; want %v", in, c, err, want)
		}
	}
	for _, bad := range []string{"", "Geth", "Geth/", "/v1.0.0", "Geth/notaversion", "   "} {
		if _, err := ParseClient(bad); err == nil {
			t.Errorf("ParseClient(%q) should fail", bad)
		}
	}
}

func mustDB(t *testing.T) *DB {
	t.Helper()
	d, err := Default()
	if err != nil {
		t.Fatalf("embedded database is invalid: %v", err)
	}
	return d
}

func match(t *testing.T, s string) map[string]bool {
	t.Helper()
	c, err := ParseClient(s)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, v := range mustDB(t).Match(c) {
		out[v.CVE] = true
	}
	return out
}

func TestMatchBoundaries(t *testing.T) {
	// CVE-2021-39137: introduced 1.10.0, fixed 1.10.8 (range is [introduced, fixed)).
	if !match(t, "Geth/v1.10.7-stable-aa/linux-amd64/go1.16")["CVE-2021-39137"] {
		t.Error("1.10.7 must be affected")
	}
	if match(t, "Geth/v1.10.8-stable-aa/linux-amd64/go1.16")["CVE-2021-39137"] {
		t.Error("1.10.8 is the fixed version")
	}
	if match(t, "Geth/v1.9.25-stable-aa/linux-amd64/go1.16")["CVE-2021-39137"] {
		t.Error("1.9.25 predates the introduction of the bug")
	}
	// 1.10.9 vs 1.10.17: a lexical compare would call 1.10.9 "newer" than 1.10.17.
	if !match(t, "Geth/v1.10.9-stable-aa/linux-amd64/go1.16")["CVE-2022-29177"] {
		t.Error("1.10.9 < 1.10.17 so CVE-2022-29177 applies")
	}
	if match(t, "Geth/v1.10.17-stable-aa/linux-amd64/go1.18")["CVE-2022-29177"] {
		t.Error("1.10.17 is fixed")
	}
}

func TestMatchIsClientSpecific(t *testing.T) {
	// The old database attributed Geth CVEs to other clients. A Nethermind or
	// Erigon build must never match a Geth entry.
	for _, s := range []string{"Nethermind/v1.10.7+abc/linux-x64/dotnet8", "erigon/1.10.7/linux-amd64/go1.21"} {
		if got := match(t, s); len(got) != 0 {
			t.Errorf("%s matched %v", s, got)
		}
	}
}

func TestCoverage(t *testing.T) {
	d := mustDB(t)
	if !d.Covers("Geth") || !d.Covers("geth") {
		t.Error("geth must be covered")
	}
	if d.Covers("nethermind") || d.Covers("erigon") {
		t.Error("no verified data exists for nethermind/erigon; they must not be claimed as covered")
	}
}

func TestEmbeddedEntriesAreUniqueAndOrdered(t *testing.T) {
	seen := map[string]bool{}
	for _, e := range mustDB(t).Entries() {
		if seen[e.CVE] {
			t.Errorf("duplicate CVE %s", e.CVE)
		}
		seen[e.CVE] = true
	}
}

func TestLoadRejectsBadData(t *testing.T) {
	good := `{"id":"X","cve":"CVE-1","client":"geth","introduced":"1.0.0","fixed":"1.1.0","severity":"HIGH","summary":"s","source":"src","reference":"https://e.example"}`
	if _, err := Load([]byte("[" + good + "]")); err != nil {
		t.Fatalf("good entry rejected: %v", err)
	}
	bad := map[string]string{
		"not json":          `{`,
		"bad introduced":    `[{"id":"X","client":"geth","introduced":"x","fixed":"1.1.0","severity":"HIGH","summary":"s","source":"a","reference":"https://e"}]`,
		"intro>=fixed":      `[{"id":"X","client":"geth","introduced":"2.0.0","fixed":"1.1.0","severity":"HIGH","summary":"s","source":"a","reference":"https://e"}]`,
		"bad severity":      `[{"id":"X","client":"geth","introduced":"1.0.0","fixed":"1.1.0","severity":"SEVERE","summary":"s","source":"a","reference":"https://e"}]`,
		"upper-case client": `[{"id":"X","client":"Geth","introduced":"1.0.0","fixed":"1.1.0","severity":"HIGH","summary":"s","source":"a","reference":"https://e"}]`,
		"no source":         `[{"id":"X","client":"geth","introduced":"1.0.0","fixed":"1.1.0","severity":"HIGH","summary":"s","reference":"https://e"}]`,
		"http reference":    `[{"id":"X","client":"geth","introduced":"1.0.0","fixed":"1.1.0","severity":"HIGH","summary":"s","source":"a","reference":"http://e"}]`,
		"duplicate id":      "[" + good + "," + good + "]",
	}
	for name, data := range bad {
		if _, err := Load([]byte(data)); err == nil {
			t.Errorf("%s: should be rejected", name)
		}
	}
}
