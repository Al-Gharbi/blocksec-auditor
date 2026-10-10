// Package vulndb matches a node's web3_clientVersion string against a small,
// curated list of published client vulnerabilities.
//
// The list is NOT a complete advisory feed. It only contains entries whose
// affected range could be checked against a primary source (see "source" in
// data.json), and only for clients listed in Clients(). A client with no
// entries must be reported as "no data", never as "no known vulnerabilities".
package vulndb

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

//go:embed data.json
var dbBytes []byte

// Vulnerability is one advisory entry. A build is affected when
// Introduced <= version < Fixed (versions compared numerically as X.Y.Z).
type Vulnerability struct {
	ID         string `json:"id"`
	CVE        string `json:"cve"`
	Client     string `json:"client"`
	Introduced string `json:"introduced"`
	Fixed      string `json:"fixed"`
	Severity   string `json:"severity"`
	Summary    string `json:"summary"`
	Source     string `json:"source"`
	Reference  string `json:"reference"`
}

// Version is a parsed X.Y.Z client version. Any suffix ("-stable-3f907d6a",
// "+20a1b2c", "-unstable") is kept in Suffix but ignored for comparison:
// clients publish builds of the form X.Y.Z-<channel>-<commit>, and an
// "-unstable" build of X.Y.Z is a development build *after* the stable release
// of the same number, so numeric comparison is the correct, conservative rule.
type Version struct {
	Major, Minor, Patch int
	Suffix              string
}

func (v Version) String() string { return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch) }

// Compare returns -1, 0 or 1.
func (v Version) Compare(o Version) int {
	for _, p := range [][2]int{{v.Major, o.Major}, {v.Minor, o.Minor}, {v.Patch, o.Patch}} {
		if p[0] < p[1] {
			return -1
		}
		if p[0] > p[1] {
			return 1
		}
	}
	return 0
}

var versionRE = regexp.MustCompile(`^v?(\d+)\.(\d+)(?:\.(\d+))?(.*)$`)

// ParseVersion parses "1.13.5", "v1.13.5-stable-abc", "v1.25.4+20a1b2c".
// A missing patch number is treated as 0.
func ParseVersion(s string) (Version, error) {
	m := versionRE.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return Version{}, fmt.Errorf("not a version: %q", s)
	}
	atoi := func(x string) (int, error) {
		if x == "" {
			return 0, nil
		}
		n, err := strconv.Atoi(x)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("version component out of range: %q", x)
		}
		return n, nil
	}
	var v Version
	var err error
	if v.Major, err = atoi(m[1]); err != nil {
		return Version{}, err
	}
	if v.Minor, err = atoi(m[2]); err != nil {
		return Version{}, err
	}
	if v.Patch, err = atoi(m[3]); err != nil {
		return Version{}, err
	}
	v.Suffix = m[4]
	return v, nil
}

// ClientInfo is the result of parsing web3_clientVersion.
type ClientInfo struct {
	Raw     string
	Name    string // lower-cased, e.g. "geth", "nethermind", "erigon"
	Version Version
}

// ParseClient parses strings such as
//
//	Geth/v1.13.5-stable-3f907d6a/linux-amd64/go1.21.4
//	Nethermind/v1.25.4+20a1b2c/linux-x64/dotnet8.0.1
//	erigon/2.60.0/linux-amd64/go1.21.5
func ParseClient(s string) (ClientInfo, error) {
	parts := strings.Split(strings.TrimSpace(s), "/")
	if len(parts) < 2 || parts[0] == "" {
		return ClientInfo{}, fmt.Errorf("unrecognised client string %q", s)
	}
	v, err := ParseVersion(parts[1])
	if err != nil {
		return ClientInfo{}, err
	}
	return ClientInfo{Raw: s, Name: strings.ToLower(parts[0]), Version: v}, nil
}

// DB is a loaded vulnerability list.
type DB struct{ entries []Vulnerability }

// Load parses and validates a JSON list. Every entry must be well-formed;
// a malformed database is an error, never silently ignored.
func Load(data []byte) (*DB, error) {
	var list []Vulnerability
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("vulndb: %w", err)
	}
	seen := map[string]bool{}
	for i, e := range list {
		where := fmt.Sprintf("entry %d (%s)", i, e.ID)
		if e.ID == "" || seen[e.ID] {
			return nil, fmt.Errorf("vulndb: %s: missing or duplicate id", where)
		}
		seen[e.ID] = true
		if e.Client == "" || e.Client != strings.ToLower(e.Client) {
			return nil, fmt.Errorf("vulndb: %s: client must be non-empty lower-case", where)
		}
		intro, err := ParseVersion(e.Introduced)
		if err != nil {
			return nil, fmt.Errorf("vulndb: %s: introduced: %w", where, err)
		}
		fixed, err := ParseVersion(e.Fixed)
		if err != nil {
			return nil, fmt.Errorf("vulndb: %s: fixed: %w", where, err)
		}
		if intro.Compare(fixed) >= 0 {
			return nil, fmt.Errorf("vulndb: %s: introduced must be below fixed", where)
		}
		switch e.Severity {
		case "LOW", "MEDIUM", "HIGH", "CRITICAL":
		default:
			return nil, fmt.Errorf("vulndb: %s: bad severity %q", where, e.Severity)
		}
		if e.Source == "" || !strings.HasPrefix(e.Reference, "https://") || e.Summary == "" {
			return nil, fmt.Errorf("vulndb: %s: source, https reference and summary are required", where)
		}
	}
	return &DB{entries: list}, nil
}

var (
	defaultOnce sync.Once
	defaultDB   *DB
	defaultErr  error
)

// Default returns the embedded database.
func Default() (*DB, error) {
	defaultOnce.Do(func() { defaultDB, defaultErr = Load(dbBytes) })
	return defaultDB, defaultErr
}

// Entries returns a copy of all entries.
func (d *DB) Entries() []Vulnerability { return append([]Vulnerability(nil), d.entries...) }

// Clients lists the (lower-case) client names the database has data for.
func (d *DB) Clients() []string {
	set := map[string]bool{}
	for _, e := range d.entries {
		set[e.Client] = true
	}
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// Covers reports whether the database has any data for the client.
func (d *DB) Covers(client string) bool {
	for _, e := range d.entries {
		if e.Client == strings.ToLower(client) {
			return true
		}
	}
	return false
}

// Match returns the entries affecting the given client build, ordered as in
// the database.
func (d *DB) Match(c ClientInfo) []Vulnerability {
	var found []Vulnerability
	for _, e := range d.entries {
		if e.Client != c.Name {
			continue
		}
		intro, _ := ParseVersion(e.Introduced) // validated in Load
		fixed, _ := ParseVersion(e.Fixed)
		if c.Version.Compare(intro) >= 0 && c.Version.Compare(fixed) < 0 {
			found = append(found, e)
		}
	}
	return found
}
