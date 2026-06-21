package vulndb

import (
	_ "embed"
	"encoding/json"
	"strings"
)

//go:embed data.json
var dbBytes []byte

type Vulnerability struct {
	CVE       string   `json:"cve"`
	Client    string   `json:"client"`
	MaxVersion string  `json:"max_version"`
	Severity  string   `json:"severity"`
}

var database []Vulnerability

func init() {
	json.Unmarshal(dbBytes, &database)
}

func Check(versionString string) []Vulnerability {
	var found []Vulnerability
	parts := strings.Split(versionString, "/")
	if len(parts) < 2 {
		return nil
	}
	clientVer := parts[1]
	clientName := strings.Split(versionString, "/")[0]
	verNum := strings.Split(clientVer, "-")[0]
	for _, v := range database {
		if strings.EqualFold(v.Client, clientName) && compareVersion(verNum, v.MaxVersion) < 0 {
			found = append(found, v)
		}
	}
	return found
}

func compareVersion(a, b string) int {
	a = strings.TrimPrefix(a, "v")
	b = strings.TrimPrefix(b, "v")
	if a < b {
		return -1
	} else if a > b {
		return 1
	}
	return 0
}
