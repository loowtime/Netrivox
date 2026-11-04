package profiles

import "fmt"

type Profile struct {
	Name       string
	Ports      string
	ProbePort  int
	Banner     bool
	TLS        bool
	HTTP       bool
	Advisories bool
}

var catalog = map[string]Profile{
	"quick": {
		Name: "quick", Ports: "80,443,8080", ProbePort: 443,
	},
	"standard": {
		Name: "standard", Ports: "22,80,443,8080", ProbePort: 443,
		TLS: true, HTTP: true,
	},
	"deep": {
		Name: "deep", Ports: "1-1024", ProbePort: 443,
		Banner: true, TLS: true, HTTP: true, Advisories: true,
	},
}

func Get(name string) (Profile, error) {
	profile, ok := catalog[name]
	if !ok {
		return Profile{}, fmt.Errorf("unknown scan profile %q; choose quick, standard, or deep", name)
	}
	return profile, nil
}

func Names() []string {
	return []string{"quick", "standard", "deep"}
}
