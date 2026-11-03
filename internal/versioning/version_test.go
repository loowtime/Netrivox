package versioning

import "testing"

func TestDetectVersionFromBanner(t *testing.T) {
	version, confidence, evidence := Detect("openssh", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")
	if version != "8.9p1" || confidence != "high" || evidence == "" {
		t.Fatalf("Detect() = %q, %q, %q", version, confidence, evidence)
	}
}
