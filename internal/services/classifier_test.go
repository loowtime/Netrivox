package services

import "testing"

func TestLookupClassifiesKnownAndUnknownPorts(t *testing.T) {
	if got := Lookup(443); got.Name != "https" || got.Category != "web" {
		t.Fatalf("Lookup(443) = %+v", got)
	}
	if got := Lookup(49152); got.Name != "unknown" || got.Category != "unknown" {
		t.Fatalf("Lookup(49152) = %+v", got)
	}
}
