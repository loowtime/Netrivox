package profiles

import "testing"

func TestGetProfiles(t *testing.T) {
	quick, err := Get("quick")
	if err != nil {
		t.Fatal(err)
	}
	if quick.Ports != "80,443,8080" || quick.Banner {
		t.Fatalf("unexpected quick profile: %+v", quick)
	}
	deep, err := Get("deep")
	if err != nil {
		t.Fatal(err)
	}
	if deep.Ports != "1-1024" || !deep.Banner || !deep.Advisories {
		t.Fatalf("unexpected deep profile: %+v", deep)
	}
}
