package advisory

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLookupParsesNVDAdvisories(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"vulnerabilities":[{"cve":{"id":"CVE-2099-0001","descriptions":[{"lang":"en","value":"Test advisory"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL"}}]}}}]}`))
	}))
	defer server.Close()
	result, err := (Client{BaseURL: server.URL}).Lookup(context.Background(), "http", "1.2.3")
	if err != nil || len(result) != 1 || result[0].ID != "CVE-2099-0001" || result[0].CVSS != 9.8 {
		t.Fatalf("Lookup() = %+v, %v", result, err)
	}
}
