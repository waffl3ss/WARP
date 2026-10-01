package recon

import (
	"encoding/json"
	"testing"
)

func TestMFPRoundTrip(t *testing.T) {
	for _, m := range []MFPState{MFPAbsent, MFPCapable, MFPRequired, MFPUnknown} {
		b, _ := json.Marshal(m)
		var got MFPState
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatalf("unmarshal %s: %v", m, err)
		}
		if got != m {
			t.Errorf("round-trip %s -> %s", m, got)
		}
	}
}
