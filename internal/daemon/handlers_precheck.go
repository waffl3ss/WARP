package daemon

import (
	"context"
	"encoding/json"

	"github.com/waffl3ss/warp/internal/audit"
	"github.com/waffl3ss/warp/internal/precheck"
	"github.com/waffl3ss/warp/internal/rpc"
)

// Host-environment checks, surfaced live on the radios tab.
//
// The same checks `warp precheck` runs before startup - rfkill blocks, NetworkManager and
// wpa_supplicant fighting for the interfaces - but reachable while the daemon is running, because
// the thing that reclaims a card into managed mode mid-capture is exactly what needs catching then.
// Read-only to list; the fix is an explicit, operator-driven host change, one at a time.

// PrecheckView is one host check for the frontends.
type PrecheckView struct {
	Name    string `json:"name"`
	Level   string `json:"level"`
	Detail  string `json:"detail"`
	Fix     string `json:"fix,omitempty"`
	Fixable bool   `json:"fixable"`
}

func precheckViews(checks []precheck.Check) []PrecheckView {
	out := make([]PrecheckView, len(checks))
	for i := range checks {
		out[i] = PrecheckView{
			Name:    checks[i].Name,
			Level:   checks[i].Level.String(),
			Detail:  checks[i].Detail,
			Fix:     checks[i].Fix,
			Fixable: checks[i].Fixable(),
		}
	}
	return out
}

// handlePrecheckList runs the read-only host checks and returns their status.
func (d *Daemon) handlePrecheckList(ctx context.Context, _ json.RawMessage) (any, error) {
	return precheckViews(precheck.Run(ctx)), nil
}

// PrecheckFixParams names the check to fix.
type PrecheckFixParams struct {
	Name string `json:"name"`
}

// handlePrecheckFix applies one check's fix - unblock rfkill, set the Wi-Fi interfaces unmanaged,
// stop and mask a stray wpa_supplicant - then returns the refreshed status. One host change per
// call, on the operator's explicit say-so.
func (d *Daemon) handlePrecheckFix(ctx context.Context, params json.RawMessage) (any, error) {
	var p PrecheckFixParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "bad params: %v", err)
	}
	for _, c := range precheck.Run(ctx) {
		if c.Name != p.Name {
			continue
		}
		if !c.Fixable() {
			return nil, rpc.Errorf(rpc.CodeInvalidParams,
				"%q reports %s - there is nothing for WARP to change", p.Name, c.Level.String())
		}
		if err := c.Apply(ctx); err != nil {
			return nil, rpc.Errorf(rpc.CodeInternal, "applying the %q fix: %v", p.Name, err)
		}
		d.logEvent(audit.KindLifecycle, audit.OutcomeInfo, "precheck fix applied",
			map[string]any{"check": p.Name})
		return precheckViews(precheck.Run(ctx)), nil
	}
	return nil, rpc.Errorf(rpc.CodeNotFound, "no host check named %q", p.Name)
}
