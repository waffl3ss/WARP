package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/waffl3ss/warp/internal/audit"
	"github.com/waffl3ss/warp/internal/eap/certs"
	"github.com/waffl3ss/warp/internal/recon"
	"github.com/waffl3ss/warp/internal/rpc"
)

// The certificate library.
//
// The certificate is the pretext, and until now it was whatever the code happened to have:
// a mimic if a harvest had run, a self-signed one otherwise, decided at the moment the rogue
// started and invisible until afterwards. That is the wrong shape for the thing the whole
// enterprise module turns on.
//
// So it is a library the operator manages: list what is available, generate one from typed
// fields, import one made elsewhere, choose which goes on the air. Every frontend reaches all
// of it.

// CertsListParams filters the library.
type CertsListParams struct {
	// ESSID limits the listing to one network. Empty lists every network the library holds.
	ESSID string `json:"essid,omitempty"`
}

// CertsListResult is the library as a frontend shows it.
type CertsListResult struct {
	// Networks maps ESSID to the certificates filed for it, strongest first.
	Networks map[string][]certs.Entry `json:"networks"`
	// Directory is where they live, for an operator who wants the files.
	Directory string `json:"directory"`
}

func (d *Daemon) handleCertsList(_ context.Context, params json.RawMessage) (any, error) {
	var p CertsListParams
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, rpc.Errorf(rpc.CodeInvalidParams, "bad params: %v", err)
		}
	}

	lib := d.certs()
	out := CertsListResult{
		Networks:  map[string][]certs.Entry{},
		Directory: d.ws.Path("certs"),
	}

	names := []string{p.ESSID}
	if p.ESSID == "" {
		// Scoped networks that were actually *observed running WPA-Enterprise*, plus anything
		// the library already holds.
		//
		// Not every scoped name: a certificate is only ever presented by the rogue's RADIUS
		// server, so listing the PSK networks alongside was offering to prepare something
		// that could never be used, and burying the two networks that matter among a dozen
		// that do not. A scoped enterprise network with nothing prepared is still listed
		// empty on purpose - "nothing prepared for this one" is the answer as often as not.
		names = d.enterpriseESSIDs()
		if dirs, err := os.ReadDir(d.ws.Path("certs")); err == nil {
			for _, dir := range dirs {
				if dir.IsDir() {
					names = append(names, dir.Name())
				}
			}
		}
	}

	seen := map[string]bool{}
	for _, name := range names {
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		list, err := lib.List(name)
		if err != nil {
			return nil, err
		}
		out.Networks[name] = list
	}
	return out, nil
}

// enterpriseESSIDs names the scoped networks observed running WPA-Enterprise.
//
// Observed, not merely scoped: the certificate is presented by a RADIUS server, and a network
// that does not run 802.1X has no use for one. The directory names in certs/ are unioned in by
// the caller, so a network that was enterprise yesterday and is out of range today does not
// lose its library.
func (d *Daemon) enterpriseESSIDs() []string {
	seen := map[string]bool{}
	var out []string

	for _, ap := range d.engine.Tracker().APs() {
		if ap.ESSID == "" || seen[ap.ESSID] {
			continue
		}
		switch ap.Security.Class {
		case recon.SecWPAEnterprise, recon.SecWPA3Ent192:
		default:
			continue
		}
		if _, _, ok := d.ws.Scope.Match(ap.ESSID); !ok {
			continue
		}
		seen[ap.ESSID] = true
		out = append(out, ap.ESSID)
	}
	return out
}

// CertGenerateParams is the certificate wizard's input.
type CertGenerateParams struct {
	ESSID string `json:"essid"`
	certs.Fields
}

func (d *Daemon) handleCertGenerate(ctx context.Context, params json.RawMessage) (any, error) {
	var p CertGenerateParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "bad params: %v", err)
	}
	if err := d.checkCertESSID(p.ESSID); err != nil {
		return nil, err
	}
	if strings.TrimSpace(p.CommonName) == "" {
		return nil, rpc.Errorf(rpc.CodeInvalidParams,
			"a common name is required - it is what a supplicant's trust prompt shows, and a "+
				"certificate without a plausible one is refused before anyone reads the rest")
	}

	entry, err := d.certs().Generate(p.ESSID, p.Fields)
	if err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "%v", err)
	}

	d.logCertEvent("certificate generated from operator-supplied fields", p.ESSID, entry)
	return entry, nil
}

// CertImportParams brings in a certificate made elsewhere.
type CertImportParams struct {
	ESSID string `json:"essid"`
	// CertPEM and KeyPEM are the PEM blocks themselves, so a browser can paste them.
	CertPEM string `json:"cert_pem,omitempty"`
	KeyPEM  string `json:"key_pem,omitempty"`
	// CertPath and KeyPath read from the engagement box's filesystem instead, for a console
	// operator who already has the files there.
	CertPath string `json:"cert_path,omitempty"`
	KeyPath  string `json:"key_path,omitempty"`
	Note     string `json:"note,omitempty"`
}

func (d *Daemon) handleCertImport(ctx context.Context, params json.RawMessage) (any, error) {
	var p CertImportParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "bad params: %v", err)
	}
	if err := d.checkCertESSID(p.ESSID); err != nil {
		return nil, err
	}

	certPEM, err := pemFrom(p.CertPEM, p.CertPath, "certificate")
	if err != nil {
		return nil, err
	}
	keyPEM, err := pemFrom(p.KeyPEM, p.KeyPath, "private key")
	if err != nil {
		return nil, err
	}

	entry, err := d.certs().Import(p.ESSID, p.Note, certPEM, keyPEM)
	if err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "%v", err)
	}

	d.logCertEvent("certificate imported", p.ESSID, entry)
	return entry, nil
}

// pemFrom takes the inline body or reads the named file.
func pemFrom(inline, path, what string) ([]byte, error) {
	if strings.TrimSpace(inline) != "" {
		return []byte(inline), nil
	}
	if path == "" {
		return nil, rpc.Errorf(rpc.CodeInvalidParams,
			"no %s given: supply it inline or name a file on the engagement box", what)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "read %s: %v", what, err)
	}
	return body, nil
}

// CertSelectParams chooses which certificate goes on the air.
type CertSelectParams struct {
	ESSID string `json:"essid"`
	ID    string `json:"id"`
}

func (d *Daemon) handleCertSelect(ctx context.Context, params json.RawMessage) (any, error) {
	var p CertSelectParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "bad params: %v", err)
	}

	entry, err := d.certs().Select(p.ESSID, p.ID)
	if err != nil {
		return nil, rpc.Errorf(rpc.CodeNotFound, "%v", err)
	}

	// A running rogue keeps the certificate it started with - TLS sessions are already in
	// flight - so say so rather than letting the operator believe the swap took effect.
	d.eap.mu.RLock()
	running := d.eap.session != nil && d.eap.session.ESSID == p.ESSID
	d.eap.mu.RUnlock()

	d.logCertEvent("certificate selected for the rogue access point", p.ESSID, entry)

	return map[string]any{
		"certificate":      entry,
		"restart_required": running,
		"note": map[bool]string{
			true:  "the rogue is running and keeps the certificate it started with - restart it to present this one",
			false: "the rogue will present this certificate the next time it starts",
		}[running],
	}, nil
}

// CertDeleteParams removes one from the library.
type CertDeleteParams struct {
	ESSID string `json:"essid"`
	ID    string `json:"id"`
}

func (d *Daemon) handleCertDelete(ctx context.Context, params json.RawMessage) (any, error) {
	var p CertDeleteParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "bad params: %v", err)
	}
	if err := d.certs().Delete(p.ESSID, p.ID); err != nil {
		return nil, rpc.Errorf(rpc.CodeNotFound, "%v", err)
	}
	d.logEvent(audit.KindHarvest, audit.OutcomeInfo, "certificate removed from the library",
		map[string]any{"essid": p.ESSID, "certificate_id": p.ID})
	return map[string]any{"deleted": p.ID, "essid": p.ESSID}, nil
}

// checkCertESSID refuses to prepare a certificate for a network the engagement cannot beacon.
//
// Not a scope decision - nothing transmits here, and preparing a certificate is not an attack.
// It is a guard against wasted work: a certificate for an unscoped name can never go on the
// air, and finding that out at `eap start` is finding it out too late.
func (d *Daemon) checkCertESSID(essid string) error {
	if strings.TrimSpace(essid) == "" {
		return rpc.Errorf(rpc.CodeInvalidParams,
			"an ESSID is required: certificates are filed per network")
	}
	if _, _, ok := d.ws.Scope.Match(essid); !ok {
		return rpc.Errorf(rpc.CodeScopeDenied,
			"%q is not in scope, so the rogue access point could never beacon it and this "+
				"certificate could never be used. Add it to scope first if the SoW covers it",
			essid)
	}
	return nil
}

// CertsListResult and the wizard are the same surface in every frontend; nothing here is
// browser-only or console-only.

func (d *Daemon) logCertEvent(reason, essid string, e certs.Entry) {
	d.logEvent(audit.KindHarvest, audit.OutcomeInfo, reason, map[string]any{
		"essid":          essid,
		"certificate_id": e.ID,
		"source":         string(e.Source),
		"subject":        e.Subject,
		"issuer":         e.Issuer,
		"fingerprint":    e.Fingerprint,
		"selected":       e.Selected,
	})
	d.Broadcast(rpc.Event{
		Kind: "certs", Level: rpc.LevelGood,
		Text: fmt.Sprintf("[+] %s for %s - %s", reason, essid, e.Subject),
		Fields: map[string]any{
			"essid": essid, "certificate_id": e.ID, "source": string(e.Source),
		},
	})
}
