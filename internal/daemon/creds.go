package daemon

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/waffl3ss/warp/internal/workspace"
)

// CredentialsFile is a single human-readable summary of everything recovered, rewritten wholesale
// whenever a credential is taken and on startup. It exists so the deliverable is legible at a glance
// and reachable after the live log has scrolled away - the authoritative machine files
// (wps-keys.txt, mschapv2.5500, the 22000s) are still the ones a cracking rig consumes.
const CredentialsFile = "credentials.txt"

// writeCredentialsFile regenerates creds/credentials.txt from everything recovered so far. It is
// overwritten each time rather than appended, so a restart leaves a clean current snapshot rather
// than an accumulating one, and it is safe to call often.
func (d *Daemon) writeCredentialsFile() {
	// Snapshot each source under its own lock, then format outside the locks.
	d.wpsMu.Lock()
	wps := append([]WPSCredential(nil), d.wpsKeys...)
	d.wpsMu.Unlock()

	d.eap.mu.RLock()
	var eap []struct{ essid, inner, secret string }
	for _, o := range d.eap.captured {
		secret := o.HashLine
		if o.Cleartext != "" {
			secret = "CLEARTEXT " + o.Cleartext
		}
		eap = append(eap, struct{ essid, inner, secret string }{o.ESSID, o.InnerIdentity, secret})
	}
	d.eap.mu.RUnlock()

	var b strings.Builder
	fmt.Fprintf(&b, "# WARP recovered credentials - regenerated %s\n",
		time.Now().UTC().Format(time.RFC3339))
	b.WriteString("# Authoritative machine files: creds/wps-keys.txt, creds/mschapv2.5500,\n")
	b.WriteString("# pmkid.22000, handshakes.22000. This file is a human-readable summary.\n\n")

	b.WriteString("## WPS (Pixie Dust)\n")
	if len(wps) == 0 {
		b.WriteString("  none recovered\n")
	} else {
		for _, c := range wps {
			pass := c.PSK
			if pass == "" {
				pass = "(PIN only, passphrase not read)"
			}
			fmt.Fprintf(&b, "  %-32s  %s  PIN %s  %s\n",
				valueOr(c.ESSID, "(hidden)"), c.BSSID, c.PIN, pass)
		}
	}

	b.WriteString("\n## Enterprise (MSCHAPv2, hashcat -m 5500)\n")
	if len(eap) == 0 {
		b.WriteString("  none captured this run (see creds/mschapv2.5500 for earlier runs)\n")
	} else {
		for _, e := range eap {
			fmt.Fprintf(&b, "  %-32s  %-24s  %s\n",
				valueOr(e.essid, "(unknown)"), valueOr(e.inner, "(no identity)"), e.secret)
		}
	}

	path := d.ws.Path(workspace.CredsDir, CredentialsFile)
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		d.log.Warn("could not write the credentials summary", "err", err, "path", path)
	}
}

func valueOr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
