package cli

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/waffl3ss/warp/internal/daemon"
	"github.com/waffl3ss/warp/internal/eap/certs"
)

// eapCmd drives enterprise credential capture.
//
// One command group for what is really three things started together - an access point
// beaconing a scoped ESSID, WARP's RADIUS server behind it, and the EAP method server inside
// that - because none of them is useful alone and starting them separately would just be a
// way to get the combination wrong.
func eapCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "eap",
		Aliases: []string{"enterprise"},
		Short:   "Enterprise credential capture (WPA-Enterprise / 802.1X)",
		Long: `Impersonates a scoped enterprise network and captures what supplicants send it.

hostapd beacons the ESSID and relays every EAP message untouched to WARP's own RADIUS server
on localhost, which runs the PEAP state machine and records what each supplicant was willing
to negotiate. Captured MSCHAPv2 exchanges are written as hashcat -m 5500 lines into creds/.

The ESSID must be in scope. Beaconing a name the SoW never covered impersonates someone
else's network, and the gate refuses it - there is no flag that turns that off.

What this finds is a client-side misconfiguration: a supplicant that does not validate the
RADIUS server's certificate will hand its credentials to anything claiming the right name.
A supplicant that validates properly will refuse, and that refusal is the correct outcome.`,
	}

	var (
		channel      int
		noGTC        bool
		accept       bool
		keepOwnBSSID bool
		bssid        string
	)

	start := &cobra.Command{
		Use:   "start <essid>",
		Short: "Beacon a scoped ESSID and capture enterprise credentials",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			params := daemon.EAPStartParams{
				ESSID:        args[0],
				Channel:      channel,
				Accept:       accept,
				KeepOwnBSSID: keepOwnBSSID,
				BSSID:        bssid,
			}
			// GTC downgrade is automatic; --no-gtc opts out. Leaving the field nil means auto-on.
			if noGTC {
				off := false
				params.AllowGTCDowngrade = &off
			}
			return callAndRender(cmd, "eap.start", params,
				func(w io.Writer, r map[string]any) error {
					fprintf(w, "[+] impersonating %q\n", args[0])
					fprintf(w, "\nWatch for supplicants with `warp eap status`, or the "+
						"Enterprise tab in either interface.\n")
					if accept {
						fprintf(w, "\n--accept is on: a supplicant that authenticates will be "+
							"placed on this\naccess point rather than seeing a failed login.\n")
					}
					return nil
				})
		},
	}
	start.Flags().IntVar(&channel, "channel", 0,
		"channel to beacon on (default: the observed network's own channel)")
	start.Flags().BoolVar(&noGTC, "no-gtc", false,
		"do NOT offer EAP-GTC on an MSCHAPv2 Nak. GTC is offered automatically by default - it "+
			"yields a cleartext password with no cracking step, and a supplicant that refuses it "+
			"simply falls through to the MSCHAPv2 challenge WARP captures anyway")
	start.Flags().BoolVar(&accept, "accept", false,
		"return Access-Accept after capture instead of Access-Reject (hostile-portal work); "+
			"off by default so the supplicant simply sees a failed login")
	start.Flags().BoolVar(&keepOwnBSSID, "keep-own-bssid", false,
		"beacon from the adapter's own MAC instead of cloning the target's BSSID - use with a "+
			"different channel and a deauth of the real AP, so a client lands on the rogue rather "+
			"than the (often stronger) real access point sharing its BSSID")
	start.Flags().StringVar(&bssid, "bssid", "",
		"when several access points broadcast the ESSID, wear this specific observed BSSID instead "+
			"of the strongest. Must be one WARP has seen broadcasting the scoped name - an address "+
			"it has not observed for that ESSID is refused (discovered, never configured)")

	stop := &cobra.Command{
		Use:   "stop",
		Short: "Tear down the rogue access point and release the radio",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return callAndRender(cmd, "eap.stop", nil, func(w io.Writer, r map[string]any) error {
				fprintf(w, "stopped\n")
				return nil
			})
		},
	}

	status := &cobra.Command{
		Use:   "status",
		Short: "Show the running capture, associated clients and what has been taken",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return callAndRender(cmd, "eap.status", nil, renderEAPStatus)
		},
	}

	var harvestSeconds int
	harvest := &cobra.Command{
		Use:     "harvest <bssid>",
		Aliases: []string{"clone"},
		Short:   "Read the RADIUS server's certificate off the air, for the rogue to mimic",
		Long: `Harvest the certificate a scoped enterprise network's RADIUS server presents.

This is the step that makes the evil twin worth running. A self-signed certificate carrying
none of the target's naming is refused by every client that shows the user anything, so the
rogue has to present one that mirrors the real thing - subject, issuer, SANs, validity, key
algorithm, serial. All of that is in the certificate the server hands out, and it hands it out
to anyone who starts a connection, because it presents it before it knows who is asking.

WARP associates to the access point itself and runs its own EAP-TLS client over the association -
what wpa_supplicant does by hand, minus the passphrase. The association is real and kernel-driven,
so the card acknowledges the access point the way any client does; WARP answers the identity
request and starts TLS, the server sends its certificate in the clear before it knows who is
asking, and the exchange is abandoned the moment it arrives. WARP has no credentials and needs
none - nothing authenticates.

It is the same bytes you would dig out of a pcap by hand (` + "`tls.handshake.type == 11`" + `).
This just does it in one command, which is the difference between doing it and shipping a
self-signed certificate instead.

The harvest is saved to certs/<essid>/ and reused automatically the next time
` + "`warp eap start`" + ` runs.

The certificate the rogue then presents is deliberately not an exact copy: its common name
carries a trailing space. That changes no visible glyph at a trust prompt, so click-through -
the thing being measured - is unaffected, while the artefact in the engagement directory is
provably not the client's own certificate.

Refused unless the access point broadcasts a scoped ESSID: associating to it is transmission.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return callAndRender(cmd, "harvest",
				daemon.HarvestParams{BSSID: args[0], Seconds: harvestSeconds}, renderJobStart)
		},
	}
	harvest.Flags().IntVar(&harvestSeconds, "seconds", 0,
		"how long the exchange may take, in seconds (default 20, capped at 60)")

	cmd.AddCommand(start, stop, status, harvest, certCmd())
	return cmd
}

// certCmd manages the engagement's certificate library.
func certCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "cert",
		Aliases: []string{"certs", "certificate"},
		Short:   "Manage the certificates the rogue access point can present",
		Long: `The certificate is the pretext.

A supplicant deciding whether to hand over its credentials is, in almost every real case,
deciding whether the certificate looks like the one it expects - by validating a chain, or by
showing a human a name and a prompt. A self-signed certificate carrying none of the target's
naming loses that decision every time against any client that shows the user anything.

Four ways one gets into the library, strongest first:

  mimic        built from a certificate harvested off the air (warp eap harvest)
  imported     a certificate and key produced elsewhere
  generated    built from fields you type (warp eap cert generate)
  self-signed  from the ESSID alone - the fallback, and the weakest

Whichever is selected goes on the air, and the selection is engagement state: it survives a
daemon restart and appears in the report. A new certificate is selected automatically when it
is at least as convincing as the one selected now.`,
	}

	list := &cobra.Command{
		Use:   "list [essid]",
		Short: "List the certificates available for each scoped network",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var p daemon.CertsListParams
			if len(args) == 1 {
				p.ESSID = args[0]
			}
			return callAndRender(cmd, "certs.list", p, renderCertList)
		},
	}

	var f certs.Fields
	var dnsNames, ipAddrs []string

	generate := &cobra.Command{
		Use:   "generate <essid>",
		Short: "Build a certificate from fields you supply",
		Long: `Build a certificate for a scoped network from fields you supply.

For when the target cannot be harvested - out of range, not yet observed, or an engagement
that starts before the site visit - but the naming is known from a scoping call or a previous
report.

The fields are used verbatim. Unlike a mimic, which always carries a distinguishing mark
because it is a copy of somebody's real certificate, this is what you typed, and it is used
exactly as typed. What the subject will be is printed back before anything goes near the air.

Only --common-name is required. --issuer-common-name matters nearly as much: most clients that
prompt a human display the issuing authority, and a certificate issued by an authority with its
own name reads as self-signed in every viewer.

  warp eap cert generate ACME-CORP \
      --common-name radius.acme-corp.internal \
      --organization "ACME Corporation" \
      --organizational-unit "IT Infrastructure" \
      --country US \
      --issuer-common-name "ACME Corporate Issuing CA" \
      --issuer-organization "ACME Corporation" \
      --dns radius.acme-corp.internal --dns radius2.acme-corp.internal`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f.DNSNames = dnsNames
			f.IPAddresses = ipAddrs
			return callAndRender(cmd, "certs.generate",
				daemon.CertGenerateParams{ESSID: args[0], Fields: f}, renderCertEntry)
		},
	}
	generate.Flags().StringVar(&f.CommonName, "common-name", "",
		"what a trust prompt shows - a hostname like radius.acme-corp.internal, or a "+
			"descriptive name (required)")
	generate.Flags().StringVar(&f.Organization, "organization", "", "O")
	generate.Flags().StringVar(&f.OrganizationalUnit, "organizational-unit", "", "OU")
	generate.Flags().StringVar(&f.Country, "country", "", "C, two letters")
	generate.Flags().StringVar(&f.Province, "state", "", "ST")
	generate.Flags().StringVar(&f.Locality, "locality", "", "L")
	generate.Flags().StringVar(&f.Email, "email", "", "emailAddress in the subject (eaphammer prompts for it)")
	generate.Flags().StringVar(&f.IssuerCommonName, "issuer-common-name", "",
		"the issuing authority a client displays (default: \"<common name> Issuing CA\")")
	generate.Flags().StringVar(&f.IssuerOrganization, "issuer-organization", "",
		"the issuing authority's organisation (default: the subject's)")
	generate.Flags().StringSliceVar(&dnsNames, "dns", nil,
		"subject alternative name; repeatable. A supplicant with domain_suffix_match set "+
			"checks these and nothing else")
	generate.Flags().StringSliceVar(&ipAddrs, "ip", nil, "IP subject alternative name; repeatable")
	generate.Flags().IntVar(&f.ValidityDays, "days", 0,
		"validity in days (default 825, the longest a public CA may issue for)")
	generate.Flags().IntVar(&f.KeyBits, "key-bits", 0, "RSA modulus size (default 2048)")
	generate.Flags().StringVar(&f.Note, "note", "", "recorded with the certificate")

	var imp daemon.CertImportParams
	importCmd := &cobra.Command{
		Use:   "import <essid>",
		Short: "Import a certificate and key produced elsewhere",
		Long: `Import a certificate and private key made outside WARP.

For a chain you prepared in advance, or one the client's own CA issued for the test - which is
the strongest pretext there is, because a supplicant validating against that CA accepts it.

The pair is validated before anything is written: a certificate whose key does not match would
otherwise surface as the rogue refusing to start, halfway through an engagement.

Any certificates after the leaf in --cert are treated as the chain and presented with it.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			imp.ESSID = args[0]
			return callAndRender(cmd, "certs.import", imp, renderCertEntry)
		},
	}
	importCmd.Flags().StringVar(&imp.CertPath, "cert", "", "path to the certificate PEM (required)")
	importCmd.Flags().StringVar(&imp.KeyPath, "key", "", "path to the private key PEM (required)")
	importCmd.Flags().StringVar(&imp.Note, "note", "", "recorded with the certificate")

	selectCmd := &cobra.Command{
		Use:     "select <essid> <id>",
		Aliases: []string{"use"},
		Short:   "Choose which certificate the rogue presents",
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return callAndRender(cmd, "certs.select",
				daemon.CertSelectParams{ESSID: args[0], ID: args[1]},
				func(w io.Writer, r certSelectResult) error {
					fprintf(w, "selected %s\n", r.Certificate.ID)
					fprintf(w, "  %s\n", r.Certificate.Subject)
					fprintf(w, "  issued by %s\n", r.Certificate.Issuer)
					fprintf(w, "  %s\n\n", r.Certificate.SourceDetail)
					fprintf(w, "%s\n", r.Note)
					return nil
				})
		},
	}

	deleteCmd := &cobra.Command{
		Use:   "delete <essid> <id>",
		Short: "Remove a certificate from the library",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return callAndRender(cmd, "certs.delete",
				daemon.CertDeleteParams{ESSID: args[0], ID: args[1]},
				func(w io.Writer, r map[string]string) error {
					fprintf(w, "deleted %s\n", r["deleted"])
					return nil
				})
		},
	}

	cmd.AddCommand(list, generate, importCmd, selectCmd, deleteCmd)
	return cmd
}

type certSelectResult struct {
	Certificate     certs.Entry `json:"certificate"`
	RestartRequired bool        `json:"restart_required"`
	Note            string      `json:"note"`
}

func renderCertList(w io.Writer, r daemon.CertsListResult) error {
	if len(r.Networks) == 0 {
		fprintf(w, "no scoped networks\n")
		return nil
	}

	names := make([]string, 0, len(r.Networks))
	for n := range r.Networks {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, name := range names {
		list := r.Networks[name]
		fprintf(w, "%s\n", name)
		if len(list) == 0 {
			// Worth stating rather than leaving blank: it is the answer to "why did the rogue
			// present a self-signed certificate".
			fprintf(w, "  nothing prepared - the rogue would generate a self-signed certificate\n")
			fprintf(w, "  warp eap harvest <bssid>   or   warp eap cert generate %s --common-name ...\n\n", name)
			continue
		}
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  \tID\tSOURCE\tSUBJECT\tEXPIRES")
		for _, e := range list {
			mark := " "
			if e.Selected {
				mark = "*"
			}
			expires := e.NotAfter.Format("2006-01-02")
			if e.Expired {
				expires += " EXPIRED"
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n",
				mark, e.ID, e.Source, e.Subject, expires)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
		fprintf(w, "\n")
	}
	fprintf(w, "* is the one the rogue will present.  %s\n", r.Directory)
	return nil
}

func renderCertEntry(w io.Writer, e certs.Entry) error {
	fprintf(w, "%s  %s\n\n", e.ID, e.SourceDetail)
	fprintf(w, "  subject     %s\n", e.Subject)
	fprintf(w, "  issuer      %s\n", e.Issuer)
	if len(e.SANs) > 0 {
		fprintf(w, "  sans        %s\n", strings.Join(e.SANs, ", "))
	}
	fprintf(w, "  valid       %s → %s\n",
		e.NotBefore.Format("2006-01-02"), e.NotAfter.Format("2006-01-02"))
	fprintf(w, "  key         %s-%d\n", e.KeyAlgorithm, e.KeyBits)
	fprintf(w, "  sha256      %s\n", e.Fingerprint)
	fprintf(w, "  files       %s\n", e.CertPath)
	if e.Selected {
		fprintf(w, "\nSelected - this is what the rogue will present.\n")
	} else {
		fprintf(w, "\nNot selected. Use it with:  warp eap cert select %s %s\n", e.ESSID, e.ID)
	}
	return nil
}

func renderEAPStatus(w io.Writer, s daemon.EAPStatus) error {
	if !s.Running {
		fprintf(w, "no enterprise capture running\n")
		if len(s.Captured) == 0 {
			fprintf(w, "\n  warp eap start <essid>\n")
			return nil
		}
	} else {
		fprintf(w, "impersonating %q on ch%d (%s)\n",
			s.Session.ESSID, s.Session.Channel, s.Session.Ifname)
		fprintf(w, "certificate: %s\n", s.Session.CertSource)
		fprintf(w, "fingerprint: %s\n", s.Session.Fingerprint)

		fprintf(w, "\nRADIUS: %d requests, %d challenges, %d captured",
			s.Stats.Requests, s.Stats.Challenges, s.Stats.Captured)
		if s.Stats.CertRefused > 0 {
			// The correct client behaviour, and worth stating plainly so it is not mistaken
			// for a fault in the tool.
			fprintf(w, ", %d refused the certificate", s.Stats.CertRefused)
		}
		fprintf(w, "\n")

		if len(s.Clients) > 0 {
			fprintf(w, "\nassociated:\n")
			for _, c := range s.Clients {
				fprintf(w, "  %s  since %s\n", c.MAC, c.Since.Format("15:04:05"))
			}
		}
	}

	if len(s.Captured) == 0 {
		if s.Running {
			fprintf(w, "\nnothing captured yet - a supplicant has to try to join.\n")
		}
		return nil
	}

	fprintf(w, "\ncaptured:\n")
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "IDENTITY\tOUTER\tMETHOD\tCLIENT\tRESULT")
	for _, o := range s.Captured {
		result := "no credential"
		switch {
		case o.Cleartext != "":
			result = "CLEARTEXT PASSWORD"
		case o.HashLine != "":
			result = "MSCHAPv2 (-m 5500)"
		}
		inner, outer := o.InnerIdentity, o.OuterIdentity
		if inner == "" {
			inner = "-"
		}
		if outer == "" {
			outer = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			inner, outer, o.Method, orDash(o.CallingStation), result)
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	fprintf(w, "\nWARP does not crack. Transfer to the cracking rig:\n  %s\n", s.CredsFile)
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
