package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"os/user"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/waffl3ss/warp/internal/build"
	"github.com/waffl3ss/warp/internal/daemon"
	"github.com/waffl3ss/warp/internal/handshake"
	"github.com/waffl3ss/warp/internal/radio"
	"github.com/waffl3ss/warp/internal/radio/nl80211"
	"github.com/waffl3ss/warp/internal/scope"
	"github.com/waffl3ss/warp/internal/store"
	"github.com/waffl3ss/warp/internal/web"
	"github.com/waffl3ss/warp/internal/workspace"
)

// webAccessFile is where the web interface's URL, access token and listen address are written in the
// engagement directory each run, so they are retrievable without watching the console at startup.
const webAccessFile = "web-access.txt"

func initCmd() *cobra.Command {
	var (
		scopePath     string
		acknowledge   bool
		operator      string
		allNetworks   bool
		justification string
	)

	cmd := &cobra.Command{
		Use:   "init <dir>",
		Short: "Create an engagement directory from a client-supplied scope file",
		Long: `Creates an engagement directory and copies the client's scope.txt into it.

scope.txt is a newline-delimited list of ESSIDs and is the only scope input. Any BSSID
broadcasting one of those ESSIDs is authorized for active work; BSSIDs are discovered off
the air and are never configured.

Scoped ESSIDs that are common or vendor-default names (Guest, linksys, attwifi, ...) are
flagged: a neighbour can legitimately broadcast the same name, so active work there could
reach a device outside the engagement. Each one requires an explicit acknowledgment, which
is written to the audit log as engagement evidence.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := args[0]
			out := cmd.OutOrStdout()

			switch {
			case allNetworks && scopePath != "":
				return errors.New("--all-networks and --scope are mutually exclusive: either " +
					"the SoW names the networks or it covers the site")
			case allNetworks:
				if operator == "" {
					operator = currentOperator()
				}
				var err error
				justification, err = siteWideAuthorization(cmd, justification, operator)
				if err != nil {
					return err
				}
			case scopePath == "":
				return errors.New("--scope is required: the client's list of in-scope ESSIDs " +
					"(or --all-networks if the SoW covers every network at the site)")
			}

			ws, warns, err := workspace.InitSiteWide(dir, scopePath, justification)
			if err != nil {
				return err
			}
			defer ws.Close()

			fprintf(out, "engagement initialised at %s\n", dir)
			if ws.Scope.IsSiteWide() {
				fprintf(out, "scope: EVERY NAMED NETWORK AT THIS SITE\n")
				fprintf(out, "authority: %s\n", ws.Scope.SiteWideNote())
				fprintf(out, "\nready. start the daemon with:\n  warp daemon --workspace %s\n", dir)
				return nil
			}
			fprintf(out, "scope: %d ESSIDs\n", ws.Scope.Len())
			for _, e := range ws.Scope.List() {
				fprintf(out, "  %s\n", e)
			}

			for _, w := range warns {
				fprintf(out, "\nwarning: %s\n", w)
			}

			pending := ws.Gate.PendingAcknowledgments()
			if len(pending) == 0 {
				fprintf(out, "\nready. start the daemon with:\n  warp daemon --workspace %s\n", dir)
				return nil
			}

			if operator == "" {
				operator = currentOperator()
			}
			if err := acknowledgeGeneric(cmd, ws.Gate, pending, acknowledge, operator); err != nil {
				return err
			}

			fprintf(out, "\nready. start the daemon with:\n  warp daemon --workspace %s\n", dir)
			return nil
		},
	}

	cmd.Flags().StringVar(&scopePath, "scope", "", "path to the client-supplied scope.txt (required)")
	cmd.Flags().BoolVar(&acknowledge, "acknowledge-generic", false,
		"accept the residual risk of generic ESSIDs without prompting (for scripted setup)")
	cmd.Flags().StringVar(&operator, "operator", "", "name recorded against the acknowledgment (default: current user)")
	cmd.Flags().BoolVar(&allNetworks, "all-networks", false,
		"scope every named network at the site instead of a list - for an SoW written that way; "+
			"requires a written justification and transmits at networks nobody enumerated")
	cmd.Flags().StringVar(&justification, "justification", "",
		"written authority for --all-networks (SoW reference, client contact); prompted for if omitted")
	return cmd
}

// siteWideAuthorization collects and confirms the justification for a site-wide scope.
//
// A site-wide engagement removes the check that stops WARP transmitting at a network the SoW
// never named, so it is not something to be reached by a flag alone. The operator has to write
// down what authorises it, and that sentence then travels with every transmission in
// events.jsonl and appears on screen for the life of the engagement.
func siteWideAuthorization(cmd *cobra.Command, note, operator string) (string, error) {
	out := cmd.OutOrStdout()

	rule := strings.Repeat("!", 72)
	fprintf(out, "\n%s\n", rule)
	fprintf(out, "SITE-WIDE SCOPE\n\n")
	fprintf(out, "Every named network this adapter can hear becomes authorized for active work:\n")
	fprintf(out, "solicitation, deauthentication and rogue AP beaconing, at any ESSID.\n\n")
	fprintf(out, "WARP cannot tell the client's networks from a neighbour's. On a shared floor,\n")
	fprintf(out, "in a multi-tenant building, or anywhere with RF bleed past the demised space,\n")
	fprintf(out, "this will transmit at equipment belonging to someone who never signed anything.\n\n")
	fprintf(out, "Use it where the SoW covers a site rather than a list - a standalone warehouse,\n")
	fprintf(out, "a campus you control the airspace of - and not as a way around a scope file.\n")
	fprintf(out, "%s\n\n", rule)

	if note == "" {
		fprintf(out, "What authorises site-wide testing? (SoW reference, client contact, scope\n")
		fprintf(out, "language - recorded verbatim in the engagement evidence)\n> ")
		line, err := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
		if err != nil && line == "" {
			return "", fmt.Errorf("no justification given: %w", err)
		}
		note = strings.TrimSpace(line)
	}
	if note == "" {
		return "", errors.New("a site-wide scope requires a written justification; " +
			"pass --justification or answer the prompt")
	}

	note = fmt.Sprintf("%s (recorded by %s)", note, operator)

	if !confirmPrompt(cmd.InOrStdin(), out,
		"Authorize active work at EVERY named network this kit can hear? [y/N]: ") {
		return "", errors.New("site-wide scope declined - no engagement was created")
	}
	return note, nil
}

// acknowledgeGeneric surfaces the generic-ESSID risk and records a human's acceptance.
//
// The brief is specific here: do not silently proceed, and do not refuse. Surface the
// residual risk, require an explicit acknowledgment, and write it to the audit log.
//
// The acknowledgment is workspace state, not a runtime prompt. It is made once at init and
// replayed from events.jsonl thereafter, which is what lets a NUC shipped to a wiring closet
// do identical work with nobody present.
func acknowledgeGeneric(cmd *cobra.Command, gate *scope.Gate, pending []string, preAcked bool, operator string) error {
	out := cmd.OutOrStdout()

	rule := strings.Repeat("!", 72)
	fprintf(out, "\n%s\n", rule)
	fprintf(out, "GENERIC ESSIDs IN SCOPE\n\n")
	fprintf(out, "These scoped names are common or vendor defaults. A neighbouring business can\n")
	fprintf(out, "legitimately broadcast the same name, and active work at a matching BSSID would\n")
	fprintf(out, "then transmit at a device outside this engagement:\n\n")
	for _, e := range pending {
		fprintf(out, "    %q\n", e)
	}
	fprintf(out, "\nThis risk cannot be resolved from the air. Confirm with the client that these\n")
	fprintf(out, "names are theirs, or use `scope reject <bssid>` on site to exclude specific APs.\n")
	fprintf(out, "%s\n\n", rule)

	if !preAcked {
		if !confirmPrompt(cmd.InOrStdin(), out,
			fmt.Sprintf("Accept this risk for all %d ESSID(s) and record the acknowledgment? [y/N]: ", len(pending))) {
			return errors.New("acknowledgment declined - engagement not started (the directory and scope file were still created)")
		}
	}

	for _, e := range pending {
		if err := gate.AcknowledgeGeneric(e, operator); err != nil {
			return err
		}
		fprintf(out, "acknowledged %q (recorded as %s)\n", e, operator)
	}
	return nil
}

func confirmPrompt(in io.Reader, out io.Writer, prompt string) bool {
	fprintf(out, "%s", prompt)
	sc := bufio.NewScanner(in)
	if !sc.Scan() {
		return false
	}
	answer := strings.ToLower(strings.TrimSpace(sc.Text()))
	return answer == "y" || answer == "yes"
}

func currentOperator() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	if n := os.Getenv("SUDO_USER"); n != "" {
		return n
	}
	return "unknown"
}

func daemonCmd() *cobra.Command {
	var (
		wsDir             string
		radios            []string
		skipInjectionTest bool
		assumeInjection   bool
		resetRadios       bool
		regDomain         string

		webEnable      bool
		webListen      string
		webToken       string
		webNoTLS       bool
		webAllowRemote bool
		webURLFile     string
	)

	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Run warpd - owns the radios, the scheduler, the scope gate and all jobs",
		Long: `Runs the WARP daemon.

The daemon owns every radio and every running job, and survives client disconnect: the
operator will often be SSH'd into a box in a wiring closet, and a dropped session must not
end the engagement.

Requires CAP_NET_ADMIN (run as root) to reconfigure adapters. Enumeration alone does not.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if wsDir == "" {
				return errors.New("--workspace is required")
			}
			log := logger()

			ws, err := workspace.Open(wsDir)
			if err != nil {
				return err
			}
			defer ws.Close()

			// A generic ESSID with no recorded acknowledgment blocks active work at that
			// name. Say so at startup rather than letting it surface as a confusing refusal
			// hours later.
			if pending := ws.Gate.PendingAcknowledgments(); len(pending) > 0 {
				fprintf(cmd.ErrOrStderr(),
					"warning: %d generic ESSID(s) have no recorded acknowledgment and are excluded from active work: %s\n"+
						"         run `warp init` against this directory, or acknowledge them before relying on results.\n",
					len(pending), strings.Join(pending, ", "))
			}

			// A clean-slate USB reset before enumeration recovers adapters that wedged in a
			// previous session (mt76 and other USB parts stop delivering frames after heavy
			// mode-cycling). It re-creates the phy, so it must happen before Discover reads the
			// phys - doing it here means every fresh daemon start begins with un-wedged cards.
			if resetRadios {
				resetWirelessUSB(cmd.Context(), cmd.ErrOrStderr(), radios)
			}

			// Set the regulatory domain before enumerating, so the phys come back with the upper
			// bands transmit-usable rather than NoIR under the world default. Only fills in the
			// unset default - a domain the system already set is left alone. Best-effort: a failure
			// here (no privileges, kernel without CRDA) just leaves the bands as the kernel had them.
			if reg, err := radio.EnsureRegDomain(regDomain); err != nil {
				log.Warn("could not set the default regulatory domain", "err", err, "requested", regDomain)
			} else {
				log.Info("regulatory domain", "cc", reg)
			}

			disc, err := radio.Discover(cmd.Context(), radio.DiscoverOptions{
				Only:           radios,
				RequireMonitor: true,
			})
			if err != nil {
				return err
			}
			for _, ex := range disc.Excluded {
				log.Warn("adapter excluded", "radio_id", ex.ID, "ifname", ex.Ifname, "reason", ex.Reason)
			}

			acquirer := radio.NewAcquirer(log)
			defer acquirer.Close()

			// Injection is demonstrated, never assumed: the capability bitmap lies on several
			// common chipsets, and the scheduler refuses transmitting roles on any adapter
			// that has not been shown to inject. This takes a couple of seconds per adapter.
			if assumeInjection {
				radio.AssumeInjection(disc.Devices,
					"asserted with --assume-injection; not demonstrated by WARP")
				log.Warn("injection assumed rather than tested - --assume-injection was given")
			} else if !skipInjectionTest {
				fprintf(cmd.ErrOrStderr(), "testing injection on %d adapter(s)...\n", len(disc.Devices))
				radio.VerifyInjectionAll(cmd.Context(), acquirer, disc.Devices, log)

				for _, d := range disc.Devices {
					if d.Injection != radio.InjectionVerified {
						fprintf(cmd.ErrOrStderr(),
							"warning: %s (%s) injection %s - transmitting work will be refused "+
								"on this adapter.\n  %s\n",
							d.ID, d.Ifname, d.Injection, d.InjectionNote)
					}
				}
			}

			sched, err := radio.NewScheduler(disc.Devices, log)
			if err != nil {
				return err
			}

			db, err := store.Open(ws.Path(workspace.DBFile))
			if err != nil {
				return err
			}
			defer db.Close()

			// Hash files are opened for append and read back first, so a daemon restarting
			// mid-engagement does not append a second copy of every hash it already has.
			hashes, err := handshake.NewWriter(ws.Dir, workspace.PMKIDFile, workspace.HandshakeFile)
			if err != nil {
				return err
			}

			// Raw capture runs continuously alongside parsing so a parser bug cannot lose an
			// engagement's data. The daemon owns the archive: it opens a fresh timestamped pcapng
			// (and a netxml snapshot beside it) for each recon start/stop, into captures/.
			deps := daemon.Deps{
				Workspace: ws,
				Scheduler: sched,
				Store:     db,
				Acquirer:  acquirer,
				Hashes:    hashes,
				Log:       log,
			}
			if webEnable {
				deps.Web = &web.Config{
					Addr:        webListen,
					Token:       webToken,
					TLS:         !webNoTLS,
					AllowRemote: webAllowRemote,
				}
			}

			d, err := daemon.New(deps)
			if err != nil {
				return err
			}

			// Clean teardown on signal. A panic or an abrupt exit must not leave adapters
			// stranded in monitor mode.
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			fprintf(cmd.ErrOrStderr(), "\n%s %s  ·  %s\n",
				build.Name, build.Release(), build.Author)

			// The token is generated per run and never written to disk, so this line is the
			// only place it appears. Print it before Run blocks.
			if w := d.Web(); w != nil {
				fprintf(cmd.ErrOrStderr(),
					"\nweb interface:  %s\naccess token:   %s\n\n"+
						"The link above logs in on its own. The token is new for this run and is not\n"+
						"stored anywhere; restart the daemon to invalidate it.\n",
					w.URL(), w.Token())

				// Always drop the URL, token and address into the engagement directory, so an operator
				// who was not at the console at startup (a closet box over a VPN) can retrieve them. The
				// engagement dir is already 0700 and holds the recovered credentials; this file is 0600
				// alongside them, rewritten each run (the token is new each run).
				access := fmt.Sprintf("web interface:  %s\naccess token:   %s\nlisten address: %s\n",
					w.URL(), w.Token(), w.Addr())
				if err := os.WriteFile(ws.Path(webAccessFile), []byte(access), 0o600); err != nil {
					fprintf(cmd.ErrOrStderr(), "warning: could not write %s: %v\n", ws.Path(webAccessFile), err)
				} else {
					fprintf(cmd.ErrOrStderr(), "Also written to %s (0600).\n\n", ws.Path(webAccessFile))
				}
				if !webNoTLS {
					fprintf(cmd.ErrOrStderr(),
						"The certificate is self-signed and generated at startup, so the browser will\n"+
							"warn once. Nothing on this box identifies itself with a real certificate.\n\n")
				}
				// For a closet deployment reached over a VPN, the operator is not at the console to
				// read the line above. --web-url-file writes the one-click login URL (token included)
				// to a file they can retrieve over SSH. It is 0600 and holds a live credential: whoever
				// can read the file can drive the interface, which transmits. Opt-in, never on by
				// default - the token stays off disk unless asked.
				if webURLFile != "" {
					if err := os.WriteFile(webURLFile, []byte(w.URL()+"\n"), 0o600); err != nil {
						return fmt.Errorf("write --web-url-file %q: %w", webURLFile, err)
					}
					fprintf(cmd.ErrOrStderr(),
						"The login URL (with token) was written to %s (0600). Retrieve it over your\n"+
							"management channel; anyone who can read it can drive this interface.\n\n",
						webURLFile)
				}
			}

			return d.Run(ctx, g.socket)
		},
	}

	cmd.Flags().StringVar(&wsDir, "workspace", "", "engagement directory created by `warp init` (required)")
	cmd.Flags().StringSliceVar(&radios, "radios", nil, "adapters to use, e.g. --radios wlan0,wlan1 (default: all capable)")
	cmd.Flags().BoolVar(&skipInjectionTest, "skip-injection-test", false,
		"do not test injection at startup; transmitting roles will be refused")
	cmd.Flags().BoolVar(&assumeInjection, "assume-injection", false,
		"treat every adapter as injection-capable without testing (recorded as asserted, not demonstrated)")
	cmd.Flags().StringVar(&regDomain, "reg-domain", radio.DefaultRegDomain,
		"regulatory domain (ISO country code) to set at startup when the kernel is on the world "+
			"default, so the 5/6 GHz bands are transmit-usable; a domain already set is left alone")
	cmd.Flags().BoolVar(&resetRadios, "reset-radios", false,
		"USB-reset the adapters before starting, to clear any wedged firmware state from a previous session")

	cmd.Flags().BoolVar(&webEnable, "web", false,
		"serve the browser interface alongside the RPC socket")
	cmd.Flags().StringVar(&webListen, "web-listen", web.DefaultAddr,
		"address for the browser interface")
	cmd.Flags().StringVar(&webToken, "web-token", "",
		"access token for the browser interface (default: generated and printed at startup)")
	cmd.Flags().BoolVar(&webNoTLS, "web-no-tls", false,
		"serve the browser interface over plain HTTP (only sane behind an SSH port-forward)")
	cmd.Flags().BoolVar(&webAllowRemote, "web-allow-remote", false,
		"allow the browser interface to bind a non-loopback address - it can transmit, so this is deliberate")
	cmd.Flags().StringVar(&webURLFile, "web-url-file", "",
		"write the one-click login URL (token included, 0600) to this path, for retrieval over a management channel on a remote/closet deployment")
	return cmd
}

// probeCmd runs the capability probe without starting a daemon.
//
// This is the Phase 1 hardware gate: it needs no privileges and no workspace, so the probe
// can be run and diffed against `iw list` before anything is reconfigured.
func probeCmd() *cobra.Command {
	var (
		radios     []string
		testInject bool
	)

	cmd := &cobra.Command{
		Use:   "probe",
		Short: "Enumerate adapters and print their capabilities (no daemon, no privileges)",
		Long: `Probes every wireless adapter over nl80211 and prints what the kernel reports:
bands and channels, supported interface modes, and valid interface combinations.

Compare this against ` + "`iw list`" + ` before building on it. Injection is reported as
"unverified" because it is deliberately not read from the capability bitmap, which lies on
several common chipsets - it is only ever reported as verified after an empirical test.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			disc, err := radio.Discover(cmd.Context(), radio.DiscoverOptions{Only: radios})
			if err != nil {
				if errors.Is(err, nl80211.ErrUnavailable) {
					return fmt.Errorf("%w\n\nThis machine has no wireless stack. Run the probe on the engagement hardware", err)
				}
				return err
			}

			// Injection is only tested on request: it requires root, reconfigures the
			// adapter into monitor mode, and transmits. Plain enumeration does none of that.
			if testInject {
				fprintf(cmd.ErrOrStderr(),
					"testing injection on %d adapter(s) - this reconfigures each adapter into\n"+
						"monitor mode and transmits an inert self-addressed frame.\n\n",
					len(disc.Devices))
				acquirer := radio.NewAcquirer(logger())
				defer acquirer.Close()
				radio.VerifyInjectionAll(cmd.Context(), acquirer, disc.Devices, logger())
			}

			if g.jsonOut {
				return emitJSON(cmd.OutOrStdout(), disc)
			}
			return renderProbe(cmd.OutOrStdout(), disc)
		},
	}

	cmd.Flags().StringSliceVar(&radios, "radios", nil, "restrict to these adapters")
	cmd.Flags().BoolVar(&testInject, "inject", false,
		"also test injection empirically (needs root; reconfigures adapters and transmits)")
	return cmd
}

func resetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reset [radio|interface...]",
		Short: "Power-cycle wedged USB adapters (live if warpd is running, else standalone)",
		Long: `Re-enumerate a USB Wi-Fi adapter from scratch to recover it after heavy mode-cycling.

Monitor mode on mt76 and other USB parts (Panda/Ralink, rt2800usb, RTL, ath9k_htc) can stop
delivering frames until the device is reset - recon that "used to get 40 APs now gets 7", or a
card stuck at 0 frames after an attack borrowed it. A USB reset clears the wedged firmware state
without unloading any driver, so it works for any card, and it preserves the interface name and
MAC.

Two modes, chosen automatically:

  - warpd running: names one radio (phyN or its interface) and resets it live over the RPC, then
    rebinds it to the re-created phy - no daemon restart. Capture must be stopped first (the daemon
    refuses otherwise), because the reset power-cycles the adapter.

  - warpd stopped: names one or more interfaces, or resets every USB adapter with no arguments,
    doing the re-enumeration directly. A built-in PCIe/SDIO adapter is skipped.

Needs root:

  sudo warp radios reset phy0`,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()

			// When warpd is running, reset live over the RPC: it stops nothing (the daemon enforces
			// that capture is already stopped), power-cycles the named adapter, and rebinds it to the
			// re-created phy without a daemon restart. This is the on-site path - a wedged card during
			// an engagement. Naming a radio is required, because the live reset is per-adapter.
			if c, err := dial(); err == nil {
				defer c.Close()
				if len(args) == 0 {
					return fmt.Errorf("warpd is running - name the radio to reset (e.g. `warp radios " +
						"reset phy0` or an interface name); the live reset is per-adapter. `warp radios " +
						"list` shows them")
				}
				for _, target := range args {
					if err := callAndRender(cmd, "radios.reset", map[string]string{"radio_id": target},
						func(w io.Writer, r struct {
							RadioID string `json:"radio_id"`
							Ifname  string `json:"ifname"`
							Note    string `json:"note"`
						}) error {
							fprintf(w, "%s (%s) reset - %s\n", r.RadioID, r.Ifname, r.Note)
							return nil
						}); err != nil {
						return err
					}
				}
				return nil
			}

			// warpd is not running: do the standalone re-enumeration ourselves.
			targets := args
			if len(targets) == 0 {
				disc, err := radio.Discover(cmd.Context(), radio.DiscoverOptions{})
				if err != nil {
					if errors.Is(err, nl80211.ErrUnavailable) {
						return fmt.Errorf("%w\n\nRun this on the engagement hardware", err)
					}
					return err
				}
				for _, d := range disc.Devices {
					if d.Ifname != "" && radio.IsUSBAdapter(d.Ifname) {
						targets = append(targets, d.Ifname)
					}
				}
				if len(targets) == 0 {
					fprintf(out, "no USB adapters to reset (built-in PCIe/SDIO cards cannot be reset this way)\n")
					return nil
				}
			}

			failed := resetInterfaces(out, targets)
			fprintf(out, "\nGive the adapters a second or two to re-enumerate, then start warpd.\n")
			if failed > 0 {
				return fmt.Errorf("%d of %d adapter(s) could not be reset", failed, len(targets))
			}
			return nil
		},
	}
	return cmd
}

// resetWirelessUSB USB-resets adapters at daemon startup (the --reset-radios path). It discovers
// the USB adapters itself when none are named, and never fails startup - a reset that could not run
// is reported and the daemon carries on with whatever the adapter's current state is.
func resetWirelessUSB(ctx context.Context, out io.Writer, only []string) {
	targets := only
	if len(targets) == 0 {
		disc, err := radio.Discover(ctx, radio.DiscoverOptions{})
		if err != nil {
			fprintf(out, "reset-radios: could not enumerate adapters (%v) - continuing without a reset\n", err)
			return
		}
		for _, d := range disc.Devices {
			if d.Ifname != "" && radio.IsUSBAdapter(d.Ifname) {
				targets = append(targets, d.Ifname)
			}
		}
	}
	if len(targets) == 0 {
		return
	}
	fprintf(out, "reset-radios: power-cycling %s to clear any wedged state...\n", strings.Join(targets, ", "))
	resetInterfaces(out, targets)
}

// resetInterfaces resets each named interface, printing one line per adapter, and returns the count
// that failed. A built-in (non-USB) adapter is reported as skipped rather than an error.
func resetInterfaces(out io.Writer, ifaces []string) int {
	var failed int
	for _, ifn := range ifaces {
		if !radio.IsUSBAdapter(ifn) {
			fprintf(out, "  %-8s skipped (not a USB adapter)\n", ifn)
			continue
		}
		if err := radio.ResetUSBAdapter(ifn); err != nil {
			fprintf(out, "  %-8s reset failed: %v\n", ifn, err)
			failed++
			continue
		}
		fprintf(out, "  %-8s reset OK\n", ifn)
	}
	return failed
}

func renderProbe(w io.Writer, disc *radio.Discovery) error {
	if len(disc.Devices) == 0 {
		fprintf(w, "no usable wireless adapters found\n")
	}

	for _, dev := range disc.Devices {
		fprintf(w, "%s  %s", dev.ID, dev.Ifname)
		if dev.Driver != "" {
			fprintf(w, "  driver=%s", dev.Driver)
		}
		if dev.MAC != "" {
			fprintf(w, "  mac=%s", dev.MAC)
		}
		fprintf(w, "\n")

		if dev.Phy != nil {
			var modes []string
			for _, t := range dev.Phy.SupportedIftypes {
				modes = append(modes, t.String())
			}
			fprintf(w, "  modes:      %s\n", strings.Join(modes, ", "))

			for _, band := range dev.Phy.Bands {
				usable, total := 0, len(band.Freqs)
				for _, f := range band.Freqs {
					if f.Usable() {
						usable++
					}
				}
				fprintf(w, "  band %-6s %d channels (%d usable for transmit)\n", band.Name, total, usable)
			}

			fprintf(w, "  interface combinations:\n")
			if len(dev.Phy.Combinations) == 0 {
				fprintf(w, "    (none advertised - concurrent interfaces not supported)\n")
			}
			for _, c := range dev.Phy.Combinations {
				fprintf(w, "    %s\n", c)
			}
			if dev.Phy.SupportsAPMonitorConcurrent() {
				fprintf(w, "  -> supports concurrent AP + monitor (an extra logical radio)\n")
			}
		}

		fprintf(w, "  injection:  %s", dev.Injection)
		if dev.InjectionNote == "" && dev.Injection == radio.InjectionUnverified {
			fprintf(w, " (run with --inject to test it; transmitting roles refuse an untested adapter)")
		}
		fprintf(w, "\n")
		if dev.InjectionNote != "" {
			fprintf(w, "              %s\n", wrap(dev.InjectionNote, 74, "              "))
		}
		fprintf(w, "  rfkill:     %s\n\n", radio.RFKill(dev.ID))
	}

	for _, ex := range disc.Excluded {
		fprintf(w, "excluded: %s (%s) - %s\n", ex.ID, ex.Ifname, ex.Reason)
	}

	n := len(disc.Devices)
	switch {
	case n == 0:
		fprintf(w, "\nNo usable adapters. WARP needs at least one.\n")
	case n < radio.RecommendedRadios:
		fprintf(w, "\n%d adapter present. WARP runs fully on one - active work borrows the\n"+
			"capture radio for the length of each burst, so recon pauses briefly rather than\n"+
			"anything being unavailable. A second adapter removes those pauses.\n", n)
	}
	return nil
}
