# Changelog

All notable changes to WARP. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning is [semantic](https://semver.org/), with the caveat that WARP is pre-1.0 and the RPC
surface is still allowed to move between minor versions.

The version lives in `internal/build/build.go` and is tagged in git to match. `warp --version`
reports it together with the commit the binary was built from - the version says which release,
the commit says which build of it, and a client asking which code produced a finding needs the
second one.

---

## [v0.29.0] - 2026-10-06

### Added

- **BSSID selection reaches the CLI and TUI, not just the web.** `warp eap start` gained a `--bssid`
  flag to wear a specific observed BSSID (validated against what WARP has seen, same as the web), and
  the terminal dashboard can start the evil twin against the enterprise access point under the cursor
  on the Access Points tab (`S`), wearing that BSSID. Keeps all three clients at capability parity
  (invariant 9).

- **TUI marks 802.1X captures as not crackable.** A PMKID or handshake overheard from a
  WPA-Enterprise network now shows as `802.1X` with "not crackable" in the terminal credentials
  table, instead of reading as crackable PSK material - the same honesty the web credentials tab
  enforces.

- **TUI explains the injection state.** Each adapter's injection line on the Radios tab carries a
  one-line explanation; "inconclusive" reads as "not a failure, transmitting proceeds" so two
  identical mt76x2u cards coming up differently is no longer confusing.

## [v0.28.0] - 2026-10-06

### Added

- **Evil Twin BSSID selection.** When several access points broadcast the scoped network name, the
  target card now has a dropdown to pick which observed BSSID the rogue clones its certificate from
  and wears as its own MAC, rather than always the strongest. The list only ever offers addresses
  WARP has discovered on the air for that ESSID, and the daemon validates the choice again on start
  (`eap/start` gained a `bssid` field that is refused unless it was observed broadcasting the scoped
  name) - selection among discovered addresses, never a hand-typed target, and the ESSID still
  authorizes (invariant 1).

### Changed

- **The in-scope control is a real on/off switch.** The engagement-wide in-scope toggle in the top
  bar is now the same red/green sliding switch as the per-adapter toggles on the Radios tab, and it
  sits immediately to the left of the lock button.

### Fixed

- **Evil Twin running timer sits beside Stop.** The live timer is now grouped with the Stop button at
  the right of the red running banner, instead of being stranded next to the capture count.

## [v0.27.0] - 2026-10-06

### Added

- **Evil Twin running timer.** The red running banner now shows how long the rogue AP has been on
  the air, immediately to the left of the Stop button, and the running view gained **running for**
  and **associations** cards alongside requests / challenges / captured.

### Changed

- **Evil Twin "not running" intro is compact.** The large centred placeholder that pushed the real
  controls below the fold is now a tight left-aligned note.

- **Radios tab explains injection state.** Each adapter's injection line carries a one-line
  explanation (and tooltip). "inconclusive" now reads as what it is - the driver took the frames but
  did not loop them back, common on mt76, not a failure, transmitting proceeds - so two identical
  mt76x2u cards reading differently is no longer confusing. Only "failed" blocks work.

### Fixed

- **Evil Twin live output no longer fights the poll.** The console element is cached and re-used
  instead of rebuilt every 2 s, so resizing it is no longer aborted by a refresh and the scrollbar
  no longer blinks; a press inside it also holds the background rebuild off until release. The target
  picker's "N BSSIDs broadcasting this name" list now keeps its open state across a refresh instead
  of snapping shut.

## [v0.26.0] - 2026-10-06

### Added

- **Evil Twin certificate feedback.** The running view now shows the presented certificate in full
  - subject, issuer, SHA-256 fingerprint, the SANs a strict client actually checks, the validity
  window and the key - so an operator can confirm exactly what was cloned and, when a client
  refuses, see what it checked. Every certificate in the library gained a `details` toggle that
  reveals the same, with its open state kept across the background poll.

- **Evil Twin live output box (EAPHammer-style).** A resizable console on the Evil Twin tab streams
  the rogue AP's own events - associations, credential captures, certificate events - each tagged by
  what it is (ASSOC / CRED / CERT / REJECT). Drag it to any size for a clean screenshot; the size is
  remembered across re-renders. It filters the shared event stream to just the rogue AP, and lingers
  after a stop so a run can still be captured.

- **Evil Twin target picker.** A crowded enterprise site that puts dozens of BSSIDs on the air under
  a few names used to render as an unreadable wall of cards. It is now one dropdown of the scoped
  enterprise networks plus one focused panel: the BSSIDs discovered broadcasting the selected name
  (discovered, never configured), the strongest radio and channel to harvest/beacon from, whether a
  certificate is ready, and the Clone/Start actions. Readable whatever the AP count.

## [v0.25.0] - 2026-10-06

### Added

- **Engagement-wide "in scope only" toggle.** A single toggle in the dashboard header, beside the
  lock, narrows every tab - APs, clients, findings and credentials - to networks the SoW covers.
  It drives the same flag the per-tab "in scope only" checkboxes do, so setting it anywhere sets it
  everywhere and each tab's checkbox reflects it. Off by default; nothing is hidden until asked.

- **Credentials tab honours the scope filter.** The credentials/hashes tab now has its own "in scope
  only" checkbox (wired to the engagement-wide toggle), so incidental out-of-scope captures can be
  narrowed out of view there like everywhere else. The empty state explains when captures exist but
  are all out of scope, rather than reading as "nothing captured."

- **802.1X captures filed separately and never announced as a win.** A PMKID or four-way handshake
  overheard from a WPA-Enterprise (802.1X) network is still captured and kept as evidence, but its
  pairwise key comes from the RADIUS exchange, not a passphrase - no hashcat 22000 wordlist can
  recover anything. These now sit in their own "802.1X captures - not crackable" table on the
  credentials tab, clearly labelled and kept out of the PSK material headed for the rig, and the
  live notification for one is dropped to an informational log line (no tray toast) so it never
  reads as a crackable recovery. The split keys off the observed AP's advertised security class.

## [v0.24.0] - 2026-09-28

### Added

- **Cleartext enterprise credentials get their own deliverable file.** A no-crack credential
  (TTLS-PAP, EAP-GTC) now lands in `creds/cleartext.txt` - tab-separated ESSID, identity, password,
  self-contained and mappable back to the network - beside `creds/mschapv2.5500`, so the enterprise
  handoff is two machine files (hashes to crack, passwords already in the clear) rather than only the
  human-readable summary. Written live and fsynced, same as the hash files.

- **Certificate rejections are surfaced.** When a supplicant validates the presented certificate and
  refuses it (a correctly-configured client - not a finding, not a capture), WARP now says so: a log
  line and a one-time popup per client (retries are logged, not re-popped), plus a running rejection
  count on the Evil Twin page. Previously a refusal read only as the vague "no credential captured."

### Changed

- **The Evil Twin captured-credentials table now has a Type column and shows the value.** It marks
  each capture CLEARTEXT or MSCHAPv2 and shows the actual credential for both - previously a cleartext
  capture rendered as a blank "Hash line" cell, hiding the very thing that was captured.
- **The certificate library's "use" button is green.** With several certificates prepared for a
  network, the button that selects which one the rogue presents now stands out instead of blending in.

## [v0.23.1] - 2026-09-28

### Fixed

- **EAP-TTLS now completes against TLS 1.3 supplicants** (modern Windows, Wi-Fi 6E/7 clients). A TLS
  1.3 client sends its Finished and its first Phase-2 AVPs in one flight, so the credentials are
  already buffered the instant the tunnel comes up; WARP was acknowledging and waiting for them in a
  separate packet that never came, so the exchange deadlocked and the client reported "network not
  available" (PEAP was unaffected because it is server-initiated after the handshake). WARP now peeks
  for the front-loaded AVPs when the tunnel opens and only waits if none arrived (the TLS 1.2 path).
- **The in-memory EAP TLS pipe now honours read deadlines.** `SetReadDeadline` was a no-op, so a read
  on an empty buffer blocked forever - harmless while a payload was always fed first, but it made the
  Phase-2 peek unsafe. Reads now time out cleanly, which is what makes the peek above possible.

## [v0.23.0] - 2026-09-28

### Added

- **EAP-TTLS inner methods (PAP and MSCHAPv2).** The rogue RADIUS/EAP server already stood up a TTLS
  tunnel when a supplicant asked for it; it now handles the Phase-2 credentials inside that tunnel.
  TTLS carries Diameter AVPs (not inner EAP like PEAP), so WARP reads them off the decrypted stream:
  **PAP** yields the password in **cleartext** (no cracking step - the strongest enterprise outcome),
  and **MSCHAPv2** (explicit MS-CHAP-Challenge + MS-CHAP2-Response AVPs) maps onto the same
  `hashcat -m 5500` line the PEAP path produces, reusing the identical derived-challenge maths.
  Captures land where the existing ones do: cleartext in `creds/credentials.txt`, hashes in
  `creds/mschapv2.5500`. No configuration or hostapd change is needed - a supplicant that negotiates
  TTLS (by Nak-ing the PEAP offer) is handled automatically. Inner CHAP and MSCHAPv2 with an implicit
  (TLS-derived) challenge are detected and noted rather than mis-emitted.

## [v0.22.0] - 2026-09-25

### Added

- **Audible hunt cue in the browser.** The hunt banner now has a speaker toggle on its far right: a
  Geiger-style cue (like the CLI's `warp hunt --audible`) that beeps faster, and a touch higher, as
  the signal strengthens, so you can walk a device down by ear. It is built on the Web Audio API (a
  soft sine blip, kept gentle rather than an alarm), **muted by default**, and per-viewer - it makes
  sound only in that browser and transmits nothing. The rate mirrors the daemon's mapping (RSSI
  clamped to -90..-30 dBm onto 1500..60 ms) and is derived from the live hunt state the banner
  already has, so there is no daemon change. It goes silent whenever muted, no hunt is live, or the
  target has no signal.

## [v0.21.1] - 2026-09-25

Wording accuracy sweep across the CLI, console and web, plus one advertised-but-dead flag made real.

### Fixed

- **`warp psk --station` help no longer says it is "required with --deauth".** It is optional -
  omitting it broadcasts against every client on the AP (which the command's own long help and the
  `--broadcast` flag already said). The help now reads "omit it to broadcast against every client".
- **Scope add/remove no longer claim a change that did not happen.** Adding a name already in scope,
  or removing one that was not, printed "added to scope" / "removed from scope (recorded in the audit
  log)" as if it had mutated state and written an audit entry - it had not. The CLI `scope add` and
  the console `scope add`/`remove` now say "already in scope" / "was not in scope" when nothing
  changed (the CLI `scope remove` already did this).
- **The console WPS hint no longer claims a finding for absent WPS.** Pressing WPS on an AP with no
  WPS element said "that absence is the finding"; no finding is recorded for absent WPS. It now says
  WPS being off is the good outcome and that no finding is recorded for its absence.
- **`warp hunt --audible` now actually sounds.** The flag was accepted and the daemon computed the
  beep interval, but the one-shot hunt readout never emitted the terminal bell, so it was silent. It
  now beeps, with the rate rising as the signal strengthens, as the flag promises.

## [v0.21.0] - 2026-09-25

Deauthentication campaign sizing in the GUI/console, and a sweep for misleading message wording.

### Added

- **Deauthentication size is adjustable from every frontend.** The plumbing always took frames-per-
  burst and a duration; now the browser surfaces them in a small options dialog (pre-filled with the
  defaults, so the common case is still one click), and the console `psk` command takes `--count` and
  `--seconds`. The CLI already had `--count`/`--seconds`. The duration is clamped to 60s in the UI as
  well as the daemon, so more control cannot become a sustained outage at a client site.

### Fixed

- **The 802.11w deauth refusal no longer reads as an exposure.** Where deauthentication is refused
  because a network requires management frame protection, the daemon, the web AP panel and the web
  client panel now describe it as a hardening control that classification records as a control
  (802.11w required), not as "a finding" (and no longer claim it was "recorded" when nothing was).
- **The report and console no longer name a file that does not exist or mislabel the handshake
  product.** The Markdown report said hashes were written to `eapol.22000` (the file is
  `handshakes.22000`) and both the report and `report export` summary called them "EAPOL hashes";
  they now say "handshake hashes" and name `handshakes.22000`. "EAPOL" reads to an operator as
  uncrackable WPA-Enterprise, so it is kept out of all user-facing output (invariant 3a-ii), now
  guarded across the report/console/subcommand layers, not just the web assets.

## [v0.20.2] - 2026-09-25

### Fixed

- **The deauthentication refusal on an 802.11w network no longer claims to have recorded a finding.**
  Refusing to deauthenticate a network that requires management frame protection previously said "this
  is itself a finding and has been recorded" - but nothing was recorded there, and 802.11w-required is
  a hardening control (a pass), not an exposure. The refusal (in the daemon and the web panel) now
  states that plainly: clients ignore unprotected deauthentication, so it is refused, and the posture
  is a control that classification records as one (802.11w required) - not something the refusal
  itself records.

## [v0.20.1] - 2026-09-25

Self-heal from a transient USB re-enumeration instead of stranding the radio.

### Fixed

- **A USB adapter that drops and comes back no longer wedges the radio.** On a flaky bus (a hub, or
  USB passthrough into a VM), an mt76-class card can re-enumerate on its own: the kernel rebuilds the
  netdev under the same name but a new interface index and phy. Every low-level call WARP made was by
  the cached index, so after a drop the capture socket bind and the mode-set both failed with ENODEV
  ("no such device") against a dead index - and the reopen loop retried that same dead index for 30s
  and gave up, leaving the card visible in `iwconfig` but unusable until a daemon restart. WARP now
  re-resolves the interface by its (stable) name and rebinds to the re-created phy: the capture reopen
  loop reconciles each attempt, and the acquire paths (recon, survey, hunt, PMKID/handshake, WPS,
  rogue AP) reconcile and retry once when an adapter's index has actually changed. A failure that is
  not a re-enumeration is surfaced unchanged rather than masked by a retry.

## [v0.20.0] - 2026-09-25

Reset a wedged adapter without restarting the daemon.

### Added

- **Live per-radio USB reset.** A **Reset** button on each USB adapter card in the web Radios tab,
  `radios reset <radio>` from the console command prompt, and `warp radios reset <radio>` (which now
  resets live over the RPC when warpd is running, and falls back to the standalone re-enumeration when
  it is not). It USB power-cycles the one adapter to clear the wedged firmware state that stops mt76
  (and similar) parts capturing after heavy mode-cycling - the "did not associate" a card reset fixes
  - then waits for it to re-enumerate and rebinds the managed radio to the re-created phy by its
  (preserved) interface name. No daemon restart. It is offered only for USB adapters and only when
  nothing holds the card: capture stopped and no jobs running. The daemon enforces that gate, not just
  the frontends, so no client can pull a radio out from under a live capture. Built-in PCIe/SDIO cards
  report as not resettable this way.

## [v0.19.0] - 2026-09-24

Operator-marked rogue devices, and a PSK-on-an-enterprise-name finding the classifier now derives on
its own.

### Added

- **Mark a specific BSSID as a potential rogue.** A new **Mark Rogue Device** button on every access
  point in the web APs tab (detail pane), the `m` key on the console APs tab, and `warp rogue mark
  <bssid>` / `warp rogue unmark <bssid>`. It is an operator judgement, not a classifier verdict:
  nothing is auto-marked. The mark colours the device red (the way in scope is green) in both
  dashboards, is specific to the one BSSID (siblings on the same ESSID are untouched), and records an
  evidence-tier "Potentially Rogue Device" finding whose evidence points at manual evidence you
  supply (the JSON report fills it with the replaceable placeholder). It transmits nothing and never
  consults scope, so it works on any device in scope or not. Marks survive a daemon restart and a
  re-classify never wipes them. Its evidence is a plain "manual evidence required" block (the
  placeholder sits in the evidence field, never in the finding's description), not a beacon cipher
  dump. Because a suspected rogue is, by nature, not on a scoped ESSID, the finding is always part of
  the in-scope views - the "in scope only" toggle, `findings-in-scope.csv`, and `report-in-scope.json`
  all keep it rather than filing it away with the out-of-scope neighbours.
- **PSK access point on an otherwise enterprise ESSID** is now derived by the classifier. When one or
  more BSSIDs serve an ESSID over 802.1X enterprise and another serves the same name over a
  pre-shared key, the PSK BSSID is flagged (evidence tier, "verify physically") - the shape of a
  misconfiguration or an impostor a client would still trust.

### Changed

- The old placeholder label "unknown device present in the footprint" is retired; unknown devices
  remain in the unclassified list, and "Potentially Rogue Device" is now an operator-applied label
  rather than an automatic one.

## [v0.18.0] - 2026-09-24

The JSON report is reorganised around what a reader actually needs, and finding evidence now fits
the finding it sits under. The BSSID-to-ESSID map and the findings are two separate sections instead
of findings nested per device, and a hidden-network finding no longer shows a cipher dump.

### Added

- **Each BSSID in the JSON report carries an `encryption_detail` field** - the parsed beacon security
  laid out like a `tshark -V` dump, the same packet-detail output the web "Encryption Packet" popup
  shows - so it imports into a reporting platform verbatim, one field per access point under its ESSID.
- **Findings with no packet-level evidence carry a replaceable placeholder.** When a finding has no
  beacon/probe-response record joined and no cited fingerprint differences (an unknown device, say),
  its evidence carries a single stable token (`REPLACE: no packet-level evidence was captured...`)
  instead of a silently empty field, so an import always has one obvious slot to fill in by hand.

### Changed

- **The JSON report is reorganised into two sections.** `networks` is now purely the
  BSSID-to-ESSID map - one entry per ESSID with every BSSID broadcasting it and what was captured for
  that network. `findings` is a new top-level section, one entry per finding: its title, the evidence
  behind it, and the list of assets it affects. Previously each network carried its own findings, so
  the same finding was repeated down the document; it now reads as "here is a finding and everything
  it affects." Still no secret material (no passphrases, PINs, hashes or cleartext), and still two
  variants, `report-in-scope.json` and `report.json`.
- **Finding evidence fits the finding.** The evidence block under each finding is chosen by the
  finding type rather than always dumping the beacon encryption: a recovered hidden-network name now
  shows the cloaking (empty SSID element, the recovered name), and a karma-responder or evil-twin
  finding shows the observed device record. Encryption findings still show the parsed `tshark -V`
  style beacon detail.
- **A "what to look at" line sits above the evidence block** (web), tying the finding to the packet
  field it rests on - for a WPA2/WPA3 transition BSS, "the AKM list advertises SAE (WPA3) alongside
  PSK (WPA2): a transition BSS, the WPA2 side is downgrade-attackable"; for WEP, open, TKIP, WPS and
  the rest, the one-line reason in the same place. Transition mode was previously invisible in the
  evidence even though it drove the finding.

## [v0.17.0] - 2026-09-24

Per-session capture files, Kismet netxml output beside every capture, evidence you can open under
each finding, a clients-tab scope filter, and a durable credentials summary. Plus clearer startup:
the control socket and the web bind address now document their defaults so a launch command carries
only what it needs.

### Added

- **Each recon start/stop is its own capture.** Starting capture opens a fresh
  `captures/capture-<UTC>.pcapng`; stopping closes it. A run is never appended to a previous one.
- **Kismet netxml alongside the pcaps.** Each capture writes a `.netxml` beside its pcap, each
  walkthrough writes one holding just that pass's networks, and a live `networks.netxml` is
  regenerated with the CSV projections - the observed networks and clients in the shape survey
  tools import.
- **A durable credentials summary.** `creds/credentials.txt` is a human-readable roll of every
  recovered WPS passphrase and enterprise credential, rewritten as each one lands and on startup, so
  the deliverable is legible at a glance and survives the live log scrolling away.
- **Machine-readable JSON report**, in the dashboard (Overview → *Export JSON*), the TUI
  (`report json`) and the CLI (`warp report export`). It groups by network - every BSSID under each
  ESSID, the findings and the assets they affect, the evidence, and what was captured for which
  ESSID - and carries no secret material (no passphrases, PINs, hashes or cleartext). Two variants,
  `report-in-scope.json` (the deliverable) and `report.json` (everything), both written to the
  engagement directory and offered as a download.
- **Collapsible Evidence under every finding** (web), and an **Encryption Packet** button on
  in-scope access points. Both render the network's parsed beacon security in the layout of a
  `tshark -V` dump - the Privacy bit-field, SSID, Group and Pairwise Cipher Suites (named the way
  tshark names the suites), each AKM as `<name> (<type>)`, and the 802.11w Required/Capable bits -
  so it reads as packet evidence, not a summary. WARP parsed all of it off the air, so no external
  tool runs; the `tshark` one-liner to pull the same detail from the pcap by hand sits below the
  copyable block (and is not part of what Copy copies). When no beacon record is joined, the evidence
  says so and gives the command. Findings and their Evidence are collapsible and remember their open
  state across the background poll. (WARP now also parses and exposes the group cipher separately.)
- **"In scope only" filter on the Clients tab**, matching the access-points and findings tabs. A
  client counts as in scope if it is associated to, or has probed by name for, a scoped network.

### Changed

- **The web URL, access token and listen address are written to `web-access.txt`** in the engagement
  directory (0600) every run - previously they only printed at startup (the `--web-url-file` flag was
  opt-in). A closet box reached over a VPN is now retrievable without watching the console.
- **The Overview export buttons both save and download.** Export CSV, Write Report and Export JSON
  all write their files into the engagement directory *and* hand the browser a copy: Export CSV
  downloads the projections as one in-memory zip (built and streamed, never saved; observations.csv
  is left out as it can be enormous), Write Report downloads `report.md`, and Export JSON downloads
  the chosen variant. Downloads are prefixed with the engagement/workspace name so files from
  different engagements do not collide in a downloads folder. Useful when the browser is on a laptop
  and the engagement dir is on a remote box.
- **Startup carries only what it needs.** The control socket defaults to `/run/warp.sock`, so
  `--socket` is only for overriding it, and the docs say so.
- **Remote web access is spelled out.** `--web` binds loopback only; reaching it from the network
  takes `--web-listen <addr> --web-allow-remote` together (binding non-loopback without the opt-in
  is refused). The README and Quickstart now make this explicit rather than leaving `--web` looking
  like it should already be remote.

### Fixed

- **The web log tab no longer opens empty.** A browser connecting during a quiet stretch now
  replays the recent event backlog instead of showing nothing until the next event.
- **A walkthrough leaves the radios the way it found them.** Begun while recon was idle, it now
  brings capture up (previously its pcap opened but caught nothing) and ending it returns the cards
  to idle; begun while recon was running, ending it returns to capturing.
- **Walkthrough files are named for the pass, not `name-<id>`.** The pcap/netxml/summary use the
  walkthrough's own name (`3rd-floor-east.pcapng`), only falling back to a `-<id>` suffix if a file
  of that name already exists.
- **Findings and their Evidence no longer collapse on the background poll.** Each finding is a
  collapsible section and the Evidence block is laid out like a Wireshark packet-details pane (the
  pertinent 802.11/RSN/fingerprint/signal fields for one in-scope asset, plus a `tshark` filter to
  pull that BSSID's frames from the pcap); both remember their open state across refreshes.

## [v0.16.0] - 2026-09-18

Findings for every observed network filed by scope, a `control` tier that separates passes from
exposures, scope you can edit from any interface, and a hardening of direction-finding on a shared
radio. First launch release: the sample-capture and lab scaffolding are out of the tree, so a
consultant clones, runs `make`, and goes.

### Added

- **Findings are produced for every observed network, in scope or not, and filed by scope.** Posture
  (open, WEP, TKIP, WPS, 802.11w, transition mode) is read off every network; `findings.csv` holds
  all of it, `findings-in-scope.csv` holds only scoped networks (the reporting file), the report
  keeps its totals to in-scope with an *Out of scope (context)* section for the rest, and the
  findings tab gained an **in scope only** toggle. Observing is not transmitting, so scope still
  gates every transmission; evil-twin clustering stays scope-only.
- **A `control` tier separates passes from exposures.** A correct configuration or a test the
  network passed - 802.11w required, WPS locked, an AP that resisted Pixie Dust - is filed as a
  control and shown apart from the exposures, so a pass never reads as a problem.
- **Edit scope from any interface.** `scope add`/`scope remove <essid>` (RPC, CLI and TUI) widen or
  narrow the list, persisted to `scope.txt`; the access-point **Exclude** button removes the whole
  network from scope and **Add to scope** puts it back.
- **Footer credential counters** for recovered WPS keys and evil-twin captures, alongside pmkid and
  handshakes.

### Changed

- **A Pixie Dust result supersedes the beacon-derived "WPS enabled and unlocked" note** rather than
  sitting beside it: once tested, an AP shows "resistant" (a control) or "PIN recovered", and a
  re-classify will not re-add the stale note.
- **Direction-finding on a shared radio is far more reliable.** A borrowed hunt now reads recon's
  existing capture through an in-engine tap instead of opening a second socket on the same interface
  (unreliable on mt76 after mode-cycling); it parks the channel promptly, and when a wedged card
  will not retune it says so and points to `warp radios reset` rather than showing a dead gradient.

### Fixed

- A run of web-interface polish: findings that gain a finding leave the unclassified list; the
  top-bar sparkline no longer overlaps the frame count and the `CH … lock` shows amber again; long
  walkthrough names fit their card; detail-panel actions stack as a same-size column; and the
  evil-twin banner and card buttons render cleanly.

## [v0.15.0] - 2026-09-14

WPA3 transition-mode downgrade surfaced as a first-class attack, automatic GTC downgrade,
per-walkthrough capture files and an overview log, a hunt banner built for walking a signal to
its source, live (not peak-latched) signal everywhere, and a batch of web/TUI parity and
correctness fixes. Code complete; on-hardware validation of the new radio-facing pieces is in
progress against the lab environment (the mechanisms below that were already validated are noted
as such).

### Added

- **Full TUI/GUI parity.** Every capability the browser can reach is now reachable from the terminal
  dashboard too. New console commands closed the remaining gaps: `precheck [fix <check>]` (host
  readiness checks and fixes), `radios channels <radio> [1,6,11] [no5ghz] [random]`, `radios
  regdomain [cc]`, `scope acknowledge <essid>`, `certs list|delete|import`, and `walkthrough split`
  / `walkthrough devices`. A parity audit over the RPC surface backs this up.
- **A `wiki/` folder with the documentation**, ready to publish as the repository's GitHub wiki:
  a quickstart, a full TUI reference (every key and command), a web-interface guide, and a
  step-by-step guide to creating the GitHub wiki itself.
- **The regulatory domain is set automatically, and adjustable live.** warpd sets a default
  regulatory domain (US, `--reg-domain` to change) at startup when the kernel is still on the
  world/unset domain - so the 5/6 GHz bands come up transmit-usable instead of receive-only, with no
  `iw reg set` to remember. It only fills in the unset default; a domain the system already set is
  left alone. It can be changed while running from the radios tab (a country dropdown + Apply),
  `warp radios regdomain [cc]`, or `radios regdomain [cc]` in the TUI, after which WARP re-probes so
  the band flags and its own transmit gating reflect the new rules. Set natively over nl80211
  (`REQ_SET_REG`/`GET_REG`), no shelling out to `iw`.
- **WPA3/WPA2 transition-mode downgrade is now a named attack, not a side effect.** The mechanism
  already existed - for a transition BSS, PMKID solicitation associates offering *only* the PSK AKM
  (`connect.go`), forcing the WPA2 side, and reads the crackable PMKID from M1 with no client and no
  passphrase. It is now discoverable: the `WPA2/WPA3 transition mode` finding spells out the exploit
  for the report (SAE has no offline-crackable material; the legacy PSK side hands over a PMKID on
  association; where the AP will not volunteer one, deauthentication forces a crackable four-way),
  and the web AP action reads **"Downgrade & solicit PMKID"** on a transition BSS with a tooltip
  explaining the AKM downgrade. The WPA3 upgrade buys nothing while the WPA2 path is offered.
- **GTC downgrade is automatic.** Once an operator starts an enterprise capture they have committed
  to collecting credentials, and a supplicant that refuses EAP-GTC simply falls through to the
  MSCHAPv2 challenge WARP captures anyway - so GTC is now offered by default. `AllowGTCDowngrade` is
  a tri-state pointer (nil = auto-enable); the web gets it for free, and the CLI opts out with
  `warp eap start --no-gtc`. A supplicant that accepts GTC hands over a cleartext password with no
  cracking step.
- **Per-walkthrough capture files.** Starting a walkthrough now opens a dedicated raw archive at
  `walkthroughs/<name>-<id>.pcapng` for exactly the span it is open, and closing it writes a
  `walkthroughs/<name>-<id>.txt` roll of every BSSID/ESSID (and client) heard during the pass. A
  walkthrough can be replayed in isolation from the engagement-wide capture, and the summary answers
  "what did this pass cover" at a glance. `walkthrough.devices` RPC + `/api/walkthrough/devices`.
- **A walkthrough log on the overview.** A banded table of every walkthrough - name, duration, APs
  and clients heard, capture file - each row expandable (default collapsed) to the BSSID/ESSID roll
  for that specific pass, with a Delete button for a failed pass. Delete removes the pcap and the
  summary but never the observations, which belong to the engagement and are associated by time
  range. `walkthrough.delete` RPC + `/api/walkthrough/delete` + `warp walkthrough delete <id>` +
  `walkthrough delete <id>` in the TUI. `warp walkthrough list` now shows APs/clients/pcap.
- **The hunt banner is built for walking a signal to its source.** A hunt already channel-locks and
  targets one BSSID; the banner now shows the locked channel and radio, an oversized live RSSI, a
  warmer/colder/steady trend read off the sparkline, and the sparkline itself, in both frontends. On
  the web it refreshes on a fast (~600 ms) timer while a hunt is live rather than only the 2 s page
  poll - 2 s is too slow to walk to a device by - touching only the banner, so it never disturbs a
  text selection.

- **A TKIP (WPA1) posture finding.** An access point advertising the TKIP cipher - a pure WPA1
  BSS, or a WPA2 BSS still offering TKIP for backward compatibility - now produces a posture
  finding (deprecated since 2012, weaker than CCMP). Pairs with the existing WEP and open-network
  findings so the deprecated-crypto postures are all reported rather than only the crackable ones.

### Changed

- **Signal is shown live, not peak-latched.** The AP and client tables and details showed
  `best_rssi` - the strongest reading ever seen - which latches to maximum after one close pass and
  never decays, so a device not heard in minutes still read as full-strength (and an association
  spike during an attack stuck at max forever). All three frontends now show the **last-heard**
  reading, dimmed with an age when the device has gone stale, with peak kept as a separate figure in
  the detail pane. The station view gained `active`/`last_seen_secs` to match the AP view.
- **Findings are grouped by name.** The findings tab (web and TUI) now shows one entry per finding
  with a description and an affected-assets table (BSSID/Network), rather than one row per
  (BSSID, finding) repeating the same label down the page. The Classify button on the findings tab
  is coloured (green) and its label reflects state ("Classify" on a clean slate, "Re-classify" once
  findings exist).
- **`rogues.csv` holds only rogues.** The all-findings projection is `findings.csv`; `rogues.csv` is
  now restricted to rogue-labelled findings (evil-twin candidates, karma responders) rather than
  every finding.
- **A walkthrough is never implicit.** The daemon no longer opens a walkthrough at startup;
  observations carry one only when the operator explicitly starts it, and starting/ending one resets
  the radios at the boundary so each pass is captured from a clean slate (invariants 2 and 5
  revised). Captures made outside any walkthrough carry none - the honest record of a closet
  deployment where nobody walked.
- **The capture toggle lives in the top bar** (reachable from any tab), and the **Enterprise
  capture button was removed from the overview** - enterprise capture is not a one-button action and
  lives on the Evil Twin tab.

### Fixed

- **Re-classifying no longer deletes the findings the attacks produced.** A re-classify cleared the
  whole findings table and re-added only the classifier's conclusions - wiping a WPS PIN/passphrase
  recovered by Pixie Dust, which is a result of work done, not a conclusion the classifier can
  re-derive. It now clears only the classifier's own labels and leaves attack-recorded findings in
  place.
- **The bottom of the page is a permanent status bar.** The running counters (APs, clients,
  findings, PMKID, handshakes, jobs, disk) moved out of the top bar into a footer pinned to the
  bottom of every page - left-aligned with dividers between them - with the build and attribution on
  the right. The top bar keeps the wordmark, capture toggle, per-radio activity, and the lock button
  on the far right. The wordmark got a subtle cyan→green treatment.
- **Timestamps show the date and the viewer's local time.** They are converted to the operator's
  own clock (the one they compare against), and the credentials tab shows the full date since an
  engagement can run more than a day.
- **No em dashes anywhere in the interfaces.** Swept out of the web, TUI and CLI (and the strings the
  daemon emits into them); only the README and this changelog still use them.
- **The generated web access token is alphanumeric** ([A-Za-z0-9], ~190 bits) with no dashes or
  underscores, so it copies, types and pastes into a URL cleanly.
- **The karma responder test actually sweeps every channel.** The per-channel loop passed a channel
  to the probe but never retuned the radio, so every probe went out on whatever channel the adapter
  was already on and only that one was really tested; it now tunes to each channel (one burst per
  channel, the same radio capturing the response there).
- **Radios tab: wider cards, per-adapter facts as a banded table**, so a card fits more without
  scrolling; the top-bar per-radio line is on fixed columns so a one- vs three-digit channel no
  longer shifts everything after it.
- **The findings "unclassified" list is a table** of BSSID and network, not a run-on line of MACs.
- **The log tab has "Copy whole log" and "Download log"** for handing a session's log off to
  troubleshoot.
- **Empty tabs are dark to the edges** - a tab with no detail pane left an empty grey panel showing
  below the content; it is hidden when empty so the background is uniform header to footer.
- Small spacing fix so the note under the WPS credentials table is not flush against it, and the
  lock button sits at the far right of the top bar.
- **The pinned header is scoped to the big data tables.** Access-points and clients keep the sticky
  header; the credentials tab (which stacks several tables and prose) gets a plain header again, so a
  pinned header no longer floats over the text above the next table.
- **The country dropdown no longer collapses on a poll.** A background redraw is held off while the
  operator has a form control focused (an open `<select>`, a field being typed in) - the same
  protection selection already had - and the reg panel keeps a pending choice across a rebuild.
- **The web credentials tab dropped a WPS key when no PSK hash was captured alongside it.** An
  empty PSK-hash list serialises to JSON `null`, and the refresh guard replaced the entire hashes
  object - `wps_keys` included - whenever `.hashes` was not an array. So a Pixie Dust run with no
  PMKID/handshake in the same session showed the passphrase in the job log and the TUI but never on
  the web. The guard now keeps the object and only normalises the list. A regression test
  reproduces the exact shape.
- **The WPS finding no longer embeds the recovered secret.** The finding described the exposure
  using the run's own outcome text, which quoted the PIN and the recovered passphrase - a
  credential belongs on the credentials tab and in `creds/wps-keys.txt`, not in a finding's prose.
  The rationale now describes the exposure and points to the credentials; only the nonce generator
  (the technical fact) stays.
- **The TUI credentials column is "SECRET", not "HASH"** - it holds passphrases and cleartext
  passwords as well as hash lines.
- **An expanded walkthrough keeps updating.** Its device roll was cached on first expand and never
  refetched, so it went stale and a collapse/re-expand showed nothing new; it now refetches on
  expand and on each poll while open.
- **The country dropdown, and selections generally, survive a poll.** The radios pane rebuilt every
  poll because the capture counters change in the redraw signature - which closed an open dropdown
  and reset a pending choice. Those counters are excluded from the signature now (the header still
  updates them out-of-band), and the pending country choice is preserved across a rebuild.
- **Spacing:** a clear gap between a finding's description and its affected-assets table, and
  between the filter box and the table on the access-point and client tabs.
- **WPS keys reload on startup**, so a recovered passphrase keeps showing in the credentials tab
  across the daemon restarts an operator does between manual tests - the durable `creds/wps-keys.txt`
  is read back into memory at launch. (The rendering itself was already correct; a regression test
  now renders the credentials pane with a WPS key and asserts the passphrase appears.)
- **The regulatory domain is visible in the TUI** - shown at the top of `radios list`, since there
  was nowhere in the terminal dashboard it appeared.
- **The web header shows a real capture-activity sparkline per radio** (frame-rate over a rolling
  window, like the TUI) instead of a flat bar, and the count now reads "N frames".
- **The hunt trend is tuned between the two extremes** - a recent-window average vs the one before
  it with a 3 dB deadband, so it reacts to a walk without flipping on jitter and without being
  stuck on "steady".
- **The overview walkthrough table has a plain header again** - the sticky-header treatment is now
  scoped to the big scrolling data tables only; on the short overview table it floated over the
  rows. Added spacing around the section too.
- **WPS-recovered keys reach the credentials tab and persist.** The TUI credentials tab never
  rendered WPS keys at all (the row builder omitted them), so a recovered passphrase showed only in
  the job log; it now sits at the top of the tab in both frontends. Recovered keys are also written
  to a durable `creds/wps-keys.txt` (network, BSSID, passphrase, PIN, generator, time), matching the
  MSCHAPv2 creds file - a recovered passphrase is the deliverable and must survive to the report.
- **WPA1/TKIP is coloured as the deprecated posture it is** - the access-point security cell no
  longer paints WPA1/TKIP the same as an ordinary WPA2-PSK; it gets the loud colour WEP does.
- **Receive-only bands read clearly.** A 5 GHz/6 GHz band that is present but transmit-blocked by the
  regulatory domain is now labelled ` (no-tx: set reg domain)` rather than `(rx-only)`, which read as
  if the adapter could not inject - it can (injection is verified separately on 2.4 GHz); the higher
  band is regulatory-blocked for transmit until a domain is set, and WARP still sweeps it passively.
- **The hunt warmer/colder trend settles.** It read a short tail-vs-tail window and flipped every
  tick on ordinary RSSI jitter; it now compares the older and newer halves of the whole history with
  a wider deadband, so the word only changes on a real move.
- **The pinned table header is fully solid.** It kept a translucent look with rows visible in the
  gap above it (the pane's top padding); the header now paints a solid block up into that gap, uses
  bright bold text, and carries a coloured divider - nothing shows between it and the tab bar.
- **Previously-hidden networks are tagged.** A cloaked network whose name was recovered now carries a
  persistent "hidden" tag (any recovery path, not only probe-response), so it is always marked as
  previously-hidden in the access-point list.
- **Per-radio capture activity in the web header.** Each adapter row now shows a frame count and an
  activity bar sized against the busiest card - the at-a-glance "which card is pulling frames" the
  TUI radio table already gave.
- **The TUI walkthrough is controllable from one key.** `w` now ends an open walkthrough directly
  (matching the banner's stop) and otherwise starts one; the running walkthrough shows in the header
  with the stop hint, and the walkthrough dropdown on the overview separates the AP and client tables
  with a divider.

- **Interface names, never phy indices, in the operator's face.** The peak-signal detail, the hunt
  banner's channel lock, the survey-radio line, the localize header, the recon radio table and the
  assignments table all showed the internal `phyNNN` handle; they now show `wlanN`. Both frontends
  gained a radio-id→ifname resolver.
- **Dual-band cards no longer read as 2.4 GHz-only.** The radio band list counted only
  transmit-usable channels, so a card whose 5/6 GHz is entirely NoIR under a world (country 00)
  regulatory domain showed just `2.4GHz` - even though WARP passively sweeps the higher band. Bands
  now list what the card physically supports, marking a receive-only band ` (rx-only)` and the
  channel count `usable for transmit`, so the operator sees the 5 GHz capability and that setting a
  regulatory domain is what unlocks transmitting there.
- **A BSSID that changes its network name is tracked, not frozen.** The AP ESSID latched to the
  first name seen; a BSSID re-beaconed under a new name (a reconfigured radio, or a lab AP reused
  across tests) kept the stale name, which then broke scope matching and any association built from
  it. A beacon carrying a different name now updates it.
- **Findings are scoped to the engagement.** Posture findings (open, WEP, TKIP, WPS, transition,
  PMF) are recorded only for in-scope ESSIDs - a neighbour's weak crypto is not the engagement's
  finding to make. The rogue-specific labels (evil-twin candidate, karma responder,
  unknown-in-footprint, decloaked) remain the deliberate exception, since those are exactly what is
  not decided by scope.
- **Evil-twin candidate no longer fires on a small mixed mesh.** A two-vs-one fingerprint split -
  routine on a home/SMB mesh with one newer-generation node - was flagged as an impostor. A baseline
  now needs at least three matching access points before an outlier can be called; with only two you
  cannot tell the baseline from the outlier. Spoofed-BSSID detection on a real fleet is unchanged.
- **The WPS finding describes what WARP does.** It said the AP was "exposed to an online PIN
  attack"; WARP performs offline Pixie Dust and reads the passphrase from M7, never an online brute
  force (invariant 2a). The wording now says so.
- **A WPA1/TKIP posture finding, and the label to match.** `SecurityInfo` gained a `WPA1` flag; the
  access-point table shows `WPA1`/`+tkip` rather than a bare `psk`, and the classifier records the
  deprecated-cipher finding (in scope).
- **Text selection survives a row click and a channel hop.** Dragging to select a BSSID for copying
  ended in a row click that re-rendered the table and wiped the selection; the row handler now
  ignores a click that completed a text selection, on every tab.
- **Every browser prompt/confirm/alert is a styled in-page dialog.** The native popups - which look
  like a phishing box on a page that itself asks for a token - are replaced by a themed modal for
  every confirm, prompt and alert.
- **The pinned table header is opaque.** The sticky header on the access-point (and other) tables
  had a see-through background and lost its border on scroll, so rows bled through it; it is now
  solid with a drawn separator.
- **The hunt banner reads at a walkable pace.** The web banner refreshed every 0.6 s and the
  warmer/colder trend jittered on near-identical samples; it now refreshes at ~1.2 s over a wider,
  dead-banded trend window. A running walkthrough now has its own banner (web and TUI) with a stop
  control, the overview walkthrough table splits access points from clients, a hunt job's Detail
  column shows what it is tracking, and the TUI surfaces the running walkthrough and the report key.

- **Checkboxes could not be unchecked.** The web element helper set boolean attributes by presence
  (`setAttribute('checked', false)` still renders a checked box), so every checkbox - "random hop",
  "skip 5 GHz" - came up ticked and un-ticking it was undone on the next redraw. This was the real
  cause of "random hop is selected by default but sweeps sequentially" and "un-checking reapplies
  on refresh". Booleans are now driven as DOM properties, random hop defaults off (sequential), and
  a per-radio local override keeps a toggle across a rebuild.
- **Text selection was lost when a card hopped channels.** The per-radio live channel was in the
  redraw signature, forcing a full-body rebuild every dwell and wiping any selection or half-typed
  channel form. The hopping channel is excluded from the signature (the header still updates the
  live channel out-of-band), so the body only rebuilds when something that matters changes.
- **The MSCHAPv2 evil-twin note no longer claims a cleartext capture.** The "a cleartext password
  came with no cracking step" line now appears only when a cleartext credential was actually
  captured (GTC), not for an MSCHAPv2 challenge/response.



On-hardware validation of PMKID and WPS against controlled access points, with a reusable lab
harness. PMKID confirmed correct; the WPS association bug fixed; the remaining WPS blocker
diagnosed precisely.

### Added

- **Adapters can be switched on and off from the radios tab (web and TUI) and the CLI.** With
  several cards plugged in, an operator can now hand specific ones to another tool: switching an
  adapter off releases it (its capture runner is stopped, the interface freed, and it is never
  assigned again) and switching it on returns it to the pool, bringing a capture role back if one is
  uncovered. `radios.set-enabled` RPC, `warp radios enable|disable <radio>`, a Switch on/off button
  on each web radio card, and the `t` key in the TUI radios tab. Disabling the survey adapter
  un-pins survey so it moves to another card (the scheduler keeps invariant 5 for whichever adapter
  is survey). Per-runner cancellation was added so one adapter can be stopped without touching the
  others. Verified on hardware: disable moved survey off the card and released it; enable brought it
  back.
- **A "System state" panel on the radios tab - the host checks, live.** The same checks
  `warp precheck` runs (rfkill blocks, NetworkManager and wpa_supplicant fighting for the cards),
  now reachable while the daemon runs, with a per-check Fix button (unblock rfkill, set the
  interfaces unmanaged, stop/mask a stray supplicant). `precheck.list` / `precheck.fix` RPC,
  fetched on demand rather than in the poll (it shells out). The radios-tab cards were also
  rearranged: the on/off switch sits to the right of the interface name and the channel controls
  are at the top of each card.
- **Kismet-style channel control per adapter - which channels it sweeps, 5 GHz on/off, random
  hop.** `radios.channels` RPC, `warp radios channels <radio> [--only 1,6,11] [--no-5ghz]
  [--random]`, and a control on each web radio card. `--only` restricts the sweep to a channel set
  (a beacon-poor site with a known target channel wastes dwell hopping the rest); `--no-5ghz` drops
  the 5/6 GHz bands for a 2.4-only engagement; `--random` shuffles the hop order so a device that
  beacons rarely is less likely to be missed by a predictable sweep at the same phase every cycle.
  Applied live via `ChannelPlan.Adopt` - a sweeping radio reconfigures without restarting recon; a
  selection that filters everything out is refused rather than leaving a dead sweep. Verified on
  hardware: 36-channel sweep → 3 channels, 5 GHz off, random, then cleared back to full.
- **The radios display shows the interface name, not the phy index.** `wlan0` is what an operator
  tracks; the `phyNNN` index is an internal handle and is now omitted from the top bar, the radios
  tab and the session detail in all three frontends.
- **WPS Pixie Dust now retrieves the WPA passphrase, not just the PIN.** Recovering the PIN is not
  the deliverable a client understands - the passphrase is. Once Pixie Dust recovers the PIN offline
  from M3, the same exchange now completes registration with that PIN (M4, M6) so the access point
  reveals its own configuration in M7, and WARP reads the WPA passphrase (the WSC Network Key) out of
  M7's AES-128-CBC encrypted settings. It **stops at M7 and never sends M8** - M7 is the AP reporting
  its settings, M8 would write new ones, so nothing is reconfigured and nothing joins the network.
  This revises invariant 2a: the line is drawn at reconfiguring the AP (M8) and at online brute
  force, not at reading M7 - exactly what reaver does to print `WPA PSK`. New crypto in
  `internal/wps/settings.go` (encrypted settings, key-wrap authenticator, M4/M6 builders, M7 parser);
  the exchange returns the passphrase and the recovery result together. A secure AP whose PIN cannot
  be recovered still stops at M3. Confirmed on hardware against WPS-TEST: PIN `22008992` → passphrase
  read from M7, identical to reaver, in one association.
- **`--web-url-file` writes the one-click login URL to a file, for remote/closet deployments.** An
  operator reaching the box over a VPN is not at the console to read the token printed at startup.
  With `--web-listen 0.0.0.0:8443 --web-allow-remote --web-url-file <path>`, WARP binds every
  interface and writes the auto-login URL (token included, `0600`) to a file they can retrieve over
  their management channel. Opt-in; the token still stays off disk without the flag.
- **Recovered WPS credentials surface in the Credentials view.** The PIN and passphrase now appear in
  the terminal `warp hashes` output and the web Credentials tab (a "WPS recovered keys" section),
  carried on the existing `hashes.list` RPC (`HashesResult.WPSKeys`) so all three clients see the
  same thing - already-cracked credentials, kept with the credentials rather than the 22000 material
  headed for the rig.
- **A "SEEN" column across all three frontends - is an access point still on the air?** WARP keeps
  every AP it has ever observed (nothing is filtered - invariants 3a/7), which makes a live listing
  hard to read against the history. The daemon now computes `active` and `last_seen_secs` on each AP
  view (`ActiveWindow` = 90s, generous enough to survive a couple of sweep cycles), and `warp aps`,
  the terminal dashboard and the web interface all render a compact age with a live marker
  (`● 5s` for currently visible, `3m (gone)` for a stale entry). This is the airodump-style
  "currently visible" made explicit, and it is what disambiguates a real neighbour AP from a stale
  entry left over from earlier testing.
- **`testing/lab/` - on-hardware test harness.** `lab-pmkid.sh` and `lab-wps.sh` stand up a stock
  `hostapd` AP on one adapter (a normal config, not tuned for WARP) and run WARP against it on a
  second adapter, then tear both down. See `testing/lab/README.md`. These are field-confidence /
  regression checks that need real radios, so they run on the engagement box, not CI.
- **`daemon.withStation` connect-offer log** (carried over from the diagnostics work) plus a
  per-frame trace of the control-port EAPOL a solicitation receives, so an empty M1 is diagnosable.
- **`TestSolicitedPMKIDReachesTheDeliverable`** - a daemon-level integration test that drives a
  constructed message 1 (carrying a PMKID KDE) through the real `Engine.SubmitEAPOLKey`, handshake
  machine, 22000 writer and store, and asserts a crackable line lands in `pmkid.22000`. This proves
  the glue the over-the-air solicitation depends on - everything from the received M1 to the
  deliverable - deterministically, without needing an AP that happens to volunteer a PMKID. The
  PMKID attack is now covered end to end: extraction (`internal/handshake`), machine emission, and
  the daemon's file write; only the association that reads M1 needs radios, and that is hardware-
  proven.

### Fixed

- **Certificate harvest (and PMKID/association) failed against an MFP-capable AP with "operation
  not supported".** WARP mirrored an MFP-*capable* (not required) AP's 802.11w posture as
  `NL80211_MFP_OPTIONAL`, and the kernel returns `-EOPNOTSUPP` for that value on any driver without
  `NL80211_EXT_FEATURE_MFP_OPTIONAL` (mt76 among them) - so `CMD_CONNECT` was refused before any
  EAPOL, `associated as 00:00:00:00:00:00`, and the cert never arrived (it worked against a no-MFP
  test AP). WARP now requests MFP only when the AP *requires* it; a capable-but-not-required AP is
  associated as a non-PMF client, which is correct because every one of these exchanges abandons the
  association before the four-way handshake, so PMF never comes into play. `mfpForAssociation`
  centralises it; pinned by `TestMFPCapableDoesNotRequestOptional`.
- **The browser served a stale `app.js` after an upgrade, so new Credentials-tab content (the WPS
  keys section) never appeared** even though the daemon returned it. Embedded assets carry a zero
  modtime, so `http.FileServer` let the browser cache them indefinitely; static assets now send
  `Cache-Control: no-cache` so the JavaScript is revalidated on every load. If a feature "doesn't
  show up" after an upgrade, this was why - hard-refresh once, or now just reload.
- **PMKID solicitation refused WPA3 transition-mode networks.** `crackableCheck` correctly allowed
  them (the PSK half sends a crackable PMKID) but `connectParamsForAP` refused the whole SAE class,
  so the association never started. Transition mode now associates on the PSK side, offering only
  the PSK AKM (offering SAE too invites the kernel into dragonfly, which needs a passphrase) and
  mirroring the advertised group cipher. Pure WPA3-SAE is still correctly refused.

- **WPS over-the-air association now works - via a kernel-driven open+WSC association.** WPS needs an
  *open* association carrying a WSC element (what reaver injects); the connection manager
  (`CMD_CONNECT`) refuses an open association to a secured AP, which is why WPS never got off the
  ground. mt76 (and ath9k etc.) advertise userspace MLME, so WARP now drives it by hand:
  `CMD_TRIGGER_SCAN` (a fast directed scan, so the BSS is in the interface's cache - without it
  `CMD_AUTHENTICATE` returns ENOENT) → `CMD_AUTHENTICATE` (open) → `CMD_ASSOCIATE` (with the WSC
  element and the 802.1X control port), all on the association-owning socket
  (`ConnectParams.ManualMLME`). Validated on a real vulnerable AP: WARP associates and drives the
  WSC registrar exchange to PIN recovery.
- **WPS Pixie Dust now recovers the PIN over the air - the last blocker was one wrong attribute
  ID.** WARP tagged the M2 Registrar Nonce `0x101C`, which is `ATTR_IDENTITY`; the real
  `ATTR_REGISTRAR_NONCE` is `0x1039`. So a WSC 2.0 access point parsing M2 found no registrar nonce
  and refused with a `WSC_NACK` whose config error is left at 0 - `wps_process_registrar_nonce`
  fails *first* in hostapd's `wps_process_m2`, before the authenticator is ever checked. The M2 was
  otherwise byte-perfect and its authenticator verified against itself, so the failure read as a DH
  or authenticator mismatch and was not: it was this one tag. Confirmed on hardware end to end
  against a vulnerable AP (WPS-TEST): M1 → M2 → M3, PIN recovered offline, matching reaver's result.
  `internal/wps` now pins the registrar nonce to the literal `0x1039` in the exchange test so the
  builder can no longer agree with a wrong constant.
- **WPS M2 carried the single-value Authentication/Encryption Type instead of the Type Flags.** It
  sent Authentication Type / Encryption Type (which belong only in a Credential) rather than the
  Authentication Type Flags (0x1004) / Encryption Type Flags (0x1010) M2 mandates. Fixed alongside
  the registrar-nonce tag above.
- **TUI radio line ran the phy id into the interface name at two- and three-digit phy indexes.** A
  box reset many times reaches phy70+, and the fixed-width pad left no gap. A trailing space is now
  guaranteed before the interface name regardless of the phy id's length.
- **The browser interface gated Decloak behind an operator confirmation, contradicting invariant
  1a** (the daemon does not require one - decloaking a hidden network is authorized because it is
  the only way to learn whether the name is in scope; `scope confirm` is advisory). The web now
  offers Decloak on any hidden network, in or out of scope, with the confirmation as an optional
  courtesy - matching the CLI, the dashboard and the handler.

- **Station connect intermittently failed with `netlink validate: mismatched sequence in netlink
  reply`.** The socket that drives `CMD_CONNECT` joins the `mlme` multicast group to catch the
  association result, but the connect was issued with `Execute`, which validates that the reply's
  sequence matches the request - so a multicast mlme event (sequence 0) landing between the request
  and its ack failed that check, purely on timing. The connect now goes out with `Send` (no
  sequence validation; `waitConnect` reads the ack, any error and the event off the socket), the
  pre-connect disconnect runs before the group join, and the teardown disconnect is a `Send` too.
  On hardware this eliminated the error and let a previously-failing neighbour AP complete the
  association and return M1. Affects PMKID solicitation, WPS and the certificate harvest.

- **WPS Pixie Dust associated as an ordinary PSK client, so the AP never started EAP-WSC.** The WSC
  registrar exchange runs over an association that must *signal WPS*; WARP was mirroring the AP's
  RSN with no WSC element, so hostapd ran the WPA four-way and no registration exchange began
  ("advertises WPS but started no registration exchange"). The association now carries a WSC
  information element (`ConnectParams.ExtraIE`, `wpsConnectParams`, `wpsAssocIE`), and hostapd
  accepts it as a WPS station (`STA included WPS IE… assume WPS is used`).

### Validated on hardware

- **WPS Pixie Dust works over the air, end to end, on mt76.** Against a real vulnerable AP
  (WPS-TEST / `9C:EF:D5:FD:0F:42`) WARP does the open+WSC MLME association, runs the registrar
  exchange (identity → M1 → M2 → M3), and recovers the PIN offline (`22008992`) - the same PIN
  reaver recovers, cross-checked against the AP's own hostapd debug log. The earlier "association
  completes but M2 is refused" symptom was the registrar-nonce attribute-ID bug above, not a driver
  or association limitation; the open+WSC association itself was correct.

- **PMKID solicitation is correct.** Across four access points (a controlled hostapd AP and three
  in-scope BSSIDs) WARP associates, reads message 1 off the control port, and extracts any PMKID
  present. None of these APs put a PMKID in M1 for a fresh association - hostapd's own debug shows
  `kde_len=0`, i.e. the AP sends a bare M1 - so WARP's "no PMKID cached" is the correct result, not
  a defect. A PMKID seen only passively comes from a real client's roam (a cached PMKSA), which a
  fresh solicitation does not reproduce; this matches `hcxdumptool`. Extraction remains pinned by
  `internal/handshake` unit tests.

## [v0.14.1] - 2026-09-10

The Evil Twin captures credentials end to end. Validated over the air on real hardware, one
adapter beaconing the rogue and a second associating to it as a supplicant, capturing a live
PEAP-MSCHAPv2 credential to `creds/mschapv2.5500`.

### Fixed

- **PEAPv0 inner EAP framing was wrong - the exchange stalled the moment the tunnel came up.** Two
  bugs, both in `internal/eap/method`:
  - The server never opened Phase 2. When the TLS handshake completes, Go's TLS produces the
    server Finished *and* reports the handshake done in the same step, so the code sent the Finished
    and returned before `startInner` could run, then treated the supplicant's ACK as inner
    application data. It now sends the first inner EAP-Request/Identity on that ACK.
  - The inner EAP framing carried too many bytes. PEAPv0 puts only `[Type][Type-Data]` inside the
    tunnel - the Code and Identifier come from the outer PEAP packet, the Length from the TLS record
    boundary. WARP was sending `[Code][Identifier][Type][Data]`, which shifts every field along. The
    identity round survived it by luck (EAP Code Request 1 equals EAP Type Identity 1); the MSCHAPv2
    round never could, so nothing was ever captured. `marshalInner`/`unmarshalInner` now use the bare
    form, with a guarded fallback for a supplicant that sends a full inner header. New tests
    (`inner_test.go`) pin the exact bytes wpa_supplicant put on the wire.

  This clears the **PEAPv0 inner-framing validation gate** (Phase 3): the tunnel now runs to a
  captured MSCHAPv2 credential against a real supplicant.

- **The rogue can be tested without a third-party client.** With two adapters, one beacons the
  rogue and the other associates to it (`wpa_supplicant`, no CA - a misconfigured corporate client),
  which is how the capture above was validated. No behaviour change; recorded here as the procedure.

### Changed

- **Every station-based attack now logs its connect offer**, and a refused association is diagnosed
  honestly. `daemon.withStation` logs the exact crypto offered (WPA versions, ciphers, AKMs, MFP)
  before associating, so a bare `status 1` refusal is diagnosable from one place. The PMKID and WPS
  refusal messages no longer pin the blame on 802.11w: status 1 is "unspecified failure" - as often
  a weak or asymmetric link (the kernel reports a timed-out auth/assoc as status 1) as an
  undisclosed policy or MAC filter - and the message now says so and reports the strongest signal
  seen. Validated on hardware: a strong in-scope AP (−32 dBm) associates and its M1 is read every
  time; a distant in-scope neighbour AP (−57 dBm) refuses with status 1 consistently, against the
  same, correct offer - an AP-side decline, not a WARP fault.

## [v0.14.0] - 2026-09-10

Two-way exchanges all move onto the kernel-driven association that made the harvest work, and the
adapter-wedging workaround becomes a command.

### Added

- **`warp radios reset [interface...]`** - power-cycle a wedged USB adapter over `USBDEVFS_RESET`,
  driver-agnostic (mt76, Panda/Ralink, rt2800usb, RTL, ath9k_htc) and preserving the interface name
  and MAC. Recovers the "recon used to get 40 APs, now gets 7" and stuck-at-0-frames states without
  unloading any driver or naming a chipset. Refuses while warpd is running, because the reset
  re-creates the phy; run it between sessions. With no arguments it resets every USB adapter and
  skips built-in PCIe/SDIO cards.
- **`warpd --reset-radios`** - do that reset automatically at startup, before the radios are
  enumerated, so every fresh daemon run begins with un-wedged cards. It never fails startup: a reset
  that could not run is reported and the daemon carries on.

### Changed

- **PMKID solicitation now associates with a real kernel-driven connection** instead of injecting
  auth/assoc in active monitor. A PSK access point sends M1 (carrying the PMKID) the instant a
  station associates, before the four-way handshake; WARP reads it off the association's 802.1X
  control port and never answers it, so nothing joins the network. The M1 is folded into the same
  handshake machine a passively overheard one uses, so a solicited PMKID and an overheard one are
  identical from the frame onward - deduplicated, filed by scope, written to `pmkid.22000`. The
  active-monitor injection path could never reliably get the AP's ACK on the drivers a pentester
  carries, which is why solicitation kept coming back empty; the kernel association is the same path
  the certificate harvest already used.
- **WPS Pixie Dust now runs the WSC registrar exchange over the same kernel-driven association**,
  with EAP-WSC carried on the control port exactly like the harvest's EAP-TLS. Same reason: the
  injected association never ACK'd on real hardware. Still stops at M3; nothing joins the network.
- **Invariant 3a-iii rewritten.** The two-way exchanges (harvest, PMKID, WPS) are documented as
  kernel-driven associations (`daemon.withStation`), not active-monitor injection. The active-monitor
  orchestration that never worked on real hardware (`withActiveInjector`, `radioTransport`,
  `awaitReply`) is removed.

## [v0.13.1] - 2026-09-10

Live debugging on the engagement laptop (mt76x2u) after the harvest started working end to end.

### Added

- **`warp eap start --keep-own-bssid`** - beacon the rogue from the adapter's own MAC instead of
  cloning the target's BSSID. Cloning the BSSID means a client near the real access point associates
  with whichever is stronger - usually the real one - so nothing reaches the rogue. A distinct BSSID
  (with a different channel and a deauth of the real AP) puts the client on the rogue.

### Fixed

- **`warp aps` and the AP list no longer error on the MFP field.** `MFPState` marshalled to a name
  but had no `UnmarshalText`, so a client decoding the daemon's AP list failed with "cannot
  unmarshal string into MFPState" - which is what made the listing look like it was collapsing
  same-name BSSIDs. Round-trip restored.

### Diagnosed on hardware (not yet fixed)

- **Recon capturing far fewer APs than usual is the mt76x2u adapter wedging**, not a WARP bug. Heavy
  mode-cycling (monitor→managed→AP→active-monitor, repeatedly, for harvest/solicit/WPS/rogue) leaves
  the USB adapter in a state where monitor capture returns almost nothing. Confirmed: a sibling card
  captured 222 beacons on the same channel while the cycled one captured zero, and a full driver
  reload (`modprobe -r mt76x2u …; modprobe mt76x2u`) restored it to 34 APs with every same-name
  BSSID. **Workaround: reboot, or reload the driver, before a capture-heavy session.** A daemon-side
  mitigation (detect a wedged adapter, reset it) is worth adding.
- **The evil twin does not yet capture credentials - the EAP server's outbound TLS fragmentation
  stalls.** The mimic certificate is valid (subject/issuer correct, key matches), and the RADIUS/EAP
  server engages (requests and challenges observed), but a supplicant receiving the server
  certificate gets a partial TLS message ("Need N bytes more input data") and the remaining
  fragments never complete the handshake, so no inner MSCHAPv2 credential is exchanged. Localised to
  the server-side EAP-TLS fragmentation path (the harvest's *client*-side reassembly is unaffected
  and works). This is the next fix. Note: a client that validates the server chain (the real CA
  installed) correctly rejects the mimic regardless - that refusal is expected and is a PASS for the
  client, exactly as it would be against any tool.

---

## [v0.13.0] - 2026-09-10

**Certificate harvesting works end to end on real hardware.** Debugged directly on the engagement
laptop (mt76x2u), the last bug was found by capturing WARP's association request off the air and
diffing it against wpa_supplicant's: WARP's had **no RSN element at all**.

### Fixed

- **The association request now carries the RSN element.** The kernel does not build the RSN
  element from the cipher/AKM/WPA nl80211 attributes on several drivers (mt76 confirmed), so the
  request went out with no security element and the access point refused it with 802.11 status 40.
  WARP now builds the RSN element itself and supplies it via `NL80211_ATTR_IE`, exactly as
  wpa_supplicant does - the crypto attributes stay for the kernel's key bookkeeping, the element is
  what actually goes on the air. Confirmed on hardware: association succeeds, EAPOL flows over the
  nl80211 control port (6 sent / 5 received), and the RADIUS server's certificate is harvested and
  a mimic filed - the whole cert-clone pipeline, working:

  ```
  radio associated ssid=Waffles-Corp
  harvest EAPOL exchange  eapol_sent=6 eapol_received=5 err=<nil>
  harvested CN=radius.waffles.test,O=Waffles Test Authority - mimic filed and selected
  ```

- **`warp aps` (and any client decoding the AP list) no longer errors on the MFP field.** `MFPState`
  marshalled to a name but had no `UnmarshalText`, so decoding it back failed with "cannot
  unmarshal string into MFPState" and took the whole listing down. Round-trip restored.

### The full picture (v0.12.0 → v0.13.0)

The harvest failure was a stack of independent bugs, each hiding the next, all now fixed: nine wrong
nl80211 attribute numbers (v0.12.3); a guessed RSN instead of the AP's advertised suites + MFP
(v0.12.4); a wpa_supplicant systemd service reclaiming the card into managed mode (v0.12.5); and
finally the missing RSN element in the association request (this release). The association itself,
the EAPOL-over-nl80211 control port, and the EAP-TLS certificate read are all validated on hardware.

---

## [v0.12.6] - 2026-09-10

The supplicant masking (v0.12.5) worked - the card now stays in monitor mode and is genuinely
WARP's to drive - but the enterprise association is still refused with a bare 802.11 status 1, and
the target's RADIUS sees nothing, so the access point is rejecting the association at layer 2 before
EAP. Status 1 is generic, so this adds the visibility to pin the mismatch.

### Added

- **`harvest connect offer` log line**: on every harvest, before associating, WARP logs what it is
  about to offer (WPA versions, group/pairwise ciphers, AKM suites, 802.11w) alongside what the
  access point advertised (class, ciphers, AKMs, MFP, and whether an RSN element was captured at
  all). When the association is refused with status 1 the mismatch is in that line - a cipher or
  AKM the AP does not run, an 802.11w disagreement, or `ap_rsn_bytes=0` meaning recon never captured
  the AP's RSN element and the offer fell back to a WPA2/CCMP guess.

---

## [v0.12.5] - 2026-09-10

The card kept reverting to managed mode (0 frames on recon, `prior_iftype=managed` at the next
borrow, tcpdump showing an Ethernet link type). `currentIftype` reads the real mode over nl80211,
so this is genuine: a **wpa_supplicant systemd service** reclaims the interface within seconds of
being killed, holds it in managed mode, and fights WARP's own association - which also shows up as
the status-1 refusal.

### Changed

- **`warp precheck` now stops *and masks* the wpa_supplicant service**, not just `pkill`. A bare
  kill is pointless against a systemd service that restarts in seconds; precheck detects the active
  `wpa_supplicant.service` / `wpa_supplicant@wlanN.service`, stops and masks it, kills any remaining
  process, and verifies it is actually gone.
- **The station association disconnects any existing connection before it connects.** A supplicant
  that reclaimed the card may have it connected or connecting; issuing `CMD_CONNECT` over the top of
  that is refused. Best-effort - a "not connected" result is the normal, harmless case.

### Note

This is the environmental cause behind the recent failures: the interface was not even staying in
monitor mode, so recon read 0 frames and the association was fought over. With the supplicant
masked and the card actually held by WARP, the next harvest run is the real test of the connect
crypto/MFP work from v0.12.4.

---

## [v0.12.4] - 2026-09-10

With the attribute numbers fixed in v0.12.3, `CMD_CONNECT` is now well-formed and the access point
actually answers - with **802.11 status 1**, a refusal. The connect was offering a guessed
WPA2/CCMP/802.1X RSN with no 802.11w, which an enterprise access point rejects when that is not
what it runs.

### Changed

- **The association now mirrors the access point's advertised RSN element** instead of guessing.
  `connectParamsForAP` parses the AP's own RSN (`recon.ParseRSN`) and offers its exact group and
  pairwise ciphers, AKM suites, and 802.11w posture - so a network running GCMP, 802.1X-SHA256,
  WPA3, or required management frame protection is offered what it actually broadcasts, not a CCMP
  guess. Falls back to the WPA2/CCMP offer only when the element cannot be parsed.
- **802.11w is carried.** New `ConnectParams.MFP` → `NL80211_ATTR_USE_MFP` (required/optional from
  the AP's posture). An access point that requires management frame protection refuses an
  association that does not advertise it - the bare status-1 refusal - so this is likely the rest
  of the fix.
- Added `NL80211_ATTR_USE_MFP` (66) and the `nl80211_mfp` enum, compiler-verified and pinned in the
  constants tripwire; new `TestConnectParamsMirrorTheAdvertisedRSN` checks the suite-selector byte
  conversion (00-0F-AC-04 → 0x000FAC04) and that MFP is carried.

### What to expect

The connect should now either associate (status 0) and start EAP - `EAPOL frames sent N,
received M` with M > 0 and the certificate returning - or, if it still refuses, report a *specific*
802.11 status rather than the generic 1, which will name the remaining mismatch.

---

## [v0.12.3] - 2026-09-10

**The certificate harvest's real bug: nine nl80211 attribute numbers were wrong.** They were
hand-transcribed by counting the `enum nl80211_attrs`, which drifts over the enum's alias entries
and reserved gaps. The consequence was invisible until now: the crypto attributes for `CMD_CONNECT`
(cipher suites, AKM, WPA versions) landed on the wrong numbers, so the association never actually
offered WPA2/802.1X - it half-completed and EAP was never real (the `sent=3, received=0`), and once
the socket-owner / control-port-over-nl80211 attributes were added on their wrong numbers the
connect failed outright with `ERANGE` ("numerical result out of range").

### Fixed

- Corrected against the kernel header (compiler-verified, not counted):

  | Constant | was | now |
  |---|---|---|
  | `AttrSupportedCommands` | 51 (collided with `AttrFrame`) | 50 |
  | `AttrStatusCode` | 66 | 72 |
  | `AttrCipherSuitesPairwise` | 57 | 73 |
  | `AttrCipherSuiteGroup` | 58 | 74 |
  | `AttrWPAVersions` | 59 | 75 |
  | `AttrAKMSuites` | 71 | 76 |
  | `AttrFeatureFlags` | 173 | 143 |
  | `AttrSocketOwner` | 129 | 204 |
  | `AttrControlPortOverNL80211` | 154 | 264 |

  Every command value and every other attribute checked out correct; these nine (all added for the
  connect/station work, plus two older wiphy-dump attrs) were the wrong ones.

- **New tripwire:** `TestConstantsMatchKernel` pins every command and attribute number to its kernel
  value and asserts no two attributes collide - the `AttrFrame`/`AttrSupportedCommands` clash at 51
  would have been caught the moment it was written.

### What this should mean on hardware

The `CMD_CONNECT` now offers the correct WPA2/CCMP/802.1X and the correct control-port-over-nl80211
+ socket-owner attributes, so the `ERANGE` is gone and the association should genuinely negotiate
802.1X. Next run: `EAPOL frames sent N, received M` with **M > 0**, and the certificate coming back.

---

## [v0.12.2] - 2026-09-10

Audit of the radio mode state machine - how cards are set, borrowed, swapped between modes, and
restored - and the one path that was still getting it wrong.

### Fixed

- **The rogue AP (evil twin) thrashed the capture loop on a borrowed card.** Every other path that
  reconfigures a borrowed card - active-monitor injection (WPS), the station association (harvest) -
  suspends that card's capture loop first (`SuspendCapture`) so it does not race to reopen a
  monitor socket the new mode has taken away. The rogue AP did not: it reconfigured the card to AP
  mode with recon still trying to capture on it, producing a continuous "capture interrupted /
  reopened" storm for the whole evil-twin session. It now suspends the card's capture for the life
  of the session and lifts it on teardown, after the card is restored to monitor.

### Audit result (no change needed, recorded for confidence)

The full matrix, after this and the recent restore fixes, is now consistent:

| Path | Acquire | Capture suspend | Restore |
|---|---|---|---|
| recon / survey | `SetMonitor` (with OTHER_BSS) | - | - |
| deauth / decloak / karma (borrowed) | pause hop only, stays monitor | not needed | - |
| deauth (dedicated) | `SetMonitor` + channel | - | `SetMonitor` |
| WPS (active monitor) | station→setMAC→active monitor | yes | disconnect→down→MAC→`SetMonitor` |
| harvest (station) | station→setMAC→associate | yes | close station→down→MAC→`SetMonitor` |
| rogue AP (evil twin) | `SetIftype(AP)` | **yes (fixed here)** | down→`SetMonitor` |
| hunt (borrowed) | pause hop only, stays monitor | not needed | - |

Every restore-to-monitor now goes through `SetMonitor` so the OTHER_BSS flag is preserved
(v0.12.1), the disconnect happens before the interface is downed (v0.11.1), the spoofed MAC is put
back (flipping to station first, as SIOCSIFHWADDR requires), and the frame counter carries across
the reopen (v0.11.2).

---

## [v0.12.1] - 2026-09-10

### Fixed

- **A recon card read "0 frames" after any borrow.** Restoring a borrowed adapter to monitor mode
  used a bare `SetIftype(monitor)`, which sets the interface type but not the monitor flags - so
  the card came back **without** `NL80211_MNTR_FLAG_OTHER_BSS`, and on the drivers that honour it
  (the reason the initial acquisition sets it) the capture then saw only frames addressed to the
  local station: effectively nothing. The card looked dead - sweeping across channels at 0 frames -
  once anything had borrowed it for a deauth, solicit, or harvest. Restore now goes back through
  `SetMonitor`, putting the flags back exactly as the initial acquisition set them. Combined with
  v0.11.2's cumulative counter, a borrowed card's frame count now both survives the reopen and
  keeps climbing.

---

## [v0.12.0] - 2026-09-10

The EAPOL exchange for the certificate harvest now runs over the **nl80211 control port**, not a
data-path packet socket. v0.11.3's instrumentation proved the need: on real hardware the
association completed, WARP sent 3 EAPOL frames and received 0, the target's RADIUS saw nothing,
and tcpdump saw nothing - the classic signature of a driver that does not carry the 802.1X control
port over the data path. This is the path modern `wpa_supplicant` uses.

### Changed

- **Certificate harvest EAPOL rides `NL80211_CMD_CONTROL_PORT_FRAME`.** A new
  `nl80211.StationConn` owns the association on its own netlink socket (CMD_CONNECT with
  `SOCKET_OWNER` + `CONTROL_PORT_OVER_NL80211`), receives the access point's EAPOL as control-port
  notifications on that socket, and sends ours as control-port frames - the transport the harvest's
  EAP-TLS client runs over. The association result is read on the same socket, so it still blocks
  until the association truly completes or reports the 802.11 status if refused. `AcquireStation`
  keeps the `StationConn` on the acquisition and `Release` closes it, which drops the association
  (socket ownership) and restores the card.
  - Frame-encoding for CMD_CONTROL_PORT_FRAME is asserted offline (`station_test.go`); the exchange
    itself needs real hardware, as ever.

### Removed

- The data-path EAPOL packet socket (`radio.EAPOLPort`) and the standalone `Conn.Connect` /
  `ConnectWaiter`, superseded by `StationConn`. The packet-socket path was proven not to carry
  EAPOL on the test adapter, so it is gone rather than left as a dead fallback.

### Validation

- Hardware-gated, and the specific thing to confirm on the next run: the harvest should now show
  `EAPOL frames sent N, received M` with **M > 0** (the access point answering over the control
  port), and the certificate coming back. If M is still 0, the driver rejects control-port-over-
  nl80211 too and the log will carry the send error.

---

## [v0.11.3] - 2026-09-10

Instrumentation to localise the one remaining cert-harvest failure. On real hardware the
association now completes (the connect-waiter confirms it) and release is clean, but the EAP
exchange does not start and the target's RADIUS sees no attempt - so the fault is in the EAPOL
control port, not the association. This makes the next run say which half is stuck.

### Added

- **EAPOL frame counters on the harvest.** `radio.EAPOLPort` now counts frames sent and received,
  and the harvest logs them (`harvest EAPOL exchange`) and reports them in the failure message
  (`EAPOL frames sent N, received M`). When the association completes but nothing comes back, the
  message now says the control port is not carrying traffic - not "the association did not
  complete", which the connect-waiter has already ruled out - and points at watching
  `ether proto 0x888e` on the managed interface to see whether it is the send or the receive half.

### Notes

- No behaviour change to the association itself, which is working. The likely fixes once the counts
  are in: if frames go out but none return, the driver wants the control port over nl80211
  (`CMD_CONTROL_PORT_FRAME`) rather than the data path - the next increment; if none go out, the
  send path. The counts decide, rather than guessing.

---

## [v0.11.2] - 2026-09-10

### Fixed

- **A radio's frame count reset to zero every time it was borrowed**, so a card that had run a
  deauth, solicit or harvest read "0 frames" afterward and looked dead when it was capturing
  normally. Each reopen creates a fresh capture source whose counters start at zero; the counters
  from every prior source are now carried forward, so the per-radio frame/byte/error totals climb
  continuously across a borrow instead of resetting. (The reopen itself was already correct - this
  was the *display* misreporting a working radio as stopped.) The source swap is now done under a
  lock, closing a pre-existing race between the capture loop and the stats reader.

---

## [v0.11.1] - 2026-09-09

The kernel-connect harvest reached real hardware and **the association succeeded** - the thing
active-monitor injection never managed. Three bugs stood between a working association and a
harvested certificate; these are the fixes.

### Fixed

- **`disconnect wlan1: network is down`, and the capture storm after a harvest.** Release brought
  the interface *down before* issuing `CMD_DISCONNECT`, and a disconnect on a downed interface is
  refused - so the teardown failed and left the card stranded in managed mode, which then flapped
  the recon capture (a flood of "capture interrupted / reopened"). Disconnect now runs while the
  interface is still up, before the mode change.
- **"the access point sent no EAP request" on an association that actually worked.** Two causes,
  both fixed:
  - `AcquireStation` logged "associated" and returned as soon as the kernel *accepted* the connect
    request - not when the association completed - so the EAP client fired into a half-open
    association. It now waits for the real `CMD_CONNECT` result on the mlme multicast group
    (`nl80211.ConnectWaiter`) and returns only once the association has actually completed, or
    fails with the access point's 802.11 status code if it was refused.
  - The EAP-TLS client sent one EAPOL-Start and gave up after a single 3s timeout. It now resends
    the Start a few times before concluding the network is not enterprise - an AP waiting for a
    Start, or one that missed the first in the instant the association came up, now gets answered.

### Notes

- **One card does both now.** The managed card that associates also receives the EAP exchange
  itself (the kernel delivers EAPOL to a packet socket on that interface), so the harvest does not
  need a second radio to listen - it works on a single-adapter kit. The old "one card attacks, one
  listens" split was a constraint of the injection approach, which could not receive on the
  transmitting card; kernel-connect removes it.
- Still hardware-gated: association now demonstrably works on the test adapter, but the packet
  socket EAPOL exchange end-to-end is what the next run confirms.

---

## [v0.11.0] - 2026-09-09

**`warp harvest` now steals the certificate by being the client**, not by waiting for one. This is
the change the operator kept asking for and the honest v0.10.1 PMKID diagnosis confirmed was
necessary: on hardware whose driver does not ACK injected frames, the active-monitor association
never completes, so no amount of injecting works. The kernel-connect path sidesteps that entirely.

### Changed

- **Certificate harvesting associates to the access point and runs WARP's own EAP-TLS client over
  the association** - exactly what `wpa_supplicant` does by hand, minus the passphrase. The
  association is real and kernel-driven (`nl80211 CMD_CONNECT` via `radio.AcquireStation`), so the
  firmware acknowledges the access point the way it does for any client. WARP answers the identity
  request and starts TLS; the RADIUS server presents its certificate in the clear before it knows
  who is asking, so the certificate arrives and the exchange is abandoned (WARP has no
  credentials). EAPOL rides a raw packet socket on the managed interface (`radio.EAPOLPort`).
  - No deauthentication, no waiting for a client, no dependency on the active-monitor ACK. WARP
    *is* the client generating the exchange that carries the certificate.
  - The failure diagnosis is a supplicant's now: association refused, no EAP started, or a TLS
    error - reported specifically instead of "no client authenticated".

### Added

- **`warp precheck`** - a host pre-flight to run after a reboot, before `warpd`. It checks the
  adapters are present, none are rfkill-blocked, NetworkManager will not reclaim the interfaces,
  and no stray `wpa_supplicant` is holding a card. Every check is read-only; for the fixable ones
  (a soft rfkill block, NetworkManager managing the Wi-Fi interfaces, a running supplicant) it
  shows the fix and asks the operator to confirm before doing anything - `--yes` applies all,
  `--check-only` just reports, `--json` for automation. Standalone, like `warp radios probe`,
  because it runs before any daemon exists.

### Added (foundation for the same path)

- `nl80211.Connect` / `Disconnect` (`CMD_CONNECT` / `CMD_DISCONNECT`): SSID/BSSID/freq, auth type,
  WPA version, RSN cipher/AKM suites, control-port flags. Request encoding asserted byte-for-byte.
- `radio.AcquireStation`: managed mode + a generated locally-administered MAC + the association,
  with `Release` disconnecting and restoring the card so it is never left joined to a network.
- `radio.EAPOLPort`: an AF_PACKET 802.1X transport (ethertype 0x888E) that runs the EAP-TLS client
  over the association.
- `daemon.connectParamsForAP`: maps an AP to connect parameters (enterprise owns the control port
  for the certificate; PSK is set up to elicit the M1; SAE/WEP refused), unit-tested.

### Fixed

- **The `store: closed` log flood on shutdown.** v0.10.1 stopped the crash by returning `ErrClosed`;
  the final flush then logged it once per row (hundreds of lines). `persistState` and the
  projection export now bail on the first `ErrClosed` quietly.
- **The `NetworkManager is not running` warning on every acquire** is gone: nmcli saying NM is not
  running means there is nothing to release, so it is treated as "nothing to do", not a warning.

### Not done here - validation and scope

- **This is all hardware-gated.** The netlink encoding and the parameter mapping are unit-tested,
  but the association, the packet-socket EAPOL exchange, and the whole harvest need a real adapter
  in managed mode to validate - the standing `internal/radio` gate (see the `hw-probe` skill). Do
  not read "implemented" as "confirmed on the air".
- **PMKID and WPS still use the active-monitor path.** PMKID is the natural next move onto the same
  `AcquireStation` + `EAPOLPort` primitive (associate, read the M1 off the packet socket); it was
  left for its own change rather than bundled here.

---

## [v0.10.1] - 2026-09-09

Three concrete bugs, none of them hardware-gated.

### Fixed

- **The evil twin captured nothing because hostapd could not talk to our RADIUS server.** The
  shared secret was 16 raw random bytes written verbatim into `hostapd.conf` as
  `auth_server_shared_secret=<bytes>`. Random bytes routinely contain a newline, a null, a `#` or
  an `=`, any of which truncates or mangles that config line - so hostapd ended up keyed
  differently from the server, every Access-Request failed its Message-Authenticator
  (`dropping a RADIUS packet with a bad Message-Authenticator`), and no credential was ever
  captured. The secret is now hex-encoded (printable, still 128 bits), and the hostapd config
  generator refuses a secret with any non-printable byte so this cannot silently recur.

- **Daemon crash (SIGSEGV) on shutdown.** The engine's flush loop and the store's `Close` race at
  shutdown: a final `persistState` could run after the database was closed, dereferencing a nil
  `*sql.DB` and panicking (`invalid memory address` in `UpsertStation`). Every store method now
  returns `ErrClosed` instead of touching a nil handle - invariant 8, library code never panics.

- **PMKID solicitation told you the wrong thing.** When no PMKID came back the outcome asserted
  "this access point does not offer PMKID caching - many do not", which is a real finding *only*
  if the association actually completed. The solicit now watches the AP's answers to its
  auth/assoc and reports what happened: the association completed and returned no PMKID (the
  genuine finding), the AP refused it with a status code, it acknowledged auth but never answered
  assoc, or - the common case on an adapter whose active monitor does not ACK - it answered
  nothing at all, which is an injection/ACK limitation, not evidence about PMKID. Invariant 7a.

- **TUI header: the capture sparkline pushed the frame counter off screen, with an intermittent
  "question mark" glyph.** The header card was truncated by a byte-slicing helper that counted
  multi-byte block glyphs and zero-width colour escapes as width, so it clipped the counter early
  and sliced through a glyph mid-rune (the `�` that came and went). The card now truncates by
  display width, the sparkline is capped at a fixed width instead of growing one glyph per poll,
  and on a non-UTF-8 locale it falls back to an ASCII ramp rather than emitting block glyphs the
  terminal cannot draw.

---

## [v0.10.0] - 2026-09-09

Certificate harvesting becomes **passive**, and the capture-thrash regression from the
active-monitor work is fixed. The association-based harvest depended on the card acknowledging
the access point's replies - the one thing that could not be made to work reliably on the borrowed
capture radio. Reading the certificate out of a client's authentication instead sidesteps that
entirely, and it is the method proven against a real capture (`SAMPLES/eap_cert_cap.pcapng`:
subject `CN=radius.waffles.test,…`, extracted end to end by the new parser).

### Changed

- **`warp harvest` now reads the certificate passively instead of associating.** A RADIUS server
  presents its certificate in the clear in the first flight of *every* EAP-TLS handshake, before
  it knows who is asking - so the certificate any real client's authentication puts on the air is
  the one WARP needs. The harvest parks a capture radio on the channel, provokes a reconnect with
  a broadcast deauthentication (the only frame it transmits, on the ordinary passive path), and
  reassembles the server certificate out of the client's authentication as it happens. No
  association, no spoofed station, no dependency on the card acknowledging anything. It is exactly
  what an operator does by hand in Wireshark (`tls.handshake.type == 11`), done automatically.
  - New `internal/eap/harvest.Assembler` reassembles the certificate across the two layers of
    fragmentation a real exchange uses (TLS records, then EAP-TLS fragments), unit-tested and
    validated against a real capture.
  - New `Engine.WatchCert` / `feedCert` assemble certificates on the live capture path, keyed per
    client exchange so two clients authenticating at once cannot corrupt each other's stream, and
    only while a harvest is watching so nothing accumulates otherwise.
  - A network requiring 802.11w is no longer refused: the deauth cannot provoke a reconnect there,
    but the harvest still reads the certificate if a client authenticates on its own, and says so.

### Fixed

- **Capture no longer thrashes while a card is in active monitor.** The v0.9.1 reopen loop raced
  the active-monitor borrow (PMKID solicit, WPS): it reopened the capture socket against the
  interface *mid-reconfiguration*, which was torn down again on the next step, reopening every
  ~500 ms for the length of the job - visible as a flood of "capture interrupted / capture
  reopened" and the symptom behind solicit's "context deadline exceeded". The capture loop now
  waits for the borrow to finish (`SuspendCapture`) before reopening, so a borrow is one clean
  interruption. Passive work (deauth, decloak, the new harvest) never triggered this and is
  unchanged.

- **Deauth against a card that was previously borrowed for active injection.** With the thrash
  gone and harvest off the active-monitor path, the capture radio is no longer left fighting an
  in-flight reopen, which is what had made an ordinary deauth intermittently fail after a harvest
  or solicit had run on the same card.

### Removed

- The association-based harvest path (`associate`, the harvesting supplicant transport, the
  active-monitor borrow in `warp harvest`). Superseded by the passive read above; do not
  reintroduce it. Active monitor remains where a two-way association is genuinely unavoidable -
  PMKID solicitation with no client present, and WPS.

---

## [v0.9.1] - 2026-09-09

Fixes for the active-monitor work in v0.9.0, which broke on contact with real hardware in ways
the offline tests could not show.

### Fixed

- **`set MAC on wlan1: invalid argument`, and the cascade behind it.** Setting the station MAC
  via SIOCSIFHWADDR fails with EINVAL on an interface already in monitor mode - a monitor
  netdev is not Ethernet-typed, and the ioctl rejects an Ethernet address on it. A *borrowed*
  card is already monitor (recon put it there), so every PMKID/harvest/WPS attempt failed at
  the MAC step. The acquire now flips the card to station mode first, sets the MAC, then to
  active monitor - the standard sequence. The restore does the same in reverse.

- **A failed acquisition stranded the adapter down.** When the MAC step failed, the restore
  also failed and left wlan1 administratively down, which then broke everything after it -
  deauth ("interface went down"), channel tuning ("operation not supported"), the injection
  probe. Restore is now resilient: it always brings the interface back up in a working mode,
  even if the MAC could not be put back, and reports what it could not do rather than aborting.

- **Recon capture died permanently the first time a card was borrowed for active injection.**
  The capture loop ran once and exited on error; an active-injection borrow downs the interface
  to change its mode and MAC, which drops the capture socket, so recon went dead for the rest of
  the run - and deauth, which used to only pause hopping, appeared broken as a knock-on. The
  loop now reopens the capture when the interface returns (bounded retry), so a borrow is a
  brief interruption rather than the end of recon.

- **Deauthentication now keeps listening after it stops transmitting.** A client knocked off at
  the end of the transmit window reconnects a few seconds *later*, and its handshake was missed
  because the campaign shut down the instant the last frame went out. Transmission still stops
  at the window (default 20s, capped 60s); capture now runs for a further 12s on the held
  channel. This applies to every campaign - deauth, solicit, decloak.

### Note on two things that are not bugs

- **"injection was inconclusive at startup"** is invariant 7a behaviour, not a regression: many
  drivers do not loop their own transmissions back to the monitor socket, so the probe cannot
  *confirm* injection even when it works. WARP proceeds anyway and says so. Replugging an
  adapter (new phy index) re-runs the probe, which is why it reappeared.

- **A `?` where the header sparkline should be** is the terminal missing the Unicode block
  glyphs (`▁▂▃▄▅▆▇█`), which needs a UTF-8 locale and a font that carries them. Over SSH with
  `LANG=C` they render as replacement characters. `export LANG=C.UTF-8` (or a locale ending
  in `.UTF-8`) fixes it; the values are correct either way.

---

## [v0.9.0] - 2026-09-09

The change that makes PMKID solicitation and certificate harvesting actually complete against
real access points.

### Fixed

- **Injected associations are now acknowledged, so they complete.** This is the root cause
  behind every "harvest did not answer" and every PMKID that never came back. WARP injected an
  authentication/association from a *passive* monitor interface, using a station address no card
  owned - so the access point's response was never ACKed, it retried, and gave up. The symptom
  in the target's own log was exact: `did not acknowledge authentication response`. That is not
  a range or injection problem, and calling it one earlier was wrong.

  The fix is what hcxdumptool and the aircrack fake-auth do: put the transmitting adapter into
  **active monitor mode** (`NL80211_MNTR_FLAG_ACTIVE`) and set its hardware address to the
  station the frames are sent from. The card's firmware then acknowledges the access point
  exactly as a real client would, and the two-way exchange runs to completion. PMKID
  solicitation, certificate harvesting and WPS all go through this path now
  (`daemon.withActiveInjector` → `radio.AcquireActiveMonitor`); broadcast deauthentication and
  decloaking keep the plain path because they need no ACK.

  On a single-adapter kit this reconfigures the capture radio for the length of the burst - a
  brief, deliberate interruption to recon - and restores its mode and MAC afterwards. The
  spoofed address is recorded and put back on release, the same discipline as monitor mode
  itself: a card is never left altered after the engagement.

  Needs a driver that supports active monitor - ath9k, ath9k_htc, mt76 and rt2800usb do, which
  is the pentester's kit. A driver that refuses says so plainly rather than silently falling
  back to a passive monitor that cannot do the job.

- **"1 captured, 1 refused" for a supplicant that captured nothing.** A certificate refusal was
  being appended to the captured-credentials list. Refusals are a *pass* for the client and
  count only in the RADIUS stats now; the captured list holds credentials only.

### Added

- **The certificate wizard's Email field** (`--email`, and a field in both the console and
  browser forms) - the last of eaphammer's certwizard fields that was missing. It goes into the
  subject as the emailAddress OID (IA5, as real CAs emit it) and renders readably in the
  listing.

### Hardware gate

The active-monitor path is written against the nl80211 contract and unit-tested where it can
be, but final confirmation that a given adapter ACKs injected associations and returns an M1 /
completes an EAP-TLS handshake belongs on real hardware - the `hw-probe` and `eap-validate`
gates. Do not report it cleared from a box with no radios.

---

## [v0.8.1] - 2026-09-08

### Added

- **The rogue access point wears the target's BSSID.** A client that has joined a network
  before remembers the address as well as the name, and many prefer or restrict themselves to
  the one they know - an access point with the right ESSID and a stranger's BSSID reads as a
  *new* access point on a familiar network, which is a materially weaker pretext. The address
  is taken from the observed access point with the strongest signal (discovered, never
  supplied); `--keep-own-bssid` opts out for a site with a WIDS or 802.11r where the collision
  is not wanted.

- **Radios can be pinned by hand**, in all three frontends. The channel plan sweeps, which is
  right for finding things and wrong for watching one; every hold in the tool until now was a
  side effect of running an attack and ended when the attack did. `warp radios lock phy1 36`,
  `l` on the console's Radios tab, a channel box in the browser. It stops the adapter *moving*,
  not capturing, and an attack that needs another channel still borrows it and puts it back.
  Refused if the adapter cannot reach the channel, or the regulatory domain disables it.

- **SAE and the other dead ends are explained before airtime is spent on them.** A WPA3-SAE
  handshake is not crackable - the key comes from the dragonfly exchange rather than PBKDF2
  over a passphrase, which is exactly the part hashcat 22000 attacks - and SAE mandates 802.11w
  so the deauthentication that would provoke one is ignored anyway. Soliciting or
  deauthenticating an SAE, open, WEP or enterprise network now says so up front. **Transition
  mode is deliberately not warned about**: the PSK half is still attackable and saying otherwise
  would talk the operator out of a real finding.

- **A certificate wizard in the console**, replacing the prefilled command line that did not
  work: the console's command set never carried `eap cert generate` or its dozen flags, so
  pressing enter closed the prompt and nothing happened. `g` now opens a real form - `↑↓`
  between fields, `⏎` to advance and submit on the last, `ctrl+g` to submit from anywhere,
  `ctrl+u` to clear, `esc` to cancel. It swallows every keystroke while open, so typing an
  organisation name cannot start a Pixie Dust attempt at the letter P.

### Fixed

- **The browser could not deauthenticate a single client.** It could deauthenticate a whole
  access point but not one device, which is backwards - the targeted form is the more precise
  of the two. The client pane now offers it, and explains rather than offering where 802.11w is
  required, where the client is unassociated, or where the network is out of scope.

- **The certificate wizard's fields were wiped every two seconds.** The pane is rebuilt on each
  poll - that is what keeps it live - and anything held only in an input element went with it,
  including whether the panel was open. Field values and open state now live in `S`, so it
  stays open and keeps what was typed.

- **The certificate library offered to prepare certificates for PSK networks.** A certificate is
  only ever presented by the rogue's RADIUS server, so listing every scoped name was offering
  something that could never be used and burying the two networks that mattered. It now lists
  the scoped networks *observed running WPA-Enterprise*, unioned with whatever the library
  already holds.

- **The console's Evil Twin tab did not line up.** `kv()` output starts at column 0 and the
  hand-written prose and lists started at column 2, so headings, values and notes each sat at a
  different margin. One `section()` renderer now indents everything under a heading.

- **A harvested mimic was labelled the weak pretext.** The check compared rendered lipgloss
  styles, which are equal for empty input, so every certificate source compared the same.

- **Nine tabs collapsed straight to bare circled numbers.** On a 110-column terminal that is
  what happened every time, and a row of ①②③ with no words tells an operator nothing. There is
  a middle tier of short names now, and even the narrowest keeps the current tab's name.

- **`EAPStatus.Session` was an exported field of an unexported type**, so a frontend could read
  it but not construct one - which made it impossible to build a fixture for. Exported as
  `daemon.EAPSession`.

- **The lab left dnsmasq running after Ctrl-C.** `cmd_target` ended in `exec hostapd`, and exec
  replaces the shell - taking the cleanup trap with it. dnsmasq would have kept the interface
  addressed and gone on answering DHCP on whatever that adapter was plugged into next.

### Changed

- **A failed harvest reports what the daemon can prove**, rather than listing four things that
  might be wrong. It counts the frames that actually left the injector and the beacons heard
  from the target while transmitting, and uses those to say which case it is: nothing
  transmitted, no capture radio on the channel, the target not audible at all, or - the
  interesting one - heard clearly and transmitted at with no reply, which is injection or
  transmit range and nothing else.

---

## [v0.8.0] - 2026-09-08

The evil twin is a first-class part of the tool rather than a side effect of `eap start`.

### Added

- **A certificate library** (`internal/eap/certs`), reachable from all three frontends. The
  certificate is the pretext - a supplicant deciding whether to hand over credentials is, in
  almost every real case, deciding whether the certificate looks like the one it expects - and
  until now it was whatever the code happened to have: a mimic if a harvest had run, a
  self-signed one otherwise, chosen at the moment the rogue started and invisible until
  afterwards.

  Four sources, ranked: **mimic** (built from a certificate harvested off the air),
  **imported** (a pair produced elsewhere - the client's own CA issuing one for the test is the
  strongest pretext there is), **generated** (from fields you type), **self-signed** (the
  fallback). Whichever is selected goes on the air; the selection is engagement state, so it
  survives a daemon restart and appears in the report. A new certificate is selected
  automatically when it is at least as convincing as the one selected now - harvesting one and
  then having the rogue go on presenting a self-signed certificate because nobody pressed a
  second button was exactly the trap.

- **A certificate wizard**, the eaphammer `--certwizard` equivalent, for when the target cannot
  be harvested but the naming is known from a scoping call or a previous report. Common name,
  organisation, OU, country, state, locality, issuer CN and organisation, SANs, validity and
  key size. `warp eap cert generate` on the console, a form in the browser, and `g` on the
  console's Evil Twin tab drops into the command line with the verb pre-typed.

  The fields are used verbatim. A mimic always carries a distinguishing mark because it is a
  copy of somebody's real certificate; this is what the operator typed, and silently mutating
  typed input would be worse than the risk it guards against. Two guards that are not
  cosmetic: a hostname common name gets a matching SAN (a supplicant with
  `domain_suffix_match` checks the SANs and nothing else), and the issuer never defaults to the
  subject's own name (a certificate issued by an authority with its own name reads as
  self-signed in every viewer).

- **Certificate import**: `warp eap cert import <essid> --cert … --key …`. The pair is validated
  before anything is written, so a mismatched key fails here rather than as the rogue refusing
  to start halfway through an engagement. Certificates after the leaf are treated as the chain
  and presented with it.

- **The lab's target network now runs DHCP.** hostapd authenticates and associates; it does not
  hand out addresses, so a phone completed PEAP, associated, waited, got nothing and dropped
  the network - which looks exactly like an authentication failure and is not one, and Android
  then marks the network bad and stops retrying. `TEST/enterprise-lab.sh target` now brings up
  an address on the interface and runs dnsmasq. Credential capture never needed it - the
  credentials are on the wire during EAP, before an address is requested - but a client that
  cannot stay associated cannot be tested twice.

### Changed

- The rogue's session records the certificate's id, subject and issuer, not just a fingerprint.
  A report saying a supplicant accepted "a certificate" is not a finding; saying it accepted one
  claiming to be the client's own RADIUS server is.
- `warp eap harvest` files its mimic into the library as it completes, so a harvest that
  produces an unusable mimic fails while the operator is still next to the access point rather
  than an hour later when the rogue will not come up.
- The console's Evil Twin tab and the browser's both show the library, mark what is selected,
  and can change it. Console: `↑↓` to move, `enter` to use, `g` to generate, `S`/`X` to start
  and stop.

---

## [v0.7.2] - 2026-09-08

### Fixed

- **Solicitation rate-limited its own rounds.** Making it a campaign in v0.7.1 left the per-AP
  cooldown inside the loop, so round one transmitted and every round after it was skipped with
  "cannot solicit again for 12s" - which looked like a double-click and was the campaign
  refusing itself. The cooldown is now checked once, as the per-action limit it was always
  meant to be, and the campaign drives an unlimited `Attempt`.

- **The adapter flapped between locked and sweeping during a solicit.** The injector was
  acquired per round, so the capture radio was borrowed and released every two seconds - and
  every time it resumed sweeping it walked away from the channel the M1 was about to arrive on.
  It is now acquired once around the whole campaign, as deauthentication and decloaking already
  were.

- **Associations were transmitted blind.** Nothing watched for the access point's answer, so a
  refused key-management suite, a busy access point, a transmitter on the wrong channel and
  injection not working at all all arrived as the same silence twenty seconds later. The access
  point does answer and says why in a status code: `Engine.WatchMgmt` picks that up off the
  capture radio, and certificate harvesting and WPS now report e.g. "association refused:
  invalid AKMP - the key management suite offered is not one this access point runs (status
  43)" instead of guessing. The harvest also mirrors the access point's own RSN element rather
  than a generic 802.1X+CCMP one.

- **The BAND column could not fit what it was rendering.** Four columns wide with
  "2.4 (ax/n/g)" in it. It now grows to twelve where there is room and falls back to the band
  alone where there is not, and the cell renders to whichever width it was given rather than
  being truncated to "2.4 (".

- **The sidebar took width the table needed.** `minTableWidth` was 79 and did not account for
  per-cell padding at all, so on a 120-column terminal the detail pane was granted its full
  third and the access-point table then dropped CH to fit. The channel is not something to
  trade for a detail pane. The pane now narrows to 30 columns before it gives up, which fits
  both exactly.

- **`truncateToWidth` never truncated a string exactly one column too wide** - `range` over a
  string never yields `len(s)` - which put a 25-column line in a 24-column pane. Narrow detail
  panes now stack the label above the value instead of hyphenating words to death.

### Added

- **`?` opens the full key list**, grouped by what each key acts on. The footer only ever had
  room for the handful that apply to the current tab, so `w` to open a walkthrough - one of the
  most useful keys here - was findable by reading the source or by accident. The footer now
  advertises `w` and `?` directly.

- **A Radios tab, in both frontends** (`7` in the console). Per adapter: driver, MAC, bands,
  usable channels, injection state, supported modes, whether AP and monitor run concurrently,
  what it is doing right now, frames and drops, which role it is serving, which roles it can
  serve, and the reason for each one it cannot. The survey radio is marked as pinned, since it
  is the one adapter that is never lent however busy the kit is.

- **An Evil Twin tab, in both frontends** (`8` in the console). What is being impersonated, on
  what channel and adapter, which certificate is on the air and its fingerprint, the RADIUS
  counters, associated clients, and every captured credential with its 5500 line - unredacted.
  A self-signed certificate is called out as the weak pretext with the fix named. Certificate
  refusals are reported as **correct client behaviour and a pass for those devices**, not as a
  failure. When nothing is running it lists the scoped enterprise networks with Clone and Start
  next to each.

- **The browser can start and stop the evil twin from the access-point pane**, and the red
  impersonation banner carries a clearly named `Stop evil twin` button rather than a bare
  "stop".

---

## [v0.7.1] - 2026-09-08

One bug underneath most of it: **every access point's channel was recorded one channel off**,
so every transmitting attack aimed at the wrong frequency.

### Fixed

- **The access point's channel came from our receiver, not from its beacon.** Radiotap reports
  the frequency the *listening* card was tuned to. 2.4 GHz channels overlap by design - a
  20 MHz spacing on a 22 MHz-wide signal - so a beacon from channel 1 is comfortably audible
  while sweeping channel 2, and that is the frequency that got recorded. An AP on 1 was filed
  as 2, one on 6 as 7, one on 10 as 11.

  Every campaign then held the radios one channel off the target and transmitted where nothing
  was listening. That is why solicitation never produced a PMKID, why deauthentication worked
  at one network and not its neighbour, and why the enterprise harvest never saw an EAP
  request. The DS Parameter Set is the access point stating its own channel in its own beacon;
  it is authoritative and it is what the frequency is now derived from. Radiotap still supplies
  the *band*, because channel 6 is 2437 MHz in 2.4 GHz and 5980 MHz in 6 GHz and the number
  alone cannot tell them apart.

- **Solicitation offered a guessed RSN.** The association request always advertised CCMP+PSK
  regardless of what the access point ran. Anything on SAE, transition mode, TKIP or enterprise
  rejects that with an invalid-AKMP status, and the rejection carries no PMKID - indistinguish-
  able from "this access point does not do PMKID". It now mirrors the RSN element the access
  point broadcast, byte for byte.

- **Solicitation was a six-second attempt, not a campaign.** Two association rounds and then it
  gave up, while deauthentication had been a proper campaign since v0.6.0. It now holds the
  channel, retries in rounds for up to `--seconds` (default 20, capped at 60), and stops the
  moment a capture for that access point lands. When nothing comes back it says what was
  actually established rather than concluding the access point has no PMKID to give.

- **Certificate harvesting gave up after one association**, and reported "it may not be
  WPA-Enterprise" - the one explanation the handler had already ruled out. It now retries
  within the window with a fresh station address each round, settles 300 ms after associating
  before sending EAPOL-Start (an access point discards 802.1X frames that arrive before the
  station entry exists), and on failure lists the things actually worth checking. The same
  settle and the same diagnostic went into the WPS exchange.

- **The browser could not broadcast-deauthenticate an access point.** It offered targeted
  deauthentication of a named client and nothing else, so the form that actually provokes a
  handshake - and that the console has had since v0.7.0 - was console-only.

- **The browser could clone an enterprise certificate but not use it.** The access point pane
  had no way to start or stop the evil twin, so the browser could prepare the pretext and not
  run it. It now offers both, says which certificate is about to go on the air, and warns when
  no harvest exists.

- **Detail-pane values were truncated mid-word.** In a 40-column pane "yes - name recovered
  from probe-response" became "yes - name recovered from p" - the cut landing exactly on the
  part carrying the information. Values wrap now, with continuation lines indented under the
  value column, and the action-key line wraps instead of running off the panel.

- **A finished job said only that it had finished.** Pixie Dust, harvest and every campaign
  produce a one-line summary that is now the job's detail and rides in the completion event, so
  the log says what was found rather than that something happened.

### Changed

- **Decloaking no longer requires an operator confirmation.** The requirement was wrong on its
  own terms: a hidden network *may well be in scope*, and there is no way to find out except by
  recovering the name - so asking a human to confirm it first asks them to assert exactly the
  fact the tool is being asked to establish. `scope confirm` goes back to being advisory
  everywhere in WARP, with no exceptions, and invariant 1a is rewritten to match. A veto still
  refuses, a network that already has a name is still refused down this path, 802.11w is still
  refused, and every record states plainly that there was no ESSID to decide on.

- **The BAND column carries the 802.11 generations**: `2.4 (ax/n/g)`, `5 (ac/n/a)`, `2.4 (g)`.
  Derived from the HT/VHT/HE/EHT elements and the rate set, with the band deciding how to read
  them. A radio with no HT at all, still on the floor, is coloured - old radios carry old
  firmware, and that is where the weak WPS and the absent 802.11w live.

---

## [v0.7.0] - 2026-09-08

Four capabilities the dashboard already implied it had, and the storage bug that was hiding
the results of everything else.

### Added

- **Certificate cloning, from the air.** `warp eap harvest <bssid>` (also `warp eap clone`,
  `C` in the console, "Clone certificate" in the browser) associates to a scoped enterprise
  network, answers its EAP identity request with an anonymous outer identity, and runs a TLS
  client handshake exactly as far as the RADIUS server's certificate - then abandons it. The
  abandonment is enforced by TLS itself: the verify callback records the chain and returns an
  error, so the standard library tears the handshake down the instant the certificate arrives.
  No key exchange, no tunnel, no inner method, and no credentials, because the harvesting
  supplicant has none.

  This is what makes the evil twin worth running. A self-signed certificate carrying none of
  the target's naming is refused by every client that shows the user anything; a mimic built
  from the real subject, issuer, SANs, validity, key algorithm and serial is not. The harvest
  is saved to `certs/<essid>/` and reused automatically the next time `warp eap start` runs,
  so restarting the rogue does not mean going back to the client's access point.

- **Every mimic is now provably not the client's certificate.** The generated leaf's common
  name carries a trailing space. It changes no visible glyph at a trust prompt, so
  click-through - the thing being measured - is unaffected; but a certificate in an engagement
  directory that is byte-identical to the client's own, in their naming, is a liability if it
  ever leaks, and "that is not ours" is not a defensible claim about an identical artefact.
  The SANs are *not* marked: they are what a validating client matches on, and marking them
  would break the mimic against exactly the better-configured clients worth reaching.

- **WPS Pixie Dust.** `warp wps <bssid>` (also `warp pixie`, `P` in the console, "Pixie Dust"
  in the browser) runs one WPS registration exchange - associate, four WSC messages,
  disconnect - and recovers the PIN offline. Three weak nonce generators are covered: zero
  nonces, secret nonces that reuse the public enrollee nonce, and a clock-seeded linear
  congruential generator whose seed is recovered from the public nonce. The exchange stops at
  M3; registration never completes and nothing joins the network.

  Online PIN brute force is deliberately **not** implemented. It needs thousands of round
  trips over hours, only works with continuous contact, locks WPS on production hardware and
  fills the client's logs. Pixie Dust needs one association and then arithmetic on the box,
  which is what an engagement with no outbound route actually has.

  An access point whose nonces are sound is recorded as a **pass**, with the ruled-out
  generators named. A report that only lists what broke leaves the reader unable to tell what
  was tested from what was not.

- **Decloaking on demand.** `warp decloak <bssid>`, `u` in the console, and a button in the
  browser. Broadcast deauthentication holds every capture radio on the access point's channel
  until a reassociating client names the network in the clear, and stops the instant it does.

  Authorization works differently here and this is the only place in WARP that it does. A
  cloaked network broadcasts no name, so requiring an ESSID match would make decloaking
  impossible by construction - the tool would refuse to do the one thing that produces the
  fact it needs in order to agree to do it. The decision moves to `scope confirm <bssid>`,
  which is advisory everywhere else and a precondition here, and the audit record says so
  explicitly. It refuses a network that already has a name, a vetoed BSSID, and anything
  requiring 802.11w.

- **Disk usage, everywhere.** The console header, the browser header and `warp status` all
  carry how much the engagement has written and how much room is left, coloured by how full
  the volume is. Past 90% it becomes a banner across both interfaces. A box that fills up
  stops capturing without an error, and nobody re-runs a capture they believe already happened.

### Fixed

- **The engagement directory was empty until the daemon exited.** Fifty access points on
  screen and a zero-byte `bssids.csv` on disk, with nothing recoverable if the box lost power.
  The projections are now regenerated on the state tick, a few seconds behind what is on
  screen, and `observations.csv` - one row per frame heard, millions of them over a long run -
  is appended and synced live by a single owning writer rather than rebuilt or buffered. Full
  rebuilds are for the small one-row-per-device files only, and `ExportCSV` no longer touches
  the file the daemon holds an append handle on.

- **Deauthenticating from the access point list picked one arbitrary client.** Acting on an
  access point means acting on the access point: it is now a broadcast, which is what actually
  provokes a handshake and what an operator means by "deauth this AP". A network whose clients
  WARP had not seen yet could not be deauthenticated at all before. Targeting one device is
  what the Clients tab is for.

- **The rogue AP never found a harvested certificate.** It looked for a metadata file nothing
  wrote. It now reads what the harvester actually saves.

### Changed

- `internal/store` splits its projections by shape: `ObservationLog` appends, `ExportCSV`
  rebuilds. See invariant 6.
- New audit event kind `harvest`, for a certificate or PIN taken off the air.
- `internal/wps` is new and has no external dependencies: Diffie-Hellman over MODP group 5,
  the WPS key derivation, the WSC message layer and the offline recovery are all hand-rolled
  and fully exercised offline, which is the only way any of it could be tested on a box with
  no radios.

---

## [v0.6.0] - 2026-09-08

Active capture actually works now. The headline fix is that a deauthentication was four frames
over eighty milliseconds with nothing listening on the right channel - the reason handshakes
were not being captured.

### Fixed

- **Deauthentication and solicitation are campaigns, not single bursts.** The old shape sent
  four frames in eighty milliseconds and handed the radio straight back. Two things were wrong
  with that: a client does not always leave on the first frame, and the handshake it provokes
  arrives a second or two *later* on the access point's channel, by which time every capture
  radio had resumed sweeping. A campaign now holds **every** capture radio on the target's
  channel, transmits in rounds across a window (20 s by default, capped at 60), and stops the
  instant a handshake for that access point lands.
- **The second adapter was doing nothing.** Pinning only the transmitting radio changes
  nothing on a two-card kit, because the transmitter and the listener are different cards and
  it is the listener that has to be on the right channel. `Engine.HoldChannel` parks all of
  them.
- **A dedicated transmitter was never tuned.** On a two-card kit the injecting adapter had
  just been taken out of managed mode and was left wherever the driver put it - the channel
  plan belongs to the capture radios, and nothing else set it.
- **Injection reported inconclusive on adapters that demonstrably work.** The loopback test
  depended entirely on the driver echoing its own transmissions, which many do not, and two
  *identical* mt76 cards reported differently purely on socket timing. There is now a settle
  delay before the first frame, and a second independent line of evidence: the driver's own
  transmit counter. A counter that advances by the number of frames written proves they left
  the adapter, whatever the monitor socket did.
- Per-burst frames raised from four to eight. One pair is regularly lost to a collision or
  arrives while the client is mid-transmit, and a burst that fails to move it produces a false
  negative that reads as a resilient network.
- **Hunting could not be stopped.** On a one-adapter kit that left recon pinned to a channel
  with nothing the operator could do about it. `h` on the hunted device toggles, `H` stops
  every hunt from anywhere, and the browser's Hunt button becomes Stop hunting.
- The no-signal bar used U+254C, which is missing from many terminal fonts and rendered as a
  replacement box - it looked like a bug in the tool rather than an absence of signal.
- The Credentials tab's empty state had its second line flush against the margin while the
  first was indented.

### Added

- **The enterprise path is reachable.** `internal/eap` was written and unit-tested but
  imported by nothing outside itself - the RADIUS server, PEAP state machine, cert harvesting
  and hostapd controller had no entry point, while the dashboard advertised "rogue AP /
  enterprise credential capture" as an available capability. `warp eap start|stop|status`, RPC
  methods, web routes and a permanent banner in both interfaces now exist.
- Certificates are mimicked from a harvested one when the workspace has it and self-signed
  otherwise, and which was used is recorded on the session and in the audit log - a supplicant
  that accepts a self-signed certificate is a more serious finding than one that accepts a
  convincing mimic.
- **Add to scope from the access point list** (`a`, or a button in the browser). The client
  naming a network on site that was missing from the list is a real situation, and editing
  scope.txt and restarting the daemon mid-walkthrough is not a workable answer. It only ever
  widens, only accepts names WARP has actually heard on the air, writes back to scope.txt, and
  is recorded in the audit log.
- **One line per adapter in both interfaces**, with role, current channel, whether it is
  sweeping or locked, and which bands it can use. A 2.4 GHz-only card will never see the 5 GHz
  half of an estate, and an operator staring at an empty listing needs to know that before
  concluding the network is not there. The capture/idle status moved up to the title line
  beside the clock.
- `TestTheRogueAPRefusesAnUnscopedESSID` exercises invariant 3 through the RPC surface. Until
  the enterprise path was wired the invariant held only because nothing could reach it.
- `warp` names the socket a daemon is actually listening on when the one it was given is
  wrong, instead of reporting "not running" for what is really a typo.
- `--seconds` on `warp psk --deauth` bounds the campaign.
- `TEST/` - a gitignored enterprise lab that builds a certificate authority, a target
  WPA2-Enterprise network on hostapd's built-in EAP server, an engagement, and the attack
  against it. `check` verifies every prerequisite before anything is started. See
  `TEST/README.md`.

### Changed

- **The Handshakes tab is now Credentials**, and carries enterprise credentials alongside PSK
  material. Nothing is redacted: the operator needs the actual value for the report, and
  hiding it only means going to a root-owned file to read the same thing.
- **Deauthenticating an access point is now a broadcast**; naming a station is the targeted
  form, offered from the client list where a specific device is already under the cursor.
  Acting at the access point level means every client, which is what provokes a handshake.

### Not yet implemented

Asked for and deliberately not half-built:

- **WPS attacks.** Pixie Dust and online PIN recovery are their own subsystem - a PIN state
  machine, M1-M7 exchange handling, and a registrar implementation. A stub that looks present
  and does not work would be worse than its absence.
- **Certificate cloning from the air.** The harvester and the mimic generator both exist and
  are unit-tested, but nothing drives them: capturing a target's certificate needs a client
  role that completes an EAP exchange against the real network first. The rogue currently
  presents a self-signed certificate, which an unvalidating supplicant accepts anyway, and
  `warp eap status` says which was used.
- **Decloaking hidden networks on demand.** The machinery is now in place - a broadcast
  campaign that holds a channel is exactly what it needs - but it is not wired to a command.

## [v0.5.0] - 2026-09-08

First tagged release. Phases 1-3 of the design brief are code complete and Phase 4 is partial;
two hardware validation gates remain open (see **Not yet validated** below).

### Added

**Engagement core**

- ESSID scope gate as the single authorization boundary. Any BSSID broadcasting a scoped ESSID
  is authorized for active work; anything else is passive observation only, permanently. BSSIDs
  are always discovered off the air and never configured, enforced by a repo-wide AST audit
  (`internal/scope/adversarial_test.go`).
- Case-insensitive ESSID matching, and *only* case. scope.txt is transcribed by a human from a
  signed document, so an SoW saying `Acme-Corp` authorizes a beacon saying `ACME-CORP`.
  Whitespace, padding, substrings and Unicode homoglyphs all stay out of scope. Every
  authorization records whether the match was byte-exact.
- Site-wide scope (`warp init --all-networks`) for an SoW that covers a facility rather than a
  list. Recorded at init with a written justification that travels with every transmission in
  `events.jsonl`; both frontends carry a permanent banner while it is in force.
- Generic-ESSID acknowledgment: scoped names like `Guest` or `linksys` require an explicit,
  audited acceptance before active work is authorized there.
- Append-only `events.jsonl` audit log, fsynced per record, complete enough to reconstruct
  exactly what was transmitted and when.

**Radio layer**

- nl80211 client over genetlink: wiphy dump with `SPLIT_WIPHY_DUMP`, bands, channels, supported
  interface types, and interface combinations with exact max-flow feasibility.
- Role scheduler with a pinned survey radio, weighted-dwell channel plan, and borrowing so a
  single adapter is a fully working kit - active work shares the capture radio for the length of
  a burst rather than being refused.
- Empirical injection verification at daemon startup. Four states, not three: only a driver that
  *rejects* the frame blocks transmitting work; a driver that accepts it but does not loop it
  back is inconclusive and proceeds with the uncertainty recorded.

**Capture and analysis**

- AF_PACKET capture, hand-rolled radiotap parser, pcapng archive written alongside parsing so a
  parser bug cannot lose an engagement's data.
- 802.11 frame and information-element parsing, RSN/WPA classification, radio fingerprinting,
  BSSID and client tracking.
- PMKID extraction and four-way handshake reconstruction, emitted natively as hashcat 22000.
  Hashes are appended the instant a tuple completes, deduplicated on the full line, and every
  line is self-contained - ESSID and both MACs are in the line, so nothing needed to crack it
  lives only in `warp.db`.
- Handshakes captured from out-of-scope networks are kept as evidence but filed separately in
  `out-of-scope-*.22000`, excluded from the counts and from `warp hashes --lines`. Capture is
  passive and never gated on scope; cracking a neighbour's handshake is unauthorized work.
- Rogue detection: population clustering per scoped ESSID with a tiered, defensible output -
  `determined` for deterministic facts, `evidence` for fingerprint outliers, `unclassified` as
  the default. Never `evil twin`, always `evil twin candidate`.
- Karma responder detection: probe for a randomly generated ESSID that cannot exist and record
  what answers.
- Direction finding with peak-hold, a live readout and an optional audible cue.
- Survey walkthroughs and ranked localization ("strongest walkthrough"), never trilateration.

**Enterprise (Phase 3)**

- Go RADIUS server with a PEAP-MSCHAPv2 state machine and TLS-over-EAP transport.
- Certificate harvesting and mimic generation.
- MSCHAPv2 credentials emitted as hashcat 5500 into `creds/`.
- hostapd rogue AP behind an `APController` interface, beaconing scoped ESSIDs only.

**Interfaces**

- Terminal dashboard: seven live tabs (Overview, Access Points, Clients, Handshakes, Findings,
  Jobs, Log) with a detail sidebar, per-radio sparklines, and single-key actions on the row
  under the cursor - no MAC address is ever typed.
- Browser interface, fully capable rather than read-only: token authentication with a
  constant-time compare and session cookies, self-signed TLS regenerated at every start,
  loopback-only unless explicitly opted out, a strict CSP, SSE event stream, and sortable,
  filterable tables. Served from assets embedded in the binary - no CDN, no build step.
- One RPC surface, three clients. The subcommands, the dashboard and the browser all dispatch
  through the same handlers; a test fails if a method exists without a web route or vice versa.
- Engagement report with an explicit limitations section naming what WARP structurally cannot
  know.
- CSV projections regenerated from sqlite, which is authoritative.

### Fixed

Everything here was found against real hardware or a real browser, and none of it was visible
from the development machine.

- **Radiotap: every RSSI reading was being discarded** on any driver emitting an extended
  present bitmap. The field walk correctly stopped at a field with no known layout, then threw
  away the antenna signal it had already decoded - signal is bit 5 and is read long before
  whatever stops the walk. The symptom was an empty signal column, a hunt with no gradient to
  follow and localization with nothing to rank, with no error anywhere.
- **Recon capture died on the first borrow and never recovered.** On mt76 and similar parts
  monitor is a *software* iftype and sits outside the advertised interface combinations, so the
  scheduler handed out a second monitor "radio" that does not exist. Acquiring it reconfigured
  the one `wlan0` recon was capturing on, downing the interface. A role wanting a mode an
  adapter is already in now borrows the interface instead.
- **Dashboard crash on resize.** `bubbles/table` re-renders on `SetColumns` against rows that
  still have the old cell count, so widening the terminal enough to restore a dropped column
  panicked with an index out of range.
- **Coloured table cells were truncated to fragments of their own escape sequences.**
  `go-runewidth` counts SGR bytes as printable, so a seven-character coloured cell measured
  nineteen columns. The dashboard now renders its own tables through lipgloss.
- **Every inline style in the browser interface was silently dropped.** The CSP is
  `style-src 'self'`, which blocks style attributes outright; signal bars rendered zero-width
  with nothing but a console warning to say why. Styles now go through the CSSOM.
- Table panels were four columns narrower than the tables inside them, clipping the last column
  against the border.
- WPA1 cipher suites use OUI `00:50:F2`, not the IEEE `00:0F:AC` - every WPA1 network was
  classified `unknown`.
- Interface-combination feasibility was order-dependent; replaced with exact max-flow.
- Hunting was gated on scope in the browser interface. It only listens, so it is not gated
  anywhere - tracking down an unaccounted-for transmitter is the entire point, and that device
  is exactly the one that will never be in `scope.txt`.

### Changed

- `EAPOL` is no longer used anywhere an operator can see it. The two products are `PMKID` and
  `HANDSHAKE`, written to `pmkid.22000` and `handshakes.22000`. EAPOL-Key is the frame type a
  WPA-Personal four-way handshake arrives in and is hashcat's own name for mode 22000, but it
  also names the transport WPA-Enterprise carries EAP over - operators read the column,
  concluded the file held uncrackable enterprise captures, and stopped looking at the
  deliverable. The word remains in the parser, where it names the actual protocol.
- `stations` renamed to `clients` throughout the interfaces; `warp stations` remains as an
  alias.
- `MFP` renamed to `PMF` and its values spelled out as `req` / `opt` / `off`. All three 802.11w
  states are findings: required is worth recording, optional is an exposure that depends on the
  client, off is one that does not.
- Access-point listings gained band and associated-client-count columns; client listings gained
  the network name, band, channel and PMF posture, joined by the daemon rather than by each
  frontend separately.
- Hidden networks whose name is recovered are marked as decloaked and raised as a finding.
  `Cloaked` latches independently of `Hidden`, which clears the moment the name is learned.
- Capability messages name an action that actually changes the outcome. The old text pointed at
  `warp radios probe`, which runs in a different process from the daemon and could never have
  helped.
- Dashboard: sortable columns (`o` / `O`), a display pause that does not stop capture (`p`),
  plain-text output for copying over SSH (`y`), and a toggleable detail pane (`v`).

### Removed

- The "ESSID differs in case from the scoped name" finding. Case-insensitive matching is
  deliberate and a case difference on its own is not a finding.

### Not yet validated

Do not treat these as done. Each has a skill carrying the procedure.

- **PEAPv0 inner EAP framing against a real supplicant** (`eap-validate`). WARP omits the Length
  field from inner EAP headers. If that is wrong the tunnel comes up and the exchange stalls
  silently, with no error on either side. It is the one part of the EAP module with no offline
  test.
- **22000 and 5500 output cracked by real hashcat** with a known passphrase
  (`hashcat-validate`). Self-consistent output that does not crack is worthless, and that
  failure only surfaces at the rig.

### Outstanding

TTLS inner methods, hostile portal, native nl80211 AP (Phase 4 by design), and 6 GHz /
WPA3-Enterprise specifics.

[v0.6.0]: https://github.com/waffl3ss/warp/releases/tag/v0.6.0
[v0.5.0]: https://github.com/waffl3ss/warp/releases/tag/v0.5.0
