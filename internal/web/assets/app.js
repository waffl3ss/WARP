/* WARP web interface.
 *
 * Vanilla JS, no framework, no build step, no network fetches beyond this origin. An
 * engagement box in a wiring closet usually has no route to the internet, and a dashboard
 * that needs a CDN is a dashboard that is blank exactly when it is wanted.
 *
 * Every action here maps onto an RPC method the console and the subcommands also use, so the
 * three frontends cannot drift apart.
 */
'use strict';

const S = {
  tab: 'overview',
  data: { status: null, aps: [], stations: [], findings: [], unclassified: [], jobs: [], hashes: { hashes: [] }, hunts: [], eap: {}, radios: [], assignments: [], certs: { networks: {} }, walkthroughs: [] },
  certForm: {},     // wizard field values per network, so a redraw does not wipe them
  pinForm: {},      // channel typed per radio, for the same reason
  chanForm: {},     // channel-selection text typed per radio
  chanChk: {},      // per-radio checkbox overrides {no5, rnd}, so a redraw does not revert a toggle
  walkOpen: {},     // which walkthrough rows are expanded on the overview (default collapsed)
  findOpen: {},     // which finding groups are expanded on the findings tab (persist across polls)
  evidOpen: {},     // which finding Evidence blocks are open (persist across polls)
  walkDevices: {},  // per-walkthrough device lists, fetched lazily when a row is expanded
  precheck: null,   // host system-checks, fetched on demand (not in the poll - it shells out)
  regdomain: null,  // current regulatory domain, fetched once on the radios tab
  regPending: null, // the operator's in-progress country choice, before Apply
  wizardOpen: {},   // which wizard panels are expanded
  certOpen: {},     // which certificate detail panels are expanded (persist across polls)
  eapTarget: '',    // the ESSID picked in the Evil Twin target selector, so 100+ enterprise APs
                    // collapse to one dropdown and one focused panel instead of a wall of cards
  eapCloneBSSID: {}, // per-target: which observed BSSID the operator chose to clone/wear, so the
                     // twin can mirror a specific access point rather than always the strongest
  eapFeedW: 0,      // operator-resized width of the Evil Twin live feed, kept across re-renders
  eapFeedH: 0,      // operator-resized height of the same, so the 2 s poll does not snap it back
  sel: {},          // selected row id per tab
  filter: {},       // search text per tab
  sort: {},         // {key, dir} per tab
  inScopeOnly: false, // one engagement-wide scope filter. The header toggle and every per-tab
                      // checkbox read and write this single flag, so narrowing to scope on the
                      // APs tab narrows the clients, findings and credentials tabs the same way -
                      // an operator sets "in scope only" once and the whole dashboard honours it.
  huntMuted: true,  // hunt audible cue starts muted; the speaker toggle on the hunt bar turns it on
  log: [],
  busy: new Set(),
};

const $ = (s) => document.querySelector(s);
const el = (t, a = {}, ...kids) => {
  const n = document.createElement(t);
  for (const [k, v] of Object.entries(a)) {
    if (k === 'class') n.className = v;
    else if (k === 'html') n.innerHTML = v;
    else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
    // Styles go through the CSSOM, never through a style attribute. The page's CSP is
    // `style-src 'self'`, which blocks style attributes outright - every signal bar came out
    // zero-width and every hand-placed element ignored its layout, with the only evidence a
    // wall of console warnings nobody on site would be looking at. Assigning cssText is not
    // an inline style as far as CSP is concerned, so it applies, and the policy stays strict.
    else if (k === 'style') n.style.cssText = v;
    // Boolean attributes (checked, disabled, selected) are presence-based in HTML: setAttribute
    // ('checked', false) still leaves the attribute present, which renders the box CHECKED. Every
    // checkbox came up ticked and un-ticking it was undone on the next redraw. Drive the DOM
    // *property* instead, which honours true/false, and mirror the attribute only when true.
    else if (typeof v === 'boolean') { n[k] = v; if (v) n.setAttribute(k, ''); }
    else if (v !== null && v !== undefined) n.setAttribute(k, v);
  }
  for (const c of kids.flat()) {
    if (c === null || c === undefined || c === false) continue;
    n.append(c.nodeType ? c : document.createTextNode(String(c)));
  }
  return n;
};

/* ------------------------------------------------------------------- modals */

// modal shows a styled dialog and resolves a Promise with the result, replacing the browser's
// prompt/confirm/alert - those cannot be styled and look exactly like a phishing box on a page
// that is itself asking for credentials. It lives on document.body, outside the render tree, so a
// background poll redraw never disturbs it. Resolves: confirm → true/false; prompt → string/null;
// alert → true.
function modal({ title, message, input, okLabel = 'OK', cancelLabel = 'Cancel', danger = false }) {
  return new Promise((resolve) => {
    let overlay;
    const done = (val) => { overlay.remove(); document.removeEventListener('keydown', onKey); resolve(val); };
    const field = input !== undefined
      ? el('input', { class: 'modal-input', type: 'text', value: input.value || '', placeholder: input.placeholder || '' })
      : null;
    const okBtn = el('button', { class: 'act ' + (danger ? 'danger' : 'primary'),
      onclick: () => done(field ? field.value : true) }, okLabel);
    const buttons = [okBtn];
    if (cancelLabel) buttons.unshift(el('button', { class: 'act', onclick: () => done(field ? null : false) }, cancelLabel));
    const box = el('div', { class: 'modal-box' },
      title ? el('h3', { class: 'modal-title' }, title) : null,
      message ? el('div', { class: 'modal-msg' }, message) : null,
      field,
      el('div', { class: 'modal-actions' }, ...buttons));
    overlay = el('div', { class: 'modal-overlay',
      onclick: (e) => { if (e.target === overlay) done(field ? null : false); } }, box);
    const onKey = (e) => {
      if (e.key === 'Escape') done(field ? null : false);
      else if (e.key === 'Enter' && (field || cancelLabel)) done(field ? field.value : true);
    };
    document.addEventListener('keydown', onKey);
    document.body.append(overlay);
    if (field) { field.focus(); field.select(); }
    else okBtn.focus();
  });
}
const confirmModal = (message, opts = {}) =>
  modal({ message, danger: opts.danger, okLabel: opts.okLabel || 'Confirm', title: opts.title });
const promptModal = (message, value = '', opts = {}) =>
  modal({ message, input: { value, placeholder: opts.placeholder || '' }, okLabel: opts.okLabel || 'OK', title: opts.title });
const alertModal = (message, opts = {}) =>
  modal({ message, okLabel: 'OK', cancelLabel: null, title: opts.title || 'Heads up' });

// Deauthentication campaign sizing. The plumbing has always taken frames-per-burst and a duration;
// this surfaces them so the operator can turn a knock up or down without dropping to the CLI. Both
// are pre-filled with the defaults, so the common case is still one click (Enter confirms), and the
// duration is clamped to 60s here (the daemon enforces the same cap) so more control cannot become a
// sustained outage at a client site. Resolves to {count, seconds} or null on cancel.
const deauthDefaults = { count: 8, seconds: 20, maxCount: 64, maxSeconds: 60 };
function deauthOptionsModal(message, opts = {}) {
  const D = deauthDefaults;
  return new Promise((resolve) => {
    let overlay;
    const done = (val) => { overlay.remove(); document.removeEventListener('keydown', onKey); resolve(val); };
    const clamp = (raw, def, max) => {
      const n = parseInt(raw, 10);
      if (!Number.isFinite(n)) return def;
      return Math.min(max, Math.max(1, n));
    };
    const countIn = el('input', { class: 'modal-input', type: 'number', min: '1', max: String(D.maxCount), value: String(D.count) });
    const secsIn = el('input', { class: 'modal-input', type: 'number', min: '1', max: String(D.maxSeconds), value: String(D.seconds) });
    const submit = () => done({
      count: clamp(countIn.value, D.count, D.maxCount),
      seconds: clamp(secsIn.value, D.seconds, D.maxSeconds),
    });
    const okBtn = el('button', { class: 'act danger', onclick: submit }, opts.okLabel || 'Deauth');
    const box = el('div', { class: 'modal-box' },
      opts.title ? el('h3', { class: 'modal-title' }, opts.title) : null,
      message ? el('div', { class: 'modal-msg' }, message) : null,
      el('div', { class: 'modal-fields' },
        el('label', { class: 'modal-field' },
          el('span', {}, 'Frames per burst'), countIn,
          el('span', { class: 'modal-hint' }, 'default ' + D.count)),
        el('label', { class: 'modal-field' },
          el('span', {}, 'Duration (seconds)'), secsIn,
          el('span', { class: 'modal-hint' }, 'default ' + D.seconds + ', max ' + D.maxSeconds))),
      el('div', { class: 'modal-actions' },
        el('button', { class: 'act', onclick: () => done(null) }, 'Cancel'),
        okBtn));
    overlay = el('div', { class: 'modal-overlay', onclick: (e) => { if (e.target === overlay) done(null); } }, box);
    const onKey = (e) => { if (e.key === 'Escape') done(null); else if (e.key === 'Enter') submit(); };
    document.addEventListener('keydown', onKey);
    document.body.append(overlay);
    countIn.focus(); countIn.select();
  });
}

// textModal shows a monospaced, pre-formatted block with Copy and Close - for output an operator
// wants to read and paste. Copy copies only `text` (the block); `footer`, when given, is rendered
// below the copy area and above the buttons (the manual-extraction command, which is not part of the
// copied evidence).
function textModal(title, text, footer) {
  let overlay;
  const close = () => { overlay.remove(); document.removeEventListener('keydown', onKey); };
  const onKey = (e) => { if (e.key === 'Escape') close(); };
  const box = el('div', { class: 'modal-box modal-wide' },
    el('h3', { class: 'modal-title' }, title),
    el('pre', { class: 'modal-pre' }, text),
    footer || null,
    el('div', { class: 'modal-actions' },
      el('button', {
        class: 'act',
        onclick: async () => {
          try { await navigator.clipboard.writeText(text); toast('ok', 'Copied to clipboard'); }
          catch { toast('deny', 'Copy failed - select the text and copy manually'); }
        },
      }, 'Copy'),
      el('button', { class: 'act primary', onclick: close }, 'Close')));
  overlay = el('div', { class: 'modal-overlay', onclick: (e) => { if (e.target === overlay) close(); } }, box);
  document.addEventListener('keydown', onKey);
  document.body.append(overlay);
}

// cmdLine renders a "get it yourself" command below a copy area (not part of the copied text).
function cmdLine(label, cmd) {
  return el('div', { class: 'modal-cmd' },
    el('div', { class: 'muted' }, label), el('code', {}, cmd));
}

// padTo right-pads a label to a fixed width for the aligned, script-style detail blocks.
function padTo(s, n) { s = String(s); return s.length >= n ? s : s + ' '.repeat(n - s.length); }

// wpaVersion turns an AP's parsed security into a human WPA-version line.
function wpaVersion(sec) {
  switch (sec.class) {
    case 'open': return 'open (no encryption)';
    case 'owe': return 'OWE (enhanced open)';
    case 'wep': return 'WEP';
    case 'wpa_sae': return sec.transition_mode ? 'WPA3-SAE (WPA2/WPA3 transition)' : 'WPA3-Personal (SAE)';
    case 'wpa_enterprise': return 'WPA2-Enterprise (802.1X)';
    case 'wpa3_enterprise_192': return 'WPA3-Enterprise 192-bit (802.1X)';
    case 'wpa_psk':
      if (sec.wpa1) return 'WPA1';
      return sec.transition_mode ? 'WPA2-PSK (WPA2/WPA3 transition)' : 'WPA2-Personal (PSK)';
    default: return sec.class || 'unknown';
  }
}

// decloakDetailText renders the evidence for a recovered hidden-network name: the cloaking, not the
// encryption. That is what the finding is about.
function decloakDetailText(ap, essid) {
  const I1 = '    ';
  const bar = '=========================================================';
  const L = [bar, 'Detailed Cloaking Information for SSID:  ' + (essid || '(unrecovered)'), bar];
  L.push(I1 + 'BSSID: ' + ((ap && ap.bssid) || '?'));
  L.push(I1 + 'Beacon SSID element: <empty> (network beacons itself as hidden)');
  L.push(I1 + 'Recovered name: ' + (essid || '(none yet)'));
  if (ap && ap.channel) L.push(I1 + 'Channel: ' + ap.channel + (ap.band ? ' (' + ap.band + ')' : ''));
  if (ap && ap.last_seen) L.push(I1 + 'Last seen: ' + stamp(ap.last_seen));
  L.push('');
  L.push(I1 + 'SSID cloaking hides the name from a passive scan and nothing else: any client that');
  L.push(I1 + 'associates names the network in the clear, which is how the name above was recovered.');
  return L.join('\n');
}

// manualEvidenceText is the evidence for an operator-marked potential rogue: a plain "manual
// evidence required" block, not the beacon encryption. The operator's judgement is the finding;
// WARP has no packet-level basis to show, so it says exactly that and leaves the slot to fill in.
function manualEvidenceText(ap, essid) {
  const I1 = '    ';
  const bar = '=========================================================';
  const L = [bar, 'Potentially Rogue Device: ' + (essid || (ap && ap.essid) || '(hidden)'), bar];
  if (ap && ap.bssid) L.push(I1 + 'BSSID: ' + ap.bssid);
  if (ap && ap.channel) L.push(I1 + 'Channel: ' + ap.channel + (ap.band ? ' (' + ap.band + ')' : ''));
  L.push('');
  L.push(I1 + 'Manual evidence required.');
  L.push(I1 + 'The operator flagged this device as a potential rogue in the client footprint.');
  L.push(I1 + 'WARP recorded no packet-level basis for it - attach the supporting evidence here.');
  return L.join('\n');
}

// observedDetailText is the fallback evidence for findings that are not about encryption (karma
// responder, evil-twin candidate, unknown device): the observed record, not a cipher dump.
function observedDetailText(ap, essid) {
  const I1 = '    ';
  const bar = '=========================================================';
  const L = [bar, 'Observed device record for: ' + (essid || (ap && ap.essid) || '(hidden)'), bar];
  if (ap) {
    L.push(I1 + 'BSSID: ' + (ap.bssid || '?'));
    if (ap.channel) L.push(I1 + 'Channel: ' + ap.channel + (ap.band ? ' (' + ap.band + ')' : ''));
    if (ap.oui) L.push(I1 + 'Vendor OUI: ' + ap.oui);
    if (ap.has_rssi) L.push(I1 + 'Best signal: ' + ap.best_rssi + ' dBm');
    if (ap.first_seen) L.push(I1 + 'First seen: ' + stamp(ap.first_seen));
    if (ap.last_seen) L.push(I1 + 'Last seen: ' + stamp(ap.last_seen));
  } else {
    L.push(I1 + 'No observed access-point record is joined here.');
  }
  return L.join('\n');
}

// evidencePointer is the one-line "what to look at" that ties a finding to the packet detail below
// it. Falls back to '' (the finding's rationale, shown above the block already, then stands alone).
function evidencePointer(label, ap, essid) {
  const l = (label || '').toLowerCase();
  if (l.indexOf('hidden network name recovered') >= 0) {
    return 'Beacons an empty SSID element yet the name "' + (essid || '?') + '" was recovered: '
      + 'cloaked, not hidden. SSID cloaking is not a security control.';
  }
  if (l.indexOf('transition') >= 0) {
    return 'The AKM list advertises SAE (WPA3) alongside PSK (WPA2): a WPA2/WPA3 transition BSS. '
      + 'The WPA2/PSK side is downgrade-attackable, so the WPA3 upgrade buys nothing here.';
  }
  if (l.indexOf('wep') >= 0) return 'Privacy is set with no RSN element: WEP, trivially recoverable.';
  if (l.indexOf('open network') >= 0) return 'No encryption advertised: clients associate in the clear.';
  if (l.indexOf('tkip') >= 0) return 'The cipher list includes TKIP (WPA1-era), weaker than CCMP.';
  if (l.indexOf('wps enabled and unlocked') >= 0) {
    return 'The beacon advertises WPS and does not report it locked: the registrar exchange is '
      + 'reachable for one offline Pixie Dust attempt.';
  }
  if (l.indexOf('resistant') >= 0) return 'WPS was reachable but the AP resisted offline PIN recovery: a pass.';
  if (l.indexOf('802.11w') >= 0 || l.indexOf('management frame') >= 0) {
    return 'Look at the Management Frame Protection Required/Capable bits below.';
  }
  if (l.indexOf('karma') >= 0) {
    return 'Answered a probe for a network name that cannot exist: it responds to arbitrary probes '
      + '(Pineapple/mana behaviour).';
  }
  if (l.indexOf('evil twin') >= 0) {
    return 'Beacons a scoped name but its radio fingerprint falls outside the fleet cluster '
      + '(see the differences below). Verify physically before acting.';
  }
  if (l.indexOf('pin recovered') >= 0) {
    return 'WPS was reachable and its registration nonces were weak: the PIN and passphrase were '
      + 'recovered offline (on the Credentials tab).';
  }
  if (l.indexOf('potentially rogue device') >= 0) {
    return 'Operator-marked potential rogue device. Manual evidence required - supply it here.';
  }
  if (l.indexOf('psk access point') >= 0 || l.indexOf('otherwise enterprise') >= 0) {
    return 'This BSSID authenticates with a pre-shared key (PSK) while other access points on the '
      + 'same ESSID use 802.1X enterprise - the shape of a misconfiguration or an impostor. Verify '
      + 'physically before acting.';
  }
  return '';
}

// evidenceBlock chooses the right detail block for a finding: cloaking for a recovered hidden name,
// the observed record for rogue/karma findings, and the parsed encryption otherwise.
function evidenceBlock(label, ap, essid) {
  const l = (label || '').toLowerCase();
  if (l.indexOf('potentially rogue device') >= 0) return manualEvidenceText(ap, essid);
  if (l.indexOf('hidden network name recovered') >= 0) return decloakDetailText(ap, essid);
  if (l.indexOf('karma') >= 0 || l.indexOf('evil twin') >= 0 || l.indexOf('unknown device') >= 0) {
    return observedDetailText(ap, essid);
  }
  if (ap && ap.security && (ap.security.class || (ap.security.ciphers || []).length)) {
    return encryptionDetailText(ap, essid);
  }
  return observedDetailText(ap, essid);
}

// encryptionCommand is the tshark one-liner to pull the beacon/probe-response encryption detail for
// an ESSID straight out of a capture - the manual way to get what the popup shows.
function encryptionCommand(essid) {
  return "tshark -r captures/<capture>.pcapng -Y '(wlan.fc.type_subtype==0x0008 || "
    + 'wlan.fc.type_subtype==0x0005) && wlan.ssid=="' + (essid || '') + '"\' -V';
}

// tsharkCipher renders a WARP cipher token the way tshark -V names the suite.
function tsharkCipher(name) {
  if (!name || name.indexOf('/') >= 0) return name || '';           // vendor-specific: OUI/type
  const m = {
    'CCMP-128': 'AES (CCM)', 'CCMP-256': 'AES (CCM-256)',
    'GCMP-128': 'AES (GCM)', 'GCMP-256': 'AES (GCM-256)',
    TKIP: 'TKIP', 'WEP-40': 'WEP-40', 'WEP-104': 'WEP-104',
    'use-group': 'Use group cipher suite',
  };
  return '00:0f:ac (Ieee 802.11) ' + (m[name] || name);
}

// tsharkAKM renders a WARP AKM token as tshark's "<name> (<suite number>)".
function tsharkAKM(name) {
  const m = {
    '802.1X': ['WPA', 1], PSK: ['PSK', 2], 'FT-802.1X': ['FT using 802.1X', 3],
    'FT-PSK': ['FT using PSK', 4], '802.1X-SHA256': ['WPA (SHA256)', 5],
    'PSK-SHA256': ['PSK (SHA256)', 6], SAE: ['SAE (SHA256)', 8],
    'FT-SAE': ['FT using SAE (SHA256)', 9], '802.1X-Suite-B': ['WPA (SuiteB)', 11],
    '802.1X-Suite-B-192': ['WPA (SuiteB-192)', 12], 'FT-802.1X-SHA384': ['FT using 802.1X (SHA384)', 13],
    OWE: ['OWE', 18], 'FT-PSK-SHA384': ['FT using PSK (SHA384)', 19],
  };
  const e = m[name];
  return e ? e[0] + ' (' + e[1] + ')' : name;
}

// encryptionDetailText renders an AP's parsed beacon security the way the reference tshark -V dump
// does - WARP parsed all of it off the air, so no external tool runs. The layout (bit-field lines,
// indentation) deliberately mirrors that output so it reads as packet evidence, not a summary.
function encryptionDetailText(ap, essid) {
  const sec = ap.security || {};
  const open = !sec.class || sec.class === 'open';
  const I1 = '    ';           // top fields
  const I2 = '            ';   // element fields
  const I3 = '                    '; // AKM
  const I4 = '                '; // MFP bits
  const bar = '=========================================================';
  const L = [bar, 'Detailed Encryption Information for SSID:  ' + (essid || ap.essid || '(hidden)'), bar];
  L.push(I1 + 'BSSID: ' + (ap.bssid || '?'));
  if (ap.channel) L.push(I1 + 'Channel: ' + ap.channel + (ap.band ? ' (' + ap.band + ')' : ''));
  if (ap.last_seen) L.push(I1 + 'Last beacon seen: ' + stamp(ap.last_seen));
  L.push(I2 + '.... .... ...' + (open ? '0' : '1') + ' .... = Privacy: '
    + (open ? 'AP/STA cannot support WEP' : 'AP/STA can support WEP'));
  L.push(I2 + 'SSID: ' + (essid || ap.essid || ''));
  if (open) {
    L.push('');
    L.push(I1 + 'WPA Version: ' + wpaVersion(sec) + ' (no RSN/WPA element)');
    return L.join('\n');
  }
  if (sec.group_cipher) L.push(I2 + 'Group Cipher Suite: ' + tsharkCipher(sec.group_cipher));
  if ((sec.ciphers || []).length) {
    L.push(I2 + 'Pairwise Cipher Suite List ' + sec.ciphers.map(tsharkCipher).join(' '));
  }
  for (const a of (sec.akms || [])) L.push(I3 + 'Auth Key Management (AKM) type: ' + tsharkAKM(a));
  const mfp = String(ap.mfp || sec.mfp || '').toLowerCase();
  const required = mfp.indexOf('require') >= 0;
  const capable = required || mfp.indexOf('capab') >= 0 || mfp.indexOf('option') >= 0;
  L.push(I4 + '.... .... .' + (required ? '1' : '0') + '.. .... = Management Frame Protection Required: '
    + (required ? 'True' : 'False'));
  L.push(I4 + '.... .... ' + (capable ? '1' : '0') + '... .... = Management Frame Protection Capable: '
    + (capable ? 'True' : 'False'));
  if (sec.wpa1) {
    L.push(I2 + 'WPA Version: 1 (legacy WPA vendor element also present)');
  }
  L.push(I2 + 'WPS: ' + (sec.wps ? ('enabled (' + (sec.wps_locked ? 'locked' : 'unlocked') + ')') : 'not present'));
  return L.join('\n');
}

/* ---------------------------------------------------------------- transport */

async function api(path, { method = 'GET', body = null, query = null } = {}) {
  let url = path;
  if (query) {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(query)) {
      if (v !== undefined && v !== null && v !== '') q.set(k, JSON.stringify(v));
    }
    if ([...q].length) url += '?' + q.toString();
  }

  const res = await fetch(url, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : null,
    credentials: 'same-origin',
  });

  if (res.status === 401) { showLogin(); throw new Error('not authenticated'); }

  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { /* non-JSON error body */ }

  if (!res.ok) {
    const err = new Error((data && data.error) || text || res.statusText);
    // A scope refusal is a correct outcome, not a malfunction, and is rendered differently.
    err.denied = Boolean(data && data.denied);
    throw err;
  }
  return data;
}

/* -------------------------------------------------------------------- login */

function showLogin() {
  $('#app').classList.remove('on');
  $('#login').style.display = 'grid';
}
function showApp() {
  $('#login').style.display = 'none';
  $('#app').classList.add('on');
}

// Locking the browser session stops nothing: the daemon owns the radios and the jobs, and a
// capture keeps running whether or not anyone is watching it.
$('#logout').addEventListener('click', async () => {
  try { await api('/logout', { method: 'POST' }); } catch { /* the session is going either way */ }
  showLogin();
  $('#token').focus();
});

$('#loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('#loginErr').textContent = '';
  try {
    await api('/login', { method: 'POST', body: { token: $('#token').value.trim() } });
    $('#token').value = '';
    start();
  } catch (err) {
    $('#loginErr').textContent = err.message;
  }
});

/* --------------------------------------------------------------------- tabs */

const TABS = [
  { id: 'overview', label: 'Overview' },
  { id: 'aps',      label: 'Access points', count: () => S.data.aps.length },
  { id: 'stations', label: 'Clients',       count: () => S.data.stations.length },
  { id: 'hashes',   label: 'Credentials',   count: () => (S.data.hashes?.hashes || []).length + (S.data.eap?.captured || []).length + (S.data.hashes?.wps_keys || []).length },
  { id: 'findings', label: 'Findings',      count: () => S.data.findings.length },
  { id: 'jobs',     label: 'Jobs',          count: () => S.data.jobs.length },
  { id: 'radios',   label: 'Radios',        count: () => (S.data.radios || []).length },
  { id: 'eviltwin', label: 'Evil twin' },
  { id: 'log',      label: 'Log' },
];

function renderTabs() {
  const nav = $('#tabs');
  nav.replaceChildren(...TABS.map((t) =>
    el('button', {
      class: S.tab === t.id ? 'on' : '',
      onclick: () => { S.tab = t.id; render(); },
    }, t.label, t.count ? el('span', { class: 'n' }, t.count()) : null)));
}

/* ------------------------------------------------------------------ helpers */

// signal renders RSSI as a bar. Scanning a column of numbers for the strongest signal is
// exactly the work a display should be doing for you.
//
// This is the LIVE reading (the last frame heard), not the peak-ever - a peak that only ever
// climbs latches to max after one close pass and never falls, so an AP not heard in minutes still
// showed full bars. When `stale` is set (the device has not been heard recently) the bar is greyed
// and the age is shown: the last value is kept (it is the honest last measurement) but it is no
// longer presented as a current signal.
function signal(rssi, has, opts = {}) {
  if (!has || rssi === null || rssi === undefined) {
    return el('span', { class: 'sig' },
      el('span', { class: 'bar' }), el('span', { class: 'n muted' }, '-'));
  }
  if (opts.stale) {
    return el('span', { class: 'sig stale', title: 'last heard ' + fmtAge(opts.ageSecs) + ' ago' },
      el('span', { class: 'bar' }, el('i', { style: 'width:100%;background:var(--line)' })),
      el('span', { class: 'n muted' }, rssi));
  }
  const pct = Math.max(0, Math.min(100, ((rssi + 90) / 55) * 100));
  const colour = rssi >= -55 ? 'var(--accent)' : rssi >= -72 ? 'var(--amber)' : 'var(--red)';
  const bar = el('span', { class: 'bar' });
  bar.append(el('i', { style: `width:${pct}%;background:${colour}` }));
  return el('span', { class: 'sig' }, bar, el('span', { class: 'n' }, rssi));
}

// ifnameFor maps a radio id (phyNNN) to its interface name (wlanN) for display - phyNNN is an
// internal handle and must never reach the operator. Falls back to the id if unknown.
function ifnameFor(id) {
  if (!id) return '';
  for (const r of (S.data.radios || [])) if (r.id === id) return r.ifname || id;
  for (const r of ((S.data.status && S.data.status.recon && S.data.status.recon.radios) || [])) {
    if (r.radio_id === id) return r.ifname || id;
  }
  return id;
}

// radioRates holds a short per-radio history of the capture rate (frames gained per poll), so the
// header can draw an activity sparkline like the TUI radio table rather than a flat bar.
const radioRates = {};
const RADIO_SPARK_LEN = 16;

// sampleRadioRates is called once per poll: it turns each adapter's cumulative frame count into a
// per-poll delta and keeps a rolling history. Called from refresh, never from render, so the
// history advances on real polls only.
function sampleRadioRates(status) {
  for (const r of ((status && status.recon && status.recon.radios) || [])) {
    const id = r.radio_id || r.ifname;
    if (!id) continue;
    const frames = r.capture?.frames || 0;
    const h = radioRates[id] || { last: frames, hist: [] };
    const delta = Math.max(0, frames - h.last);
    h.last = frames;
    h.hist.push(delta);
    if (h.hist.length > RADIO_SPARK_LEN) h.hist.shift();
    radioRates[id] = h;
  }
}

// radioSpark draws a per-radio capture-activity sparkline from the rolling rate history.
function radioSpark(id) {
  const hist = (radioRates[id] || {}).hist || [];
  if (hist.length < 2) return el('span', { class: 'fspark' });
  const glyphs = '▁▂▃▄▅▆▇█';
  const max = Math.max(1, ...hist);
  return el('span', { class: 'fspark', title: 'capture activity' },
    hist.map((v) => glyphs[Math.min(glyphs.length - 1, Math.round((v / max) * (glyphs.length - 1)))]).join(''));
}

// fitFontPx picks a card-value font size that keeps a text value inside the card. The default is
// 26px (matching .card .v); longer strings step down so a long walkthrough name does not overrun
// the card edge. An extreme name still wraps (see .card .v.fit), this just keeps the common case
// on one tidy line.
function fitFontPx(s) {
  const n = (s || '').length;
  if (n <= 12) return 26;
  if (n <= 18) return 21;
  if (n <= 26) return 17;
  if (n <= 36) return 14;
  return 12;
}

// humanCount abbreviates a large count: 1234 → 1.2k, 3400000 → 3.4M.
function humanCount(n) {
  if (typeof n !== 'number' || n < 1000) return String(n || 0);
  if (n < 1e6) return (n / 1e3).toFixed(1) + 'k';
  return (n / 1e6).toFixed(1) + 'M';
}

// fmtAge renders a seconds count as a short human age (12s, 3m, 1h).
function fmtAge(secs) {
  if (secs === null || secs === undefined) return '?';
  if (secs < 60) return secs + 's';
  if (secs < 3600) return Math.floor(secs / 60) + 'm';
  return Math.floor(secs / 3600) + 'h';
}

// Security colouring follows exposure, not alphabet: open and WEP are the loud ones.
function secClass(c) {
  if (c === 'open' || c === 'wep') return 'bad';
  if (c === 'wpa_sae' || c === 'owe' || c === 'wpa3_enterprise_192') return 'good';
  if (c === 'wpa_enterprise') return 'info';
  return 'warn';
}
// secClassAP colours by the whole security posture, not just the class: WPA1 and TKIP are as
// deprecated as WEP and get the same loud colour rather than reading like an ordinary WPA2-PSK.
function secClassAP(ap) {
  const sec = ap.security || {};
  if (sec.wpa1 || (sec.ciphers || []).includes('TKIP')) return 'bad';
  return secClass(sec.class);
}
function secLabel(ap) {
  const sec = ap.security || {};
  let s = (sec.class || '').replace(/^wpa_/, '');
  if (s === 'enterprise') s = '802.1X';
  if (s === 'wpa3_enterprise_192') s = '802.1X-192';
  // WPA1 (legacy vendor element, no RSN) reads as plain "psk" otherwise - call it out, since it
  // is a materially weaker posture than WPA2-PSK.
  if (sec.wpa1) s = 'WPA1';
  if ((sec.ciphers || []).includes('TKIP') && s !== 'WPA1') s += '+tkip';
  if (sec.wps) s += '+wps';
  if (sec.transition_mode) s += '+transition';
  return s || '-';
}
// Protected Management Frames (802.11w). Spelled "off" rather than a dash: absent PMF is a
// finding, not a blank, and it is the single fact that decides whether deauthenticating a
// client here will do anything at all.
function pmfCell(m) {
  if (m === 'required') return el('span', { class: 'good', title: '802.11w required - clients cannot be deauthenticated' }, 'req');
  if (m === 'capable') return el('span', { class: 'warn', title: '802.11w offered but not required - clients that do not negotiate it can still be deauthenticated' }, 'opt');
  if (m === 'absent') return el('span', { class: 'bad', title: '802.11w absent - any associated client can be deauthenticated at will' }, 'off');
  return el('span', { class: 'muted', title: 'no RSN element seen yet' }, '?');
}

// networkCell renders a network name, marking one that cloaked its SSID and was decloaked
// anyway. The client usually believes that network is not advertising itself.
function networkCell(ap) {
  // A manual potential-rogue mark colours the name red and takes precedence over the in-scope
  // green: a rogue is the more urgent signal, and it is BSSID-specific, so only the marked row
  // turns red even when siblings on the same ESSID stay green.
  const cls = ap.rogue ? 'bad' : (ap.essid ? (ap.in_scope ? 'good' : '') : 'muted');
  const name = el('span', {
    class: cls,
    ...(ap.rogue ? { title: 'Marked as a potential rogue device by the operator' } : {}),
  }, ap.essid || '<hidden>');
  if (ap.rogue) {
    return el('span', {}, name, el('span', {
      class: 'tag rogue-tag', title: 'Operator-marked potential rogue - manual evidence required',
    }, 'rogue'));
  }
  // A cloaked network whose name has been recovered gets a persistent "hidden" tag, so it is
  // always marked as previously-hidden regardless of how the name came out (probe response,
  // association, decloak). The `cloaked` flag latches once set, so the tag does not vanish when
  // the name appears.
  if (!ap.cloaked || !ap.essid) return name;
  return el('span', {}, name, el('span', {
    class: 'tag hidden-tag',
    title: 'Previously hidden - this network cloaked its name; recovered from '
      + (ap.essid_source || 'observed traffic') + '. SSID cloaking is not a security control.',
  }, 'hidden'));
}
// bandCell abbreviates the band. It matters as much as the channel: a 5 GHz network will not
// be heard from the far end of a floor, and an adapter parked on 2.4 GHz never sees it at all.
function bandCell(band, phy) {
  if (!band) return el('span', { class: 'muted' }, '-');
  const short = band.startsWith('2.4') ? '2.4' : band.startsWith('5') ? '5' : band.startsWith('6') ? '6' : band;
  if (!phy) return el('span', { class: 'dim', title: band }, short);

  // The generations in parentheses: "2.4 (ax/n/g)". The band says where the access point is,
  // the generations say what it is - and a radio with no HT at all, still on the floor, is a
  // finding on sight, so an old one is coloured rather than read past.
  const old = phy === 'g' || phy === 'b' || phy === 'a';
  return el('span', { class: 'dim', title: band + ' · 802.11' + phy.split('/').join(', 802.11') },
    short, el('span', { class: old ? 'warn' : 'muted' }, ' (' + phy + ')'));
}

function scopeCell(ap) {
  if (ap.operator_rejected) return el('span', { class: 'tag warn' }, 'vetoed');
  if (ap.in_scope) return el('span', { class: 'tag good' }, 'in scope');
  return el('span', { class: 'muted' }, 'passive');
}
function tierClass(t) {
  return t === 'determined' ? 'bad' : t === 'evidence' ? 'evid' : t === 'control' ? 'good' : 'muted';
}
// Timestamps are shown in the VIEWER's local time. The daemon emits RFC3339 with its own offset;
// parsing it with Date and formatting in local time converts it to the clock the operator is
// actually looking at (which is what they compare against), regardless of the daemon process's own
// timezone. hhmmss is time only; stamp adds the date (an engagement can run more than a day); day
// is the date only.
function tsParts(iso) {
  if (!iso) return null;
  const d = new Date(iso);
  if (isNaN(d.getTime())) return null;
  const p = (n) => String(n).padStart(2, '0');
  return {
    date: `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`,
    time: `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`,
  };
}
const hhmmss = (iso) => { const p = tsParts(iso); return p ? p.time : '(none)'; };
const stamp = (iso) => { const p = tsParts(iso); return p ? `${p.date} ${p.time}` : '(none)'; };
const day = (iso) => { const p = tsParts(iso); return p ? p.date : '(none)'; };

// elapsed formats how long ago an ISO timestamp was, as a running clock - H:MM:SS over an hour,
// MM:SS under one. Used for the live evil-twin "running for" timer, which updates each poll.
function elapsed(iso) {
  const t = Date.parse(iso);
  if (!iso || Number.isNaN(t)) return '0:00';
  let s = Math.max(0, Math.floor((Date.now() - t) / 1000));
  const h = Math.floor(s / 3600); s -= h * 3600;
  const m = Math.floor(s / 60); s -= m * 60;
  const p2 = (n) => String(n).padStart(2, '0');
  return h ? `${h}:${p2(m)}:${p2(s)}` : `${m}:${p2(s)}`;
}

// seenAge renders how long ago an AP was last heard, compactly (12s, 4m, 2h).
function seenAge(secs) {
  const s = Math.max(0, secs ?? 0);
  if (s < 60) return s + 's';
  if (s < 3600) return Math.floor(s / 60) + 'm';
  return Math.floor(s / 3600) + 'h';
}
// seenCell marks an AP still on the air (active) versus one that has dropped off. WARP never
// discards an AP it has seen, so this is the "currently visible" airodump shows.
function seenCell(ap) {
  const age = seenAge(ap.last_seen_secs);
  return ap.active
    ? el('span', { class: 'good' }, '● ' + age)
    : el('span', { class: 'muted' }, age + ' (gone)');
}

// since is computed here rather than taken from the daemon's `uptime` field, which changes on
// every poll and would defeat the redraw-only-on-change check in refresh().
function since(iso) {
  if (!iso) return '';
  const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m ${s % 60}s`;
  return `${s}s`;
}

function toast(kind, title, msg) {
  const box = $('#toasts');
  // A busy capture can emit events faster than anyone can read them. Cap the stack rather
  // than burying the screen - the Log tab has every one of them in order.
  while (box.children.length >= 4) box.firstElementChild.remove();
  const t = el('div', { class: `toast ${kind}` }, el('b', {}, title), msg || '');
  box.append(t);
  setTimeout(() => t.remove(), kind === 'err' ? 9000 : 5000);
}

// act runs a mutating call, guards against double submission, and reports honestly.
// loadRegDomain fetches the current regulatory domain once for the radios tab (not in the poll).
async function loadRegDomain() {
  try {
    S.regdomain = await api('/api/radios/regdomain');
  } catch { S.regdomain = { cc: '00', is_world: true }; }
  render();
}

// setRegDomain changes the regulatory domain, then reloads the radios so the band labels reflect
// the new transmit rules (5/6 GHz stops being receive-only once a country is set).
async function setRegDomain(cc) {
  if (S.busy.has('reg')) return;
  S.busy.add('reg');
  render();
  try {
    S.regdomain = await api('/api/radios/set-regdomain', { method: 'POST', body: { cc } });
    S.regPending = null; // applied - track the live value again
    toast('ok', 'Regulatory domain set to ' + (S.regdomain.cc || cc));
    await refresh();
  } catch (err) {
    toast(err.denied ? 'deny' : 'err', 'Could not set regulatory domain', err.message);
  } finally {
    S.busy.delete('reg');
    render();
  }
}

// loadPrecheck fetches the host system-checks on demand - it is not in the poll because it shells
// out to rfkill/nmcli/systemctl and should run only when the operator asks.
async function loadPrecheck() {
  try {
    S.precheck = await api('/api/precheck');
  } catch (err) {
    toast('err', 'System check failed', err.message);
  }
  render();
}

// fixPrecheck applies one host fix (unblock rfkill, unmanage in NetworkManager, stop wpa_supplicant)
// and stores the refreshed status the handler returns.
async function fixPrecheck(name) {
  if (S.busy.has('pc:' + name)) return;
  S.busy.add('pc:' + name);
  render();
  try {
    S.precheck = await api('/api/precheck/fix', { method: 'POST', body: { name } });
    toast('ok', name + ' - fix applied');
  } catch (err) {
    toast(err.denied ? 'deny' : 'err', 'Fix failed', err.message);
  } finally {
    S.busy.delete('pc:' + name);
    render();
  }
}

async function act(key, path, body, okMsg) {
  if (S.busy.has(key)) return;
  S.busy.add(key);
  render();
  try {
    await api(path, { method: 'POST', body });
    toast('ok', okMsg);
    await refresh();
  } catch (err) {
    if (err.denied) {
      toast('deny', 'Refused by the scope gate', err.message);
    } else {
      toast('err', 'Failed', err.message);
    }
  } finally {
    S.busy.delete(key);
    render();
  }
}

/* --------------------------------------------------------------------- disk */

// humanBytes matches workspace.HumanBytes on the daemon side: binary units, one decimal below
// 100 so a figure crossing 9.8 → 10.2 → 104 GB does not shift the column it sits in.
function humanBytes(n) {
  if (typeof n !== 'number' || n < 0) return '-';
  if (n < 1024) return n + ' B';
  const units = ['KB', 'MB', 'GB', 'TB', 'PB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
  return (v >= 100 ? v.toFixed(0) : v.toFixed(1)) + ' ' + units[i];
}

// diskStat is the header counter: what this engagement has written, and what is left to write
// it into. The percentage carries the colour and is the filesystem's, not WARP's share of it -
// a disk filled by something else stops the capture just as dead.
function diskStat(d) {
  // No figure rather than a confident 0% when statfs failed or the daemon predates this.
  if (!d || !d.total_bytes) return null;

  const cls = (d.level === 'critical' || d.level === 'warn') ? 'bad'
    : (d.level === 'watch' ? 'warn' : '');

  return el('div', {
    class: 'stat',
    title: `${humanBytes(d.used_bytes)} used of ${humanBytes(d.total_bytes)} on the volume `
      + `holding ${d.path || 'the engagement'}. This engagement has written `
      + `${humanBytes(d.engagement_bytes)}.`,
  },
  el('b', { class: cls }, `${Math.round(d.used_percent ?? 0)}%`),
  el('span', {}, `disk · ${humanBytes(d.engagement_bytes)} used · `
    + `${humanBytes(d.free_bytes)} free`));
}

/* ------------------------------------------------------------------- header */

// huntTrend reads the recent sparkline to tell the operator whether they are getting warmer.
// The last few samples are compared to the ones before them: a rising signal means "closer".
function huntTrend(spark) {
  if (!Array.isArray(spark) || spark.length < 6) return null;
  // Average the most recent few samples against the few before them. Averaging over ~5 samples
  // smooths the several-dB tick-to-tick jitter (so it does not flip constantly), while keeping the
  // window short enough to react as you walk. A 3 dB deadband is the "is this a real move" line.
  const win = Math.min(5, Math.floor(spark.length / 2));
  const newer = spark.slice(-win);
  const older = spark.slice(-2 * win, -win);
  const avg = (a) => a.reduce((s, v) => s + v, 0) / a.length;
  const delta = avg(newer) - avg(older);
  if (delta >= 3) return { arrow: '▲', word: 'warmer', cls: 'good' };
  if (delta <= -3) return { arrow: '▼', word: 'colder', cls: 'bad' };
  return { arrow: '▬', word: 'steady', cls: 'muted' };
}

// huntSpark draws the recent signal history as a unicode bar sparkline, so the gradient is
// visible at a glance while walking rather than having to read a number every step.
function huntSpark(spark) {
  if (!Array.isArray(spark) || !spark.length) return null;
  const glyphs = '▁▂▃▄▅▆▇█';
  const cells = spark.map((r) => {
    const pct = Math.max(0, Math.min(1, (r + 90) / 55));
    return glyphs[Math.min(glyphs.length - 1, Math.floor(pct * (glyphs.length - 1)))];
  });
  return el('span', { class: 'spark' }, cells.join(''));
}

// Speaker icons for the hunt audible toggle. Inline SVG (currentColor) to match the interface's
// monochrome glyphs and stay within the CSP - no external asset, no emoji.
const SPK_ON = '<svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" '
  + 'stroke-width="1.4" stroke-linejoin="round"><path d="M2.5 6h2.2l3-2.3v8.6l-3-2.3H2.5z" '
  + 'fill="currentColor" stroke="none"/><path d="M10 6a3 3 0 0 1 0 4" stroke-linecap="round"/>'
  + '<path d="M12 4.3a5.4 5.4 0 0 1 0 7.4" stroke-linecap="round"/></svg>';
const SPK_MUTED = '<svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" '
  + 'stroke-width="1.4" stroke-linejoin="round"><path d="M2.5 6h2.2l3-2.3v8.6l-3-2.3H2.5z" '
  + 'fill="currentColor" stroke="none"/><path d="M10.5 6l4 4M14.5 6l-4 4" stroke-linecap="round"/></svg>';

// huntSound is the web equivalent of `warp hunt --audible`: a Geiger-style cue that beeps faster as
// the signal strengthens, so an operator can walk a device down by ear. It is muted by default and
// driven by the speaker toggle on the hunt bar. The rate mirrors internal/hunt.beepInterval exactly
// (RSSI clamped to [-90,-30] dBm -> [1500,60] ms), computed from the live hunt state the bar already
// has, so no daemon change is needed. Kept deliberately gentle - a short soft sine blip, not an
// alarm - and silent whenever muted, no hunt is live, or the target has no signal.
const huntSound = {
  ctx: null,
  timer: null,
  ensureCtx() {
    try {
      if (!this.ctx) this.ctx = new (window.AudioContext || window.webkitAudioContext)();
      if (this.ctx && this.ctx.state === 'suspended') this.ctx.resume().catch(() => {});
    } catch { this.ctx = null; }
    return this.ctx;
  },
  frac(rssi) {
    const weak = -90, strong = -30;
    let v = rssi; if (v < weak) v = weak; if (v > strong) v = strong;
    return (v - weak) / (strong - weak);
  },
  intervalMs(rssi) { return 1500 - this.frac(rssi) * (1500 - 60); },
  // The strongest active hunt that currently has signal, or null. One cue, not a chord of them.
  loudest() {
    const hunts = Array.isArray(S.data.hunts) ? S.data.hunts : [];
    let best = null;
    for (const h of hunts) {
      if (!h.has_signal || h.stale) continue;
      if (!best || h.current_rssi > best.current_rssi) best = h;
    }
    return best;
  },
  blip(rssi) {
    const ctx = this.ctx;
    if (!ctx) return;
    const f = this.frac(rssi);
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = 'sine';
    osc.frequency.value = 620 + f * 440; // ~620 Hz far, ~1060 Hz close: closer reads higher + faster
    const t = ctx.currentTime;
    gain.gain.setValueAtTime(0.0001, t);
    gain.gain.exponentialRampToValueAtTime(0.11, t + 0.006); // soft attack, low volume
    gain.gain.exponentialRampToValueAtTime(0.0001, t + 0.05); // ~50 ms blip
    osc.connect(gain).connect(ctx.destination);
    osc.start(t);
    osc.stop(t + 0.06);
  },
  // Self-scheduling loop: the next delay is the beep interval for the current signal, so the rate
  // tracks the walk. Stops itself when no hunt is live; idles quietly when muted or signal-less.
  tick() {
    const hunts = Array.isArray(S.data.hunts) ? S.data.hunts : [];
    if (!hunts.length) { this.timer = null; return; }
    let delay = 400;
    if (!S.huntMuted && this.ctx) {
      const t = this.loudest();
      if (t) { this.blip(t.current_rssi); delay = this.intervalMs(t.current_rssi); }
    }
    this.timer = setTimeout(() => this.tick(), delay);
  },
  start() { if (!this.timer) this.tick(); },
  setMuted(m) {
    S.huntMuted = m;
    if (!m) this.ensureCtx(); // unmuting is a user gesture: create/resume the audio context now
  },
};

// huntMuteButton is the speaker toggle shown on the far right of the hunt bar (only there). Muted by
// default; clicking it (a user gesture, which browsers require to start audio) turns the cue on.
function huntMuteButton() {
  return el('button', {
    class: 'hunt-mute' + (S.huntMuted ? ' muted' : ''),
    'aria-label': S.huntMuted ? 'Unmute the hunt audible cue' : 'Mute the hunt audible cue',
    title: S.huntMuted
      ? 'Audible cue off - click to hear the signal (beeps faster as you get closer)'
      : 'Audible cue on - click to mute',
    html: S.huntMuted ? SPK_MUTED : SPK_ON,
    onclick: () => { huntSound.setMuted(!S.huntMuted); renderHunts(); },
  });
}

// renderHunts paints the live hunt banner. Direction finding is done while walking, watching one
// number, so this owns the top of the screen: a big live RSSI, a warmer/colder trend, the peak
// hold, a sparkline, and the locked channel/radio that confirm WARP is parked on the target.
// It is refreshed on a fast timer (huntPoll) while a hunt is live, not just the 2s page poll.
function renderHunts() {
  const hb = $('#hunts');
  if (!hb) return;
  const hunts = Array.isArray(S.data.hunts) ? S.data.hunts : [];
  hb.replaceChildren(...hunts.map((h) => {
    const name = (h.target?.addr || '') + (h.target?.essid ? ' ' + h.target.essid : '');
    const lock = h.target && h.target.channel
      ? el('span', { class: 'lock', title: 'channel-locked on the target' },
        `ch${h.target.channel}${h.target.radio_id ? ' · ' + ifnameFor(h.target.radio_id) : ''}`)
      : null;
    const stopBtn = el('button', {
      class: 'act tiny',
      onclick: () => act('huntstop:' + h.target?.addr, '/api/hunt/stop',
        { addr: h.target?.addr }, 'Hunt stopped'),
    }, 'stop');

    if (!h.has_signal) {
      return el('div', { class: 'hunt quiet' },
        el('b', {}, '◎ HUNTING ' + name), lock,
        el('span', {}, ' no frames yet - the target may have gone quiet, or be on another channel'),
        stopBtn, huntMuteButton());
    }
    const trend = huntTrend(h.sparkline);
    return el('div', { class: 'hunt' + (h.stale ? ' stale' : '') },
      el('b', {}, '◎ HUNTING ' + name), lock,
      el('span', { class: 'big-rssi' }, `${h.current_rssi}`, el('i', {}, ' dBm')),
      signal(h.current_rssi, true),
      trend ? el('span', { class: 'trend ' + trend.cls }, `${trend.arrow} ${trend.word}`) : null,
      huntSpark(h.sparkline),
      el('span', { class: 'peak' }, h.has_peak ? `peak ${h.peak_rssi} dBm` : ''),
      el('span', { class: 'rate' }, `${Math.round(h.packets_per_sec || 0)}/s`),
      stopBtn, huntMuteButton());
  }));

  // Drive the audible cue while a hunt is live (it self-stops when none remain, and stays silent
  // while muted). Muting is per-viewer and never transmits - it only decides whether this browser
  // makes a sound.
  if (hunts.length) huntSound.start();
}

// renderWalkBanner shows the open walkthrough across every tab - its name, how long it has run,
// what it has heard so far, and a stop button - so an operator always knows a pass is being
// recorded and can end it from anywhere, mirroring the hunt banner.
function renderWalkBanner() {
  const wb = $('#walkbanner');
  if (!wb) return;
  const open = (S.data.walkthroughs || []).find((w) => !w.implicit && !w.end_ts);
  if (!open) { wb.replaceChildren(); return; }
  const secs = Math.max(0, Math.round((Date.now() - new Date(open.start_ts).getTime()) / 1000));
  wb.replaceChildren(el('div', { class: 'walk-live' },
    el('b', {}, '⦿ WALKTHROUGH ' + open.name),
    el('span', { class: 'meta' }, fmtAge(secs)),
    el('span', { class: 'meta' }, `${open.aps ?? 0} APs · ${open.clients ?? 0} clients`),
    el('button', {
      class: 'act tiny',
      onclick: () => act('walkend', '/api/walkthrough/end', null, 'Walkthrough ended'),
    }, 'stop')));
}

function renderHeader() {
  const st = S.data.status;
  if (!st) return;

  // The build line, filled in once the daemon has said which version is running. Faint and
  // out of the way: findable if looked for, invisible while working.
  const credit = $('#credit');
  credit.textContent = [st.version, st.author || '@waffl3ss'].filter(Boolean).join(' · ');
  // The commit is what traces a finding back to the code that produced it, but it is not
  // something anyone reads while working - it goes in the tooltip.
  credit.title = 'WARP ' + [st.version, st.commit && '(' + st.commit + ')']
    .filter(Boolean).join(' ') + ' - Wireless Assessment & Rogue Platform';

  const pill = $('#reconPill');
  const live = st.recon?.running;
  pill.textContent = live ? 'CAPTURING' : 'IDLE';
  pill.className = 'pill ' + (live ? 'live' : 'idle');

  // Capture toggle in the top bar, so it is reachable from any tab rather than only the overview.
  const cap = $('#captureBtn');
  cap.textContent = live ? 'Stop capture' : 'Start capture';
  cap.className = 'act tiny' + (live ? ' danger' : '');
  cap.onclick = () => act('recon', live ? '/api/recon/stop' : '/api/recon/start', null,
    live ? 'capture stopped' : 'capture started');

  // Engagement-wide in-scope toggle, immediately left of the lock. A red/green sliding switch,
  // the same component as the per-adapter on/off toggles on the Radios tab, so it reads at a glance
  // as something you flip. It drives the one S.inScopeOnly flag the per-tab "in scope only"
  // checkboxes also read and write, so flipping it narrows the APs, clients, findings and
  // credentials tabs together. Green/on = in-scope only; red/off = every observed network.
  const scopeBtn = $('#scopeBtn');
  scopeBtn.className = 'toggle header-scope ' + (S.inScopeOnly ? 'is-on' : 'is-off');
  scopeBtn.setAttribute('role', 'switch');
  scopeBtn.setAttribute('aria-checked', S.inScopeOnly ? 'true' : 'false');
  scopeBtn.title = S.inScopeOnly
    ? 'In-scope only is ON - every tab is narrowed to the SoW scope. Click to show everything.'
    : 'In-scope only is OFF - every observed network is shown. Click to narrow to the SoW scope.';
  scopeBtn.replaceChildren(
    el('span', { class: 'toggle-label' }, 'IN SCOPE'),
    el('span', { class: 'toggle-track' }, el('span', { class: 'toggle-knob' })));
  scopeBtn.onclick = () => { S.inScopeOnly = !S.inScopeOnly; render(); };

  // One row per adapter. On a multi-card kit the operator's first question is which card is
  // sweeping, which is transmitting, and what channel each is on - that does not fit on a
  // shared line.
  // Per-radio capture activity - a sparkline of the recent frame rate (like the TUI radio table)
  // plus the running frame count, so it is obvious at a glance which card is actually pulling frames.
  const radioList = st.recon?.radios || [];
  $('#radios').replaceChildren(...radioList.map((r) => {
    const frames = r.capture?.frames || 0;
    return el('div', { class: 'radio' },
      // Interface name only - the phy index is an internal handle, not what the operator tracks.
      el('span', { class: 'ifn' }, r.ifname || r.radio_id || ''),
      el('span', { class: 'role' }, r.role || ''),
      el('span', {
        class: 'ch' + (r.locked ? ' warn' : ''),
        title: r.locked
          ? 'parked on this channel for a campaign or a hunt'
          : 'sweeping the channel plan',
      }, r.channel ? `CH ${r.channel} ${r.locked ? 'lock' : 'sweep'}` : 'CH -'),
      el('span', { class: 'muted bands' }, r.bands || ''),
      radioSpark(r.radio_id || r.ifname),
      el('span', { class: 'muted frames' }, humanCount(frames) + ' frames'),
      r.capture?.dropped ? el('span', { class: 'warn' }, `${r.capture.dropped} dropped`) : null);
  }));

  const stat = (label, v, cls) =>
    el('div', { class: 'stat' }, el('b', { class: cls || '' }, v), el('span', {}, label));

  // Recovered-credential counters for the two attacks whose whole point is a credential: WPS
  // passphrases/PINs and evil-twin (enterprise) captures. Both are deliverables, so they are
  // coloured 'good' the moment there is one.
  const wpsCount = (S.data.hashes?.wps_keys || []).length;
  const eapCount = (S.data.eap?.captured || []).length;

  $('#stats').replaceChildren(
    stat('APs', st.recon?.aps ?? 0),
    stat('clients', st.recon?.stations ?? 0),
    stat('findings', S.data.findings.length, S.data.findings.length ? 'warn' : ''),
    stat('pmkid', st.pmkid_hashes ?? 0, st.pmkid_hashes ? 'good' : ''),
    stat('handshakes', st.handshake_hashes ?? 0, st.handshake_hashes ? 'good' : ''),
    stat('wps', wpsCount, wpsCount ? 'good' : ''),
    stat('evil twin', eapCount, eapCount ? 'good' : ''),
    stat('jobs', st.running_jobs ?? 0),
    diskStat(st.disk),
  );

  // Past 90% this stops being a coloured number and becomes a line across the screen. A box
  // that fills up stops capturing without an error, and nobody re-runs a capture they believe
  // already happened.
  const dk = $('#disk');
  const disk = st.disk || {};
  if (disk.level === 'critical') {
    dk.replaceChildren(
      el('b', {}, `DISK ${(disk.used_percent ?? 0).toFixed(1)}% FULL`),
      ` - ${humanBytes(disk.free_bytes)} left. Capture will stop without an error. `
      + `Move ${humanBytes(disk.engagement_bytes)} of engagement data off the box, `
      + 'or free space now.');
  } else {
    dk.replaceChildren();
  }

  // A site-wide scope is not a degradation, it is what this engagement is authorized to do -
  // and it must be impossible to be looking at this screen and not know it is in force.
  const sw = $('#sitewide');
  if (st.site_wide_scope) {
    sw.replaceChildren(
      el('b', {}, 'SITE-WIDE SCOPE'),
      ' - every named network this kit can hear is authorized for active work. ',
      el('span', { class: 'why' }, st.site_wide_justification || ''));
  } else {
    sw.replaceChildren();
  }

  renderHunts();
  renderWalkBanner();

  const eap = S.data.eap || {};
  const eb = $('#eap');
  if (eap.running && eap.session) {
    // Build the child list and drop the empty slots before handing it to replaceChildren: unlike
    // el(), replaceChildren stringifies a null argument to the text "null" and appends it - which
    // is where the stray "null" after the capture count came from.
    eb.replaceChildren(...[
      el('b', {}, '◆ IMPERSONATING ' + eap.session.essid),
      el('span', {}, `ch${eap.session.channel} · ${eap.session.ifname}`),
      el('span', { class: 'why' }, 'certificate: ' + eap.session.certificate_source),
      el('span', {}, `${(eap.captured || []).length} captured`),
      eap.stats && eap.stats.certificate_refused
        // The correct client behaviour. Shown so it is not read as a fault in the tool.
        ? el('span', { class: 'why' }, `${eap.stats.certificate_refused} refused the certificate`)
        : null,
      // Right-aligned group: the running timer sits immediately to the left of the Stop button.
      // Both live in one container so the timer stays pinned beside Stop (the button alone used to
      // float right on its own, leaving the timer stranded by the capture count).
      el('div', { class: 'eap-right' },
        eap.session.started
          ? el('span', { class: 'eap-timer', title: 'how long the evil twin has been running' },
            '⏱ ' + elapsed(eap.session.started))
          : null,
        el('button', {
          class: 'act danger',
          title: 'Tear down the rogue access point and release the radio. Captured credentials '
            + 'are kept.',
          onclick: () => act('eapstop', '/api/eap/stop', null, 'Enterprise capture stopped'),
        }, 'Stop evil twin')),
    ].filter(Boolean));
  } else {
    eb.replaceChildren();
  }

  // Anything blocking or degrading work belongs on screen, not behind a menu.
  const warn = [];
  for (const e of st.pending_acknowledgments || []) {
    warn.push(`"${e}" is a generic network name and is unacknowledged - active work there is refused`);
  }
  if (st.recon?.handshake?.pending_essid) {
    warn.push(`${st.recon.handshake.pending_essid} hash(es) held pending an ESSID`);
  }
  for (const c of st.capabilities || []) {
    if (!c.available && c.reason) warn.push(`${c.name}: ${c.reason}`);
  }
  $('#banner').textContent = warn.join('   ·   ');
}

/* -------------------------------------------------------------------- table */

// table builds a sortable, filterable table and wires row selection.
function table(tabId, cols, rows, idOf, opts = {}) {
  const f = (S.filter[tabId] || '').toLowerCase();
  let view = rows;
  if (f) {
    view = rows.filter((r) => cols.some((c) => String(c.text ? c.text(r) : '').toLowerCase().includes(f)));
  }

  const sort = S.sort[tabId];
  if (sort) {
    const col = cols.find((c) => c.key === sort.key);
    if (col && col.sortVal) {
      view = [...view].sort((a, b) => {
        const x = col.sortVal(a), y = col.sortVal(b);
        const c = x < y ? -1 : x > y ? 1 : 0;
        return sort.dir === 'desc' ? -c : c;
      });
    }
  }

  if (!view.length) {
    return el('div', { class: 'empty' },
      el('b', {}, f ? 'Nothing matches that filter.' : 'Nothing here yet.'),
      f ? 'Clear the filter to see everything.' : '');
  }

  const head = el('tr', {}, ...cols.map((c) =>
    el('th', {
      onclick: () => {
        if (!c.sortVal) return;
        const cur = S.sort[tabId];
        S.sort[tabId] = (cur && cur.key === c.key)
          ? { key: c.key, dir: cur.dir === 'asc' ? 'desc' : 'asc' }
          : { key: c.key, dir: 'asc' };
        render();
      },
    }, c.label, sort && sort.key === c.key ? el('span', { class: 'dir' }, sort.dir === 'asc' ? ' ▲' : ' ▼') : null)));

  const body = view.map((r) => {
    const id = idOf(r);
    return el('tr', {
      class: S.sel[tabId] === id ? 'sel' : '',
      // A drag to select text for copying ends in a click on the row; without this guard that
      // click re-rendered the table and wiped the selection the operator was about to copy.
      onclick: () => { if (hasSelection()) return; S.sel[tabId] = id; render(); },
    }, ...cols.map((c) => {
      const cell = el('td', { class: c.wrap ? 'wrap' : '' });
      const v = c.cell(r);
      cell.append(v && v.nodeType ? v : document.createTextNode(v ?? ''));
      return cell;
    }));
  });

  return el('table', opts.sticky ? { class: 'sticky' } : {}, el('thead', {}, head), el('tbody', {}, ...body));
}

function toolbar(tabId, extra = []) {
  return el('div', { class: 'toolbar' },
    el('input', {
      type: 'search', placeholder: 'filter…', value: S.filter[tabId] || '',
      'data-fkey': 'filter:' + tabId,
      oninput: (e) => { S.filter[tabId] = e.target.value; render(); },
    }),
    ...extra);
}

/* --------------------------------------------------------------------- tabs */

// walkDevicesTable renders the roll for one expanded walkthrough, fetched lazily - access points
// and client stations in separate tables, since they answer different questions (what networks
// were here vs. what devices were here and what they were talking to).
function walkDevicesTable(id) {
  const devs = S.walkDevices[id];
  if (devs === undefined) return el('div', { class: 'muted', style: 'padding:8px 12px' }, 'Loading…');
  if (!devs.length) return el('div', { class: 'muted', style: 'padding:8px 12px' }, 'Nothing was heard during this walkthrough.');

  const aps = devs.filter((d) => d.is_ap);
  const clients = devs.filter((d) => !d.is_ap);

  const apTable = aps.length ? el('div', {},
    el('div', { class: 'walk-sub-h' }, `Access points (${aps.length})`),
    el('table', { class: 'banded sub' },
      el('thead', {}, el('tr', {}, el('th', {}, 'BSSID'), el('th', {}, 'Ch'), el('th', {}, 'Network'))),
      el('tbody', {}, ...aps.map((d) => el('tr', {},
        el('td', { class: 'mono' }, d.bssid),
        el('td', {}, d.channel || '-'),
        el('td', {}, d.essid || el('span', { class: 'muted' }, '(hidden/unknown)'))))))) : null;

  const clientTable = clients.length ? el('div', { class: 'walk-clients' },
    el('div', { class: 'walk-sub-h' }, `Clients (${clients.length})`),
    el('table', { class: 'banded sub' },
      el('thead', {}, el('tr', {}, el('th', {}, 'MAC'), el('th', {}, 'Beaconing APs'))),
      el('tbody', {}, ...clients.map((d) => el('tr', {},
        el('td', { class: 'mono' }, d.bssid),
        el('td', {}, d.essid || el('span', { class: 'muted' }, '-'))))))) : null;

  return el('div', {}, apTable, clientTable);
}

// toggleWalk expands/collapses a walkthrough row, fetching its device roll the first time.
async function toggleWalk(id) {
  const open = !S.walkOpen[id];
  S.walkOpen[id] = open;
  render();
  if (open) await loadWalkDevices(id); // always refetch, so a re-expand shows what has been added
}

// loadWalkDevices fetches (or refreshes) one walkthrough's device roll.
async function loadWalkDevices(id) {
  try {
    const devs = await api('/api/walkthrough/devices', { query: { id } });
    S.walkDevices[id] = Array.isArray(devs) ? devs : [];
  } catch { if (S.walkDevices[id] === undefined) S.walkDevices[id] = []; }
  render();
}

// refreshOpenWalkDevices re-fetches the device roll for any expanded walkthrough, so an open one
// keeps showing what recon is still adding. Called from the poll.
function refreshOpenWalkDevices() {
  for (const id of Object.keys(S.walkOpen)) {
    if (S.walkOpen[id]) loadWalkDevices(Number(id));
  }
}

// walkthroughsCard renders the walkthrough log on the overview: one row per pass with its name,
// duration, the APs and clients heard while it was open, its dedicated pcap, and a delete button
// for a failed pass. Each row expands (default collapsed) to the BSSID/ESSID roll of everything
// heard during that specific pass. Nothing is shown when no walkthrough has ever been started - a
// closet deployment where nobody walked has none, and that is the honest empty state.
function walkthroughsCard() {
  const wts = (S.data.walkthroughs || []).filter((w) => !w.implicit);
  if (!wts.length) return null;

  const dur = (w) => {
    const end = w.end_ts ? new Date(w.end_ts).getTime() : Date.now();
    const secs = Math.max(0, Math.round((end - new Date(w.start_ts).getTime()) / 1000));
    return fmtAge(secs);
  };

  const rows = wts.slice().reverse().flatMap((w) => {
    const open = !!S.walkOpen[w.id];
    const head = el('tr', { class: 'walk-row' + (open ? ' open' : '') },
      el('td', { class: 'walk-name', onclick: () => toggleWalk(w.id) },
        el('span', { class: 'caret' }, open ? '▾' : '▸'), ' ', w.name,
        w.end_ts ? null : el('span', { class: 'tag good', style: 'margin-left:6px' }, 'open')),
      el('td', { onclick: () => toggleWalk(w.id) }, dur(w)),
      el('td', { class: 'num', onclick: () => toggleWalk(w.id) }, w.aps ?? 0),
      el('td', { class: 'num', onclick: () => toggleWalk(w.id) }, w.clients ?? 0),
      el('td', { class: 'mono', title: w.pcap_path || '' },
        w.pcap_path ? w.pcap_path.split('/').pop() : '-'),
      el('td', {}, el('button', {
        class: 'act tiny danger',
        title: 'Delete this walkthrough and its pcap/summary. Observations are kept - they belong to the engagement.',
        onclick: () => {
          confirmModal('Its pcap and summary are removed. Observations are kept.', {
            title: 'Delete walkthrough "' + w.name + '"?', okLabel: 'Delete', danger: true,
          }).then((ok) => {
            if (ok) act('walkdel:' + w.id, '/api/walkthrough/delete', { id: w.id }, 'Walkthrough deleted');
          });
        },
      }, 'Delete')));
    if (!open) return [head];
    return [head, el('tr', { class: 'walk-detail' }, el('td', { colspan: 6 }, walkDevicesTable(w.id)))];
  });

  return el('div', { style: 'margin-bottom:22px' },
    el('h1', { class: 'section' }, 'Walkthroughs'),
    el('table', { class: 'banded', style: 'margin-top:8px' },
      el('thead', {}, el('tr', {},
        el('th', {}, 'Name'), el('th', {}, 'Duration'),
        el('th', { class: 'num' }, 'APs'), el('th', { class: 'num' }, 'Clients'),
        el('th', {}, 'Capture'), el('th', {}, ''))),
      el('tbody', {}, ...rows)));
}

// downloadBlob triggers a browser download of in-memory data. Used for the report/CSV exports: the
// daemon also writes the files server-side (except the transient zip), this hands a copy to the
// operator's laptop, which over an SSH forward is not where the engagement directory lives.
function downloadBlob(name, data, type) {
  const blob = new Blob([data], { type: type || 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = el('a', { href: url, download: name });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// b64ToBytes decodes base64 (the daemon returns the zip that way over JSON-RPC) into a byte array.
function b64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

// dlName prefixes a download filename with the engagement/workspace name, so files from different
// engagements do not collide in a downloads folder.
function dlName(base) {
  const p = (S.data.status && S.data.status.workspace) || '';
  const ws = (p.split('/').filter(Boolean).pop() || 'warp').replace(/[^A-Za-z0-9._-]/g, '-');
  return ws + '-' + base;
}

// exportBundle regenerates the CSV/netxml projections server-side and downloads them as one zip.
// The daemon builds the zip in memory and never saves it; the individual projections persist.
async function exportBundle() {
  if (S.busy.has('export')) return;
  S.busy.add('export');
  try {
    const res = await api('/api/export/bundle', { method: 'POST' });
    const base = (res.filename || 'projections.zip').replace(/^warp-/, '');
    downloadBlob(dlName(base), b64ToBytes(res.zip_base64 || ''), 'application/zip');
    toast('ok', `Projections regenerated and downloaded (${res.files || 0} files)`);
  } catch (e) { toast('deny', 'Export failed: ' + ((e && e.message) || e)); } finally { S.busy.delete('export'); }
}

// writeReportDownload writes report.md server-side and downloads a copy.
async function writeReportDownload() {
  if (S.busy.has('report')) return;
  S.busy.add('report');
  try {
    const res = await api('/api/report', { method: 'POST' });
    if (res && res.markdown) downloadBlob(dlName('report.md'), res.markdown, 'text/markdown');
    toast('ok', 'Report written to report.md and downloaded');
  } catch (e) { toast('deny', 'Report failed: ' + ((e && e.message) || e)); } finally { S.busy.delete('report'); }
}

// exportReportJSON writes both JSON report variants server-side and downloads the chosen one.
async function exportReportJSON(scoped) {
  const key = 'reportjson';
  if (S.busy.has(key)) return;
  S.busy.add(key);
  try {
    const res = await api('/api/report/export', { method: 'POST', body: { scoped } });
    const data = (res && res.report) || res;
    downloadBlob(dlName(scoped ? 'report-in-scope.json' : 'report.json'),
      JSON.stringify(data, null, 2), 'application/json');
    toast('ok', 'JSON report written and downloaded (' + (scoped ? 'in scope' : 'all') + ')');
  } catch (e) { toast('deny', 'Export failed: ' + ((e && e.message) || e)); } finally { S.busy.delete(key); }
}

function paneOverview() {
  const st = S.data.status;
  if (!st) return el('div', { class: 'empty' }, 'Loading…');

  const card = (k, v, m, opts) => el('div', { class: 'card' },
    el('div', { class: 'k' }, k),
    // A text value (a walkthrough name) can be long; step the font size down by length so it stays
    // inside the card instead of running past its edge, and let an extreme one wrap rather than clip.
    el('div', (opts && opts.fit)
      ? { class: 'v fit', style: 'font-size:' + fitFontPx(String(v)) + 'px' }
      : { class: 'v' }, v),
    m ? el('div', { class: 'm' }, m) : null);

  const caps = (st.capabilities || []).map((c) => {
    const mark = !c.available ? el('span', { class: 'bad' }, '✖')
      : c.degraded ? el('span', { class: 'warn' }, '◐')
        : el('span', { class: 'good' }, '✔');
    return el('div', { class: 'cap' }, mark,
      el('div', {}, c.name, c.reason ? el('div', { class: 'why' }, c.reason) : null));
  });

  return el('div', {},
    el('div', { class: 'cards' },
      card('Access points', st.recon?.aps ?? 0),
      card('Clients', st.recon?.stations ?? 0),
      card('Findings', S.data.findings.length, `${S.data.unclassified.length} unclassified`),
      card('PMKID hashes', st.pmkid_hashes ?? 0, 'for the cracking rig'),
      card('Handshakes', st.handshake_hashes ?? 0, 'for the cracking rig'),
      card('Walkthrough', st.walkthrough || '-', st.started_at ? 'up ' + since(st.started_at) : '', { fit: true }),
    ),

    el('h1', { class: 'section' }, 'Engagement'),
    el('div', { class: 'card' },
      el('dl', { style: 'display:grid;grid-template-columns:130px 1fr;gap:6px 12px;margin:0' },
        el('dt', { class: 'muted' }, 'workspace'), el('dd', { style: 'margin:0;font-family:var(--mono)' }, st.workspace || '-'),
        el('dt', { class: 'muted' }, 'scoped names'), el('dd', { style: 'margin:0' }, String(st.scope_essids ?? 0)),
        el('dt', { class: 'muted' }, 'survey radio'), el('dd', { style: 'margin:0;font-family:var(--mono)' }, st.survey_radio ? ifnameFor(st.survey_radio) : '-'))),

    el('h1', { class: 'section' }, 'This hardware'),
    el('div', { class: 'caps' }, ...caps),

    walkthroughsCard(),

    el('h1', { class: 'section' }, 'Engagement actions'),
    el('div', { class: 'toolbar' },
      // Capture start/stop lives in the top bar now, so it is reachable from every tab.
      el('button', { class: 'act', onclick: () => act('classify', '/api/rogue/classify', null, 'Classification complete') }, 'Classify'),
      el('button', {
        class: 'act',
        title: 'Broadcasts a probe for a randomly-generated network name that cannot exist. Any '
          + 'device that answers is running karma/mana - it replies to ANY probe, impersonating '
          + 'whatever a client asks for. This is detection, not per-AP: a responder answers '
          + 'regardless of which network you name, so it is one test for the whole area. A hit '
          + 'appears as a KARMA RESPONDER finding.',
        onclick: () => act('karma', '/api/rogue/karma-test', null, 'Karma probe started'),
      }, 'Karma responder test'),
      el('button', {
        class: 'act',
        title: 'Regenerate the CSV/netxml projections in the engagement dir and download them as a '
          + 'single zip (the zip is built in memory and not saved).',
        onclick: exportBundle,
      }, 'Export CSV'),
      el('button', {
        class: 'act',
        title: 'Write report.md to the engagement dir and download a copy.',
        onclick: writeReportDownload,
      }, 'Write report'),
      el('button', {
        class: 'act',
        title: 'Write the machine-readable report of the scoped networks (report-in-scope.json) to '
          + 'the engagement dir and download it: every BSSID, findings and assets, evidence, and '
          + 'what was captured. No secrets.',
        onclick: () => exportReportJSON(true),
      }, 'Export JSON (in scope)'),
      el('button', {
        class: 'act',
        title: 'The same JSON report over everything observed (report.json), written and downloaded.',
        onclick: () => exportReportJSON(false),
      }, 'Export JSON (all)'),
      // Enterprise capture is not a one-button action - cert harvest, mimic generation and the
      // rogue/RADIUS bring-up all precede it - so it lives on the Evil Twin tab, not here.
      el('button', {
        class: 'act',
        onclick: () => {
          promptModal('Where are you? This names the walkthrough and its capture file.', '', {
            title: 'Start walkthrough', okLabel: 'Start', placeholder: 'e.g. 3rd floor east',
          }).then((name) => {
            if (name) act('walk', '/api/walkthrough/start', { name }, 'Walkthrough started: ' + name);
          });
        },
      }, 'Start walkthrough'),
      st.walkthrough ? el('button', { class: 'act', onclick: () => act('walkend', '/api/walkthrough/end', null, 'Walkthrough ended') }, 'End walkthrough') : null,
    ));
}

function paneAPs() {
  let rows = S.data.aps;
  if (S.inScopeOnly) rows = rows.filter((a) => a.in_scope);

  const cols = [
    { key: 'bssid', label: 'BSSID', cell: (a) => a.bssid, text: (a) => a.bssid, sortVal: (a) => a.bssid },
    {
      key: 'essid', label: 'Network',
      cell: (a) => networkCell(a),
      text: (a) => a.essid, sortVal: (a) => (a.essid || '￿').toLowerCase(),
    },
    { key: 'band', label: 'Band', cell: (a) => bandCell(a.band, a.phy), text: (a) => (a.phy ? a.band + ' (' + a.phy + ')' : a.band), sortVal: (a) => a.band || '' },
    { key: 'ch', label: 'Ch', cell: (a) => a.channel || '-', sortVal: (a) => a.channel || 0 },
    { key: 'sig', label: 'Signal', cell: (a) => signal(a.last_rssi, a.has_rssi, { stale: a.has_rssi && !a.active, ageSecs: a.last_seen_secs }), sortVal: (a) => (a.has_rssi ? -a.last_rssi : 999) },
    {
      key: 'sec', label: 'Security',
      cell: (a) => el('span', { class: secClassAP(a) }, secLabel(a)),
      text: (a) => secLabel(a), sortVal: (a) => secLabel(a),
    },
    { key: 'pmf', label: 'PMF', cell: (a) => pmfCell(a.security?.mfp), sortVal: (a) => a.security?.mfp || '' },
    {
      key: 'clients', label: 'Clients',
      // Where the clients are is where the handshakes are, and an AP with none has nothing
      // to deauthenticate.
      cell: (a) => el('span', { class: a.clients ? 'good' : 'muted' }, a.clients ?? 0),
      sortVal: (a) => a.clients ?? 0,
    },
    { key: 'scope', label: 'Scope', cell: (a) => scopeCell(a), sortVal: (a) => (a.in_scope ? 0 : 1) },
    {
      key: 'seen', label: 'Seen',
      // WARP keeps every AP it has ever seen, so this is what tells a live network from a stale
      // entry - airodump's "still on the air" made explicit. Sort brings the freshest to the top.
      cell: (a) => seenCell(a),
      text: (a) => seenAge(a.last_seen_secs) + (a.active ? '' : ' (gone)'),
      sortVal: (a) => (a.last_seen_secs ?? 1e9),
    },
  ];

  return el('div', {},
    toolbar('aps', [
      el('label', {},
        el('input', {
          type: 'checkbox', ...(S.inScopeOnly ? { checked: 'checked' } : {}),
          onchange: (e) => { S.inScopeOnly = e.target.checked; render(); },
        }), 'in scope only'),
      el('span', { class: 'muted', style: 'margin-left:auto' },
        `${rows.length} of ${S.data.aps.length}`),
    ]),
    table('aps', cols, rows, (a) => a.bssid, { sticky: true }));
}

function paneStations() {
  const cols = [
    {
      key: 'mac', label: 'Client',
      cell: (s) => el('span', {}, s.mac, s.randomised_mac ? el('span', { class: 'muted' }, ' ∗') : null),
      text: (s) => s.mac, sortVal: (s) => s.mac,
    },
    { key: 'bssid', label: 'Associated', cell: (s) => s.bssid || '-', text: (s) => s.bssid, sortVal: (s) => s.bssid || '￿' },
    {
      key: 'essid', label: 'Network',
      cell: (s) => el('span', { class: s.essid ? (s.in_scope ? 'good' : '') : 'muted' }, s.essid || '-'),
      text: (s) => s.essid, sortVal: (s) => (s.essid || '￿').toLowerCase(),
    },
    { key: 'band', label: 'Band', cell: (s) => bandCell(s.ap_band, s.ap_phy), text: (s) => (s.ap_phy ? s.ap_band + ' (' + s.ap_phy + ')' : s.ap_band), sortVal: (s) => s.ap_band || '' },
    { key: 'sig', label: 'Signal', cell: (s) => signal(s.last_rssi, s.has_rssi, { stale: s.has_rssi && !s.active, ageSecs: s.last_seen_secs }), sortVal: (s) => (s.has_rssi ? -s.last_rssi : 999) },
    { key: 'pmf', label: 'PMF', cell: (s) => (s.bssid ? pmfCell(s.mfp) : el('span', { class: 'muted' }, '-')), sortVal: (s) => s.mfp || '' },
    { key: 'frames', label: 'Frames', cell: (s) => s.frames ?? 0, sortVal: (s) => s.frames ?? 0 },
    {
      key: 'probed', label: 'Has looked for', wrap: true,
      cell: (s) => (s.probed_essids || []).join(', ') || '-',
      text: (s) => (s.probed_essids || []).join(' '),
    },
  ];
  const rows = S.inScopeOnly
    ? S.data.stations.filter((s) => s.in_scope)
    : S.data.stations;
  return el('div', {},
    toolbar('stations', [
      el('label', {},
        el('input', {
          type: 'checkbox', ...(S.inScopeOnly ? { checked: 'checked' } : {}),
          onchange: (e) => { S.inScopeOnly = e.target.checked; render(); },
        }), ' in scope only'),
      el('span', { class: 'muted', style: 'margin-left:auto' },
        (S.inScopeOnly ? `${rows.length} of ${S.data.stations.length} · ` : '')
        + '∗ randomised MAC - may be one device seen repeatedly'),
    ]),
    table('stations', cols, rows, (s) => s.mac, { sticky: true }));
}

// paneHashes shows the engagement's actual deliverable.
//
// Everything else WARP does exists to produce these lines. Until this pane there was no way to
// see one without reading a root-owned file on the box, which is a poor answer to "did that
// deauthentication get me anything".
function paneHashes() {
  const h = S.data.hashes || {};
  let allRows = h.hashes || [];
  let creds = (S.data.eap && S.data.eap.captured) || [];
  let wps = h.wps_keys || [];

  // Cross-reference the observed AP population so a captured PMKID/handshake can be told apart by
  // the security its BSSID actually advertises. A PMKID or four-way handshake from an 802.1X
  // (WPA-Enterprise) network is real evidence, but its PMK comes from the RADIUS exchange, not a
  // passphrase - there is nothing for a 22000 wordlist to recover. Listing it beside crackable
  // PSK material invites an operator to queue a job that can never finish, so it goes in its own
  // table, clearly labelled not crackable, and never gets announced as a win in the tray.
  const apSecByBSSID = {};
  const apInScopeByBSSID = {};
  const scopedESSIDs = new Set();
  for (const a of (S.data.aps || [])) {
    const b = (a.bssid || '').toLowerCase();
    apSecByBSSID[b] = a.security?.class || '';
    apInScopeByBSSID[b] = !!a.in_scope;
    if (a.in_scope && a.essid) scopedESSIDs.add(a.essid.toLowerCase());
  }
  const isEnterprise = (r) => {
    const c = apSecByBSSID[(r.bssid || '').toLowerCase()];
    return c === 'wpa_enterprise' || c === 'wpa3_enterprise_192';
  };

  // The engagement-wide in-scope toggle narrows every section of this tab. A capture's own
  // in_scope flag is authoritative when it carries one (the PSK rows do); otherwise fall back to
  // the observed AP population, and when a credential names a network WARP cannot currently see,
  // keep it rather than hide a deliverable.
  if (S.inScopeOnly) {
    allRows = allRows.filter((r) => r.in_scope);
    creds = creds.filter((o) => !o.essid || scopedESSIDs.has((o.essid || '').toLowerCase()));
    wps = wps.filter((o) => {
      const b = (o.bssid || '').toLowerCase();
      if (b in apInScopeByBSSID) return apInScopeByBSSID[b];
      return !o.essid || scopedESSIDs.has((o.essid || '').toLowerCase());
    });
  }

  // Split PSK (crackable) from enterprise (not crackable) captures.
  const rows = allRows.filter((r) => !isEnterprise(r));
  const entRows = allRows.filter((r) => isEnterprise(r));

  // WPS-recovered credentials: already cracked, so they sit with the credentials, not the hashes
  // headed for the rig. The PIN is always present; the passphrase is there when the exchange read
  // it out of M7.
  const wpsSection = wps.length ? el('div', { style: 'margin-bottom:22px' },
    el('h1', { class: 'section' }, `WPS recovered keys (${wps.length})`),
    table('wps', [
      { key: 'essid', label: 'Network', cell: (o) => o.essid || '-', text: (o) => o.essid, sortVal: (o) => o.essid || '' },
      { key: 'bssid', label: 'BSSID', cell: (o) => o.bssid, text: (o) => o.bssid },
      {
        key: 'psk', label: 'Passphrase', wrap: true,
        // Unredacted: it is the evidence and the deliverable. Empty until the run read M7.
        cell: (o) => (o.psk
          ? el('code', { class: 'hashline' }, o.psk)
          : el('span', { class: 'muted', title: 'PIN recovered; run again to read the passphrase from M7' }, 'PIN only')),
        text: (o) => o.psk || '',
        sortVal: (o) => (o.psk ? 0 : 1),
      },
      { key: 'pin', label: 'WPS PIN', cell: (o) => el('code', { class: 'hashline' }, o.pin), text: (o) => o.pin },
      { key: 'gen', label: 'Nonce generator', cell: (o) => o.generator || '-', text: (o) => o.generator },
      { key: 'at', label: 'Recovered', cell: (o) => stamp(o.at), sortVal: (o) => o.at || '' },
    ], wps, (o) => o.bssid),
    el('div', { class: 'note' },
      'Recovered offline from one WPS exchange (Pixie Dust). The passphrase does not expire; the ',
      'PIN yields it directly.')) : null;

  const enterprise = creds.length ? el('div', { style: 'margin-bottom:22px' },
    el('h1', { class: 'section' }, `Enterprise credentials (${creds.length})`),
    table('creds', [
      {
        key: 'result', label: 'Result',
        cell: (o) => (o.cleartext
          ? el('span', { class: 'bad' }, 'CLEARTEXT')
          : o.hash_line
            ? el('span', { class: 'info' }, 'MSCHAPv2')
            : el('span', { class: 'muted' }, 'no credential')),
        text: (o) => (o.cleartext ? 'cleartext' : o.hash_line ? 'mschapv2' : 'none'),
        sortVal: (o) => (o.cleartext ? 0 : o.hash_line ? 1 : 2),
      },
      { key: 'inner', label: 'Identity', cell: (o) => o.inner_identity || o.outer_identity || '-',
        text: (o) => o.inner_identity, sortVal: (o) => o.inner_identity || '' },
      { key: 'outer', label: 'Outer', cell: (o) => o.outer_identity || '-', text: (o) => o.outer_identity },
      { key: 'essid', label: 'Network', cell: (o) => o.essid || '-', text: (o) => o.essid },
      { key: 'method', label: 'Method', cell: (o) => o.method || '-', text: (o) => o.method },
      { key: 'client', label: 'Client', cell: (o) => o.calling_station || '-', text: (o) => o.calling_station },
      {
        key: 'value', label: 'Credential', wrap: true,
        // Nothing redacted. The operator needs the actual value for the report, and hiding it
        // would only mean going to a root-owned file to read the same thing.
        cell: (o) => el('code', { class: 'hashline' }, o.cleartext || o.hash_line || ''),
        text: (o) => o.cleartext || o.hash_line,
      },
    ], creds, (o) => (o.hash_line || o.cleartext || '') + o.inner_identity),
    // Only claim a cleartext finding when one was actually captured - otherwise the note reads as
    // if a plaintext password was recovered when only an MSCHAPv2 exchange (mode 5500, still to be
    // cracked) was.
    creds.some((o) => o.cleartext)
      ? el('div', { class: 'note' },
        'A cleartext password came with no cracking step at all - that is a more serious ',
        'finding than an MSCHAPv2 exchange. Credentials are written to ',
        el('code', {}, S.data.eap.creds_file || 'creds/mschapv2.5500'), '.')
      : el('div', { class: 'note' },
        'MSCHAPv2 challenge/response captured - crack it with hashcat ',
        el('code', {}, '-m 5500'), '. Written to ',
        el('code', {}, S.data.eap.creds_file || 'creds/mschapv2.5500'), '.')) : null;

  if (!rows.length && !entRows.length && !creds.length && !wps.length) {
    const pending = h.pending_essid || 0;
    if (S.inScopeOnly && ((h.hashes || []).length || ((S.data.eap && S.data.eap.captured) || []).length || (h.wps_keys || []).length)) {
      return el('div', { class: 'empty' },
        el('b', {}, 'Nothing in scope captured yet.'),
        'Captures exist, but all of them are from out-of-scope networks. Turn off "in scope ' +
        'only" (the toggle in the header, or the checkbox on another tab) to see them.');
    }
    return el('div', { class: 'empty' },
      el('b', {}, pending
        ? `${pending} handshake(s) held, waiting for a network name.`
        : 'Nothing captured yet.'),
      pending
        ? 'A 22000 line needs the ESSID. These are emitted the moment it is learned - keep ' +
          'capturing, or deauthenticate a client so it reassociates and names the network.'
        : 'PMKID: select a scoped access point and press Solicit PMKID - no client needed. ' +
          'Handshake: deauthenticate a client from the Clients tab so it reconnects, and the ' +
          'four-way exchange is captured as it rejoins.');
  }

  const cols = [
    {
      key: 'kind', label: 'Kind',
      cell: (r) => el('span', {
        class: !r.in_scope ? 'muted' : (r.kind === 'handshake' ? 'warn' : 'good'),
        title: r.kind === 'handshake'
          ? 'WPA-Personal four-way handshake - hashcat 22000 WPA*02'
          : 'PMKID from the first message, no client needed - hashcat 22000 WPA*01',
      }, r.kind === 'handshake' ? 'HANDSHAKE' : 'PMKID'),
      text: (r) => r.kind, sortVal: (r) => r.kind,
    },
    {
      key: 'scope', label: 'Scope',
      // An incidental capture is real material and it is kept - but it is not part of the
      // deliverable, and it must never read as if it were.
      cell: (r) => (r.in_scope
        ? el('span', { class: 'tag good' }, 'in scope')
        : el('span', {
          class: 'tag bad',
          title: 'overheard from a network this engagement has no authority over - kept as ' +
            'evidence, written to a separate file, and not for the cracking rig',
        }, 'incidental')),
      text: (r) => (r.in_scope ? 'in scope' : 'incidental'),
      sortVal: (r) => (r.in_scope ? 0 : 1),
    },
    { key: 'essid', label: 'Network', cell: (r) => r.essid || '-', text: (r) => r.essid, sortVal: (r) => r.essid || '' },
    { key: 'bssid', label: 'BSSID', cell: (r) => r.bssid, text: (r) => r.bssid, sortVal: (r) => r.bssid },
    { key: 'sta', label: 'Client', cell: (r) => r.station || '-', text: (r) => r.station, sortVal: (r) => r.station || '' },
    { key: 'ch', label: 'Ch', cell: (r) => r.channel || '-', sortVal: (r) => r.channel || 0 },
    { key: 'at', label: 'Captured', cell: (r) => stamp(r.at), sortVal: (r) => r.at || '' },
    {
      key: 'line', label: 'Hash', wrap: true,
      // Selectable, so it can be copied straight into a job on the cracking rig.
      cell: (r) => el('code', { class: 'hashline', title: 'select to copy' }, r.line),
      text: (r) => r.line,
    },
  ];

  const pskMaterial = rows.length ? el('div', {},
    el('h1', { class: 'section' }, 'PSK material'),
    toolbar('hashes', [
      el('label', {},
        el('input', {
          type: 'checkbox', ...(S.inScopeOnly ? { checked: 'checked' } : {}),
          onchange: (e) => { S.inScopeOnly = e.target.checked; render(); },
        }), ' in scope only'),
      el('span', { class: 'muted', style: 'margin-left:auto' },
        `${rows.length} shown · ${h.pmkid || 0} PMKID · ${h.handshake || 0} handshake`,
        h.out_of_scope ? el('span', { class: 'bad' }, ` · ${h.out_of_scope} incidental`) : null),
    ]),
    table('hashes', cols, rows, (r) => r.line),
    el('div', { class: 'note', style: 'margin-top:14px' },
      el('b', {}, 'PMKID'), ' comes from the first message of the handshake - no client needed. ',
      el('b', {}, 'HANDSHAKE'), ' is a full WPA-Personal four-way handshake, which needs a ',
      'client to join. Both crack with hashcat mode 22000 against the same wordlist. Neither ',
      'is enterprise authentication: WPA-Enterprise credentials are MSCHAPv2 (mode 5500) and ',
      'land in ', el('code', {}, 'creds/'), ' from the RADIUS server, not here.'),

    el('div', { class: 'note', style: 'margin-top:14px' },
      'WARP does not crack. The deliverable is written to ',
      el('code', {}, (h.files || []).join(' and ')),
      ' - transfer those to the cracking rig by hand. Each line is self-contained and maps ' +
      'back to its network without warp.db.'),

    h.out_of_scope
      ? el('div', { class: 'note warn' },
        `${h.out_of_scope} handshake(s) were overheard from networks outside the scope. ` +
        'Capture is passive, so WARP records what it hears rather than discarding evidence - ' +
        'but cracking one would be unauthorized work on someone else\'s credentials. They are ' +
        'kept apart in ',
        el('code', {}, (h.out_of_scope_files || []).join(' and ')),
        ', which a *.22000 glob will not pick up.')
      : null) : null;

  // 802.1X PMKID/handshakes: captured and kept as evidence, but the PMK is derived from the
  // RADIUS exchange, not a passphrase, so no 22000 wordlist can recover anything. Shown in their
  // own table so they are never confused with crackable PSK material or queued on the rig.
  const entMaterial = entRows.length ? el('div', { style: 'margin-top:22px' },
    el('h1', { class: 'section' }, `802.1X captures - not crackable (${entRows.length})`),
    table('enthashes', cols, entRows, (r) => r.line),
    el('div', { class: 'note warn', style: 'margin-top:14px' },
      'These came off ', el('b', {}, 'WPA-Enterprise (802.1X)'), ' networks. The pairwise key ',
      'is derived from the 802.1X/RADIUS exchange, not a passphrase, so there is nothing for a ',
      'hashcat 22000 wordlist to recover - do not send these to the cracking rig. The credential ',
      'worth capturing on an enterprise network is the MSCHAPv2 exchange (mode 5500) from the ',
      'evil-twin RADIUS server, which lands in ', el('code', {}, 'creds/'), '.')) : null;

  return el('div', {}, enterprise, wpsSection, pskMaterial, entMaterial);
}

// tierRank orders tiers most-severe first for grouping.
function tierRank(t) { return ({ determined: 0, evidence: 1, control: 2 }[t] ?? 3); }

// findingGroups groups a flat finding list by label into one card per finding, carrying the most
// severe tier, a description, and the affected assets. The operator wants "here is a finding and
// everything it affects", not the same label repeated down the page.
function findingGroups(findings) {
  const groups = new Map();
  for (const f of findings) {
    let g = groups.get(f.label);
    if (!g) {
      g = { label: f.label, tier: f.tier, desc: f.rationale || '', assets: [] };
      groups.set(f.label, g);
    }
    if (tierRank(f.tier) < tierRank(g.tier)) g.tier = f.tier;
    if (!g.desc && f.rationale) g.desc = f.rationale;
    g.assets.push({ bssid: f.bssid, essid: f.essid, rationale: f.rationale, differences: f.differences || [], in_scope: !!f.in_scope });
  }
  return [...groups.values()].sort((a, b) =>
    tierRank(a.tier) - tierRank(b.tier) || a.label.localeCompare(b.label));
}

// findingEvidence renders the collapsible per-finding evidence for ONE representative asset,
// preferring an in-scope one so it drops straight into a report. Above the detail block sits a
// one-line "what to look at" pointer that ties the finding to the packet field it rests on (e.g.
// "the AKM list advertises SAE alongside PSK: a transition BSS"). The detail block itself is chosen
// by the finding type - cloaking for a recovered hidden name, the observed record for a rogue/karma
// finding, the parsed encryption otherwise - so a hidden-network finding no longer dumps ciphers.
// Then the diverging attributes the classifier cited, then the command to get it from the pcap by
// hand. When there is no observed record to show, it says so and gives the command. Open/closed
// state is remembered across the background poll.
function findingEvidence(g, apByBssid) {
  const asset = g.assets.find((a) => a.in_scope) || g.assets[0] || {};
  const ap = (apByBssid || {})[asset.bssid];
  const diffs = asset.differences && asset.differences.length
    ? asset.differences
    : [...new Set(g.assets.flatMap((a) => a.differences || []))];

  // The "what to look at" pointer, tying the finding to the field below it.
  const pointer = evidencePointer(g.label, ap, asset.essid);

  // A manually-marked potential rogue has no packet-level basis: its evidence is the operator's
  // judgement, so it shows the "manual evidence required" block and no pcap/encryption command.
  const manual = (g.label || '').toLowerCase().indexOf('potentially rogue device') >= 0;

  // The evidence block (copyable), chosen by finding type. When no observed record is joined, say so
  // plainly rather than inventing one.
  let text;
  if (manual) {
    text = manualEvidenceText(ap, asset.essid);
  } else if (ap) {
    text = evidenceBlock(g.label, ap, asset.essid);
    if (diffs.length) text += '\n\nDiffers from its peers: ' + diffs.join('; ');
  } else {
    text = 'No observed beacon/probe-response record for ' + (asset.essid || '(hidden)')
      + ' (' + (asset.bssid || '?') + ') is joined here.\nGet it from the pcap with the command below.';
    if (diffs.length) text += '\n\nDiffers from its peers: ' + diffs.join('; ');
  }
  const cmd = encryptionCommand(asset.essid)
    + (asset.essid ? '' : '   (hidden network - no SSID to filter on)');

  const key = g.label;
  return el('details', {
    class: 'evidence', ...(S.evidOpen[key] ? { open: true } : {}),
    ontoggle: (e) => { S.evidOpen[key] = e.target.open; },
  },
    el('summary', {}, 'Evidence'),
    el('div', { class: 'evidence-body' },
      pointer ? el('div', { class: 'evidence-note' }, pointer) : null,
      el('pre', { class: 'evidence-pre' }, text),
      manual ? null : cmdLine('Get it from the pcap yourself:', cmd),
      el('button', {
        class: 'act tiny',
        onclick: async () => {
          try { await navigator.clipboard.writeText(text); toast('ok', 'Evidence copied'); }
          catch { toast('deny', 'Copy failed - select and copy manually'); }
        },
      }, 'Copy')));
}

// findingCard renders one grouped finding as a collapsible section whose open/closed state is
// remembered across the background poll, with a nested Evidence block.
function findingCard(g, apByBssid) {
  const key = g.label;
  return el('details', {
    class: 'finding-group', ...(S.findOpen[key] ? { open: true } : {}),
    ontoggle: (e) => { S.findOpen[key] = e.target.open; },
  },
    el('summary', { class: 'finding-head' },
      el('span', { class: 'tag ' + tierClass(g.tier) }, g.tier),
      el('b', {}, g.label),
      el('span', { class: 'muted' }, ` · ${g.assets.length} affected`)),
    el('div', { class: 'finding-body' },
      g.desc ? el('div', { class: 'finding-desc' }, g.desc) : null,
      el('table', { class: 'affected' },
        el('thead', {}, el('tr', {}, el('th', {}, 'BSSID'), el('th', {}, 'Network'))),
        el('tbody', {}, ...g.assets.map((a) => el('tr', {},
          el('td', { class: 'mono' }, a.bssid),
          el('td', {}, a.essid || '-'))))),
      findingEvidence(g, apByBssid)));
}

function paneFindings() {
  const all = S.data.findings || [];
  const scopedOnly = S.inScopeOnly;
  // The in-scope filter narrows both findings and the unclassified list to networks the SoW
  // covers - the out-of-scope ones are noise on most engagements. It is off by default so nothing
  // is hidden until the operator asks: some rogue findings (evil-twin candidate, karma responder)
  // deliberately carry no scoped ESSID and would vanish under the filter.
  const findings = scopedOnly ? all.filter((f) => f.in_scope) : all;

  // The observed AP record behind each finding, for the Evidence detail.
  const apByBssid = {};
  for (const a of (S.data.aps || [])) apByBssid[a.bssid] = a;
  const card = (g) => findingCard(g, apByBssid);

  // Exposures (determined + evidence) are the findings proper; controls are passes and are shown
  // apart from them so a good posture never reads as a problem.
  const exposures = findingGroups(findings.filter((f) => f.tier !== 'control'));
  const controls = findingGroups(findings.filter((f) => f.tier === 'control'));

  const exposuresEl = exposures.length
    ? el('div', {}, ...exposures.map(card))
    : el('div', { class: 'empty' },
      el('b', {}, 'Nothing here yet'),
      scopedOnly && all.some((f) => f.tier !== 'control')
        ? 'No exposures on a scoped network. Turn off "in scope only" to see out-of-scope findings.'
        : 'Findings appear as recon runs and the classifier has a population to compare against.');

  const controlsEl = controls.length
    ? el('div', { style: 'margin-top:18px' },
      el('h1', { class: 'section' }, `Controls - passed (${controls.length})`),
      el('p', { class: 'muted', style: 'font-size:13px;line-height:1.6;margin:0 0 10px' },
        'Configurations found correct and active tests the network passed - 802.11w required, ' +
        'WPS locked, an AP that resisted Pixie Dust. Recorded so the report shows what was ' +
        'tested, not only what was exposed.'),
      ...controls.map(card))
    : null;

  // Resolve each unclassified BSSID to its network name so the list is a table, not a wall of MACs.
  const essidOf = {}; const scopedBSSID = {};
  for (const a of (S.data.aps || [])) { essidOf[a.bssid] = a.essid; scopedBSSID[a.bssid] = a.in_scope; }
  const unclassList = scopedOnly
    ? S.data.unclassified.filter((b) => scopedBSSID[b])
    : S.data.unclassified;
  const unclass = unclassList.length
    ? el('div', { style: 'margin-top:18px' },
      el('h1', { class: 'section' }, `Unclassified (${unclassList.length})`),
      el('p', { class: 'muted', style: 'font-size:13px;line-height:1.6;margin:0 0 10px' },
        'Observed in the footprint with no conclusion available. Listed rather than omitted: ' +
        'the absence of a finding is not the absence of interest.'),
      el('table', { class: 'banded' },
        el('thead', {}, el('tr', {}, el('th', {}, 'BSSID'), el('th', {}, 'Network'))),
        el('tbody', {}, ...unclassList.map((b) => el('tr', {},
          el('td', { class: 'mono' }, b),
          el('td', {}, essidOf[b] || el('span', { class: 'muted' }, '(hidden/unknown)')))))))
    : null;

  // Classify is the action this page exists to drive, so it is the one coloured button here -
  // green to stand out from the neutral toolbar. Label reflects whether there is anything to
  // re-run against: "Classify" on a clean slate, "Re-classify" once findings exist.
  const classifyLabel = all.length ? 'Re-classify' : 'Classify';
  const shown = exposures.length + controls.length;
  const total = findingGroups(all).length;
  return el('div', {},
    toolbar('findings', [
      el('button', { class: 'act primary', onclick: () => act('classify', '/api/rogue/classify', null, 'Classification complete') }, classifyLabel),
      el('label', { style: 'margin-left:12px' },
        el('input', {
          type: 'checkbox', ...(scopedOnly ? { checked: 'checked' } : {}),
          onchange: (e) => { S.inScopeOnly = e.target.checked; render(); },
        }), ' in scope only'),
      el('span', { class: 'muted', style: 'margin-left:auto' },
        scopedOnly ? `${shown} of ${total} findings` : `${total} findings`),
    ]),
    exposuresEl,
    controlsEl,
    unclass);
}

/* ------------------------------------------------------------------- radios */

// chanControls renders the per-adapter channel-management form: which channels it sweeps, whether
// it sweeps 5 GHz, and whether it hops randomly. Kismet-style control on the radios tab.
function chanControls(r) {
  const has5 = (r.bands || []).some((b) => String(b).includes('5'));
  const cur = (S.chanForm[r.id] !== undefined)
    ? S.chanForm[r.id]
    : (r.selected_channels || []).join(',');
  // Checkbox state: a local override wins if the operator has toggled it, so a redraw does not
  // revert the toggle back to the last server value before Apply. Both default off (full sweep,
  // ascending order) - sequential is the sane default and random is the deliberate opt-in.
  const chk = S.chanChk[r.id] || {};
  const no5 = chk.no5 !== undefined ? chk.no5 : !!r.channels_no_5ghz;
  const rnd = chk.rnd !== undefined ? chk.rnd : !!r.channels_random;
  const setChk = (k, v) => { S.chanChk[r.id] = { ...(S.chanChk[r.id] || {}), [k]: v }; };
  const apply = () => {
    const raw = (S.chanForm[r.id] !== undefined ? S.chanForm[r.id] : cur).trim();
    const channels = raw
      ? raw.split(',').map((s) => parseInt(s.trim(), 10)).filter((n) => Number.isFinite(n) && n > 0)
      : [];
    act('chan:' + r.id, '/api/radios/channels',
      { radio_id: r.id, channels, disable_5ghz: has5 && no5, random: rnd },
      r.ifname + ' channel plan updated');
  };
  // One control per row, stacked: sweep channels, then pin-to-channel, then the two toggles, then
  // Apply. The two text inputs share the .fbox styling so neither reads as an odd white box.
  return el('div', { class: 'chan' },
    el('label', { class: 'chan-in' },
      el('span', { class: 'muted' }, 'sweep channels'),
      el('input', {
        class: 'fbox', type: 'text', 'data-fkey': 'chan-' + r.id,
        placeholder: 'all - e.g. 1,6,11', value: cur,
        oninput: (e) => { S.chanForm[r.id] = e.target.value; },
      })),
    pinControl(r),
    has5
      ? el('label', { class: 'chk' },
        el('input', {
          type: 'checkbox', 'data-fkey': 'no5-' + r.id, checked: no5,
          onchange: (e) => setChk('no5', e.target.checked),
        }),
        ' skip 5 GHz')
      : null,
    el('label', { class: 'chk' },
      el('input', {
        type: 'checkbox', 'data-fkey': 'rnd-' + r.id, checked: rnd,
        onchange: (e) => setChk('rnd', e.target.checked),
      }),
      ' random hop'),
    el('button', { class: 'act', onclick: apply }, 'Apply'));
}

// pinControl renders the pin-to-channel form (or the unpin button when the adapter is pinned). It
// sits directly under "sweep channels": the channel plan sweeps, which is right for finding things
// and wrong for watching one, so an operator who knows the target's channel parks a card there
// while the others keep sweeping. Locking does not stop the adapter capturing, only moving.
function pinControl(r) {
  if (r.pinned_channel) {
    return el('div', { class: 'chan-in' },
      el('span', { class: 'muted' }, 'pin to channel'),
      el('button', {
        class: 'act danger',
        onclick: () => act('unpin:' + r.id, '/api/radios/unlock', { radio_id: r.id },
          r.id + ' back on the channel plan'),
      }, 'Unpin from ch' + r.pinned_channel));
  }
  return el('form', {
    class: 'chan-in pin',
    onsubmit: (e) => {
      e.preventDefault();
      const n = document.querySelector('[data-fkey="pin-' + r.id + '"]');
      const ch = parseInt(n ? n.value : '', 10);
      if (!Number.isFinite(ch) || ch <= 0) {
        alertModal('Enter a channel number. The adapter is refused if it cannot reach it - '
          + 'a 2.4 GHz-only card asked for channel 36 says so rather than tuning nowhere.');
        return;
      }
      act('pin:' + r.id, '/api/radios/lock', { radio_id: r.id, channel: ch },
        r.id + ' pinned to channel ' + ch);
    },
  },
    el('span', { class: 'muted' }, 'pin to channel'),
    el('input', {
      class: 'fbox', type: 'text', 'data-fkey': 'pin-' + r.id, placeholder: 'ch',
      value: (S.pinForm[r.id] || ''),
      oninput: (e) => { S.pinForm[r.id] = e.target.value; },
    }),
    el('button', { class: 'act', type: 'submit' }, 'Pin to channel'));
}

// paneRadios is the adapter management view.
//
// The scheduler decides which card does what and the header shows the outcome a line at a
// time, but nothing said *why*: which adapter can run AP mode, which one injection was
// demonstrated on, which bands a card can even reach. On a kit where one adapter is 2.4-only,
// "the 5 GHz half of the estate is missing" and "that card cannot see it" are the same fact
// and neither was on screen.
function paneRadios() {
  const radios = S.data.radios || [];
  if (!radios.length) {
    return el('div', { class: 'empty' },
      el('b', {}, 'No adapters.'),
      el('p', {}, 'warpd found no wireless devices it can manage. Check that it is running '
        + 'as root and that the adapters appear in "iw dev".'));
  }

  const st = S.data.status || {};
  const live = {};
  for (const r of (st.recon?.radios || [])) live[r.radio_id] = r;
  const held = new Set(st.recon?.held_radios || []);

  // A live USB reset power-cycles the adapter, so it is only offered when nothing holds it: capture
  // stopped and no jobs running. The daemon enforces this too - the gate here just greys the button.
  const idleForReset = !st.recon?.running && (st.running_jobs || 0) === 0;

  const byRadio = {};
  for (const a of (S.data.assignments || [])) {
    (byRadio[a.radio_id] = byRadio[a.radio_id] || []).push(
      a.role + (a.iftype ? ' (' + a.iftype + ')' : ''));
  }

  // Injection state decides whether every transmitting attack is even offered, so it is the
  // one field that gets a colour. "Inconclusive" is not a failure - many drivers do not loop
  // their own transmissions back to the monitor socket, so two identical cards (e.g. a pair of
  // mt76x2u) can legitimately read differently: one happened to catch its own test frame, the
  // other did not. Both transmit. Only "failed" blocks work (invariant 7a).
  const injClass = (v) => (String(v).includes('verified') ? 'good'
    : String(v).includes('failed') ? 'bad' : 'warn');
  const injNote = (v) => ({
    verified: 'a test frame was injected and seen coming back - injection confirmed.',
    inconclusive: 'the driver accepted the test frames but none looped back to the monitor - '
      + 'common on mt76 and not a failure. Transmitting work proceeds; two identical cards often '
      + 'differ here for no reason that affects an attack.',
    failed: 'the driver rejected the injected frame - this adapter cannot transmit, so active '
      + 'attacks are not offered on it.',
    untested: 'not probed yet - it is measured the first time a transmitting attack needs it.',
  })[String(v)] || '';

  const lvlClass = (l) => ({ ok: 'good', info: 'muted', warn: 'warn', fixable: 'warn', fail: 'bad' }[l] || '');
  const pc = S.precheck;
  const sysPanel = el('div', { class: 'sys-checks' },
    el('div', { class: 'sys-head' },
      el('b', {}, 'System state'),
      el('span', { class: 'muted' },
        ' - rfkill blocks, NetworkManager and wpa_supplicant fighting WARP for the cards'),
      el('button', {
        class: 'act', style: 'margin-left:auto',
        onclick: loadPrecheck,
      }, pc ? 'Re-check' : 'Check')),
    pc
      ? el('div', { class: 'sys-rows' }, ...pc.map((c) => el('div', { class: 'sys-row' },
        el('span', { class: 'tag ' + lvlClass(c.level) }, c.level),
        el('span', { class: 'sys-name' }, c.name),
        el('span', { class: 'sys-detail' }, c.detail),
        c.fixable
          ? el('button', {
            class: 'act danger',
            onclick: () => fixPrecheck(c.name),
          }, c.fix || 'Fix')
          : null)))
      : null);

  // Regulatory domain control. Set at startup (US by default); this changes it live, which is what
  // flips the 5/6 GHz bands from receive-only to transmit-usable. Fetched once for the tab.
  if (S.regdomain === null) loadRegDomain();
  const reg = S.regdomain || { cc: '00', is_world: true };
  const COUNTRIES = ['US', 'CA', 'GB', 'DE', 'FR', 'NL', 'AU', 'JP', 'BR', 'ES', 'IT', 'SE', '00'];
  const regBusy = S.busy.has('reg');
  // A local pending selection survives any rebuild, so choosing a country and then a poll landing
  // does not snap the dropdown back to the applied value before Apply is clicked.
  const chosen = S.regPending || reg.cc || '00';
  const regSel = el('select', {
    class: 'reg-sel', 'data-fkey': 'reg-sel',
    onchange: (e) => { S.regPending = e.target.value; },
  },
    ...COUNTRIES.map((c) => el('option', { value: c, ...(c === chosen ? { selected: true } : {}) },
      c === '00' ? '00 (world)' : c)));
  const regPanel = el('div', { class: 'sys-checks' },
    el('div', { class: 'sys-head' },
      el('b', {}, 'Regulatory domain'),
      el('span', { class: 'muted' }, reg.is_world
        ? ' - world default: 5/6 GHz is receive-only. Set your country to transmit there.'
        : ' - sets which channels and bands WARP may transmit on.'),
      el('span', { class: 'tag ' + (reg.is_world ? 'warn' : 'good'), style: 'margin-left:auto' },
        (reg.cc || '00')),
      regSel,
      el('button', { class: 'act', ...(regBusy ? { disabled: 'disabled' } : {}),
        onclick: () => setRegDomain(S.regPending || chosen) }, 'Apply')));

  return el('div', {}, regPanel, sysPanel, el('div', { class: 'cards radio-cards' }, ...radios.map((r) => {
    const l = live[r.id];
    const roles = byRadio[r.id] || [];
    const can = (r.roles || []).filter((x) => x.capable).map((x) => x.role);
    const cannot = (r.roles || []).filter((x) => !x.capable);

    let now = el('span', { class: 'muted' }, 'not capturing');
    if (l && l.channel) {
      if (r.pinned_channel) {
        now = el('span', { class: 'warn' }, `ch ${l.channel} - pinned by you, not sweeping`);
      } else if (held.has(r.id) || l.locked) {
        now = el('span', { class: 'warn' }, `ch ${l.channel} - held for a campaign`);
      } else {
        now = el('span', {}, `ch ${l.channel} sweeping`);
      }
    }

    const off = r.enabled === false;

    // Live USB reset, USB adapters only. Power-cycles the card to clear a wedged firmware state (the
    // mt76 "did not associate" after heavy mode-cycling) and rebinds it, no daemon restart. Only
    // enabled when nothing holds the card - capture stopped, no jobs.
    const resetBtn = r.usb
      ? el('button', {
        class: 'act tiny' + (idleForReset ? ' danger' : ''),
        ...(idleForReset ? {} : { disabled: 'disabled' }),
        title: idleForReset
          ? 'USB-reset this adapter now: power-cycle it to clear a wedged state and rebind it. '
            + 'Capture stays stopped; start it again afterwards.'
          : 'Stop capture and let any jobs finish first - a reset power-cycles the card, so it can '
            + 'only run when nothing is using the radio.',
        onclick: () => {
          confirmModal('This power-cycles ' + (r.ifname || r.id) + '. It drops off USB and '
            + 're-enumerates (a few seconds), then WARP rebinds it. Capture stays stopped; start it '
            + 'again afterwards.', {
            title: 'Reset ' + (r.ifname || r.id) + '?', okLabel: 'Reset adapter', danger: true,
          }).then((ok) => {
            if (ok) {
              act('reset:' + r.id, '/api/radios/reset', { radio_id: r.id },
                (r.ifname || r.id) + ' reset');
            }
          });
        },
      }, 'Reset')
      : null;

    // On/off switch, shown to the right of the interface name - a sliding toggle so it reads at a
    // glance as something you flip. Off releases the card for another tool; distinct from pinning,
    // which only stops it moving.
    const switchBtn = el('button', {
      class: 'toggle' + (off ? ' is-off' : ' is-on'),
      role: 'switch', 'aria-checked': off ? 'false' : 'true',
      title: off
        ? 'Switch this adapter on so WARP uses it again'
        : 'Switch this adapter off - WARP releases it and leaves it for another tool',
      onclick: () => act('toggle:' + r.id, '/api/radios/set-enabled',
        { radio_id: r.id, enabled: off },
        r.ifname + (off ? ' switched on' : ' switched off')),
    },
      el('span', { class: 'toggle-label' }, off ? 'OFF' : 'ON'),
      el('span', { class: 'toggle-track' }, el('span', { class: 'toggle-knob' })));

    return el('div', { class: off ? 'card off' : 'card' },
      // Header: interface name (the identity the operator tracks; the phy index is an internal
      // handle and is deliberately not shown) with the on/off switch on the right.
      el('div', { class: 'card-head' },
        el('h3', {}, r.ifname || r.id,
          r.id === st.survey_radio
            // The survey radio is never lent, so it is the one adapter that cannot be borrowed
            // for a burst however busy the kit is. Worth stating where the roles are listed.
            ? el('span', { class: 'info' }, ' · SURVEY, pinned for the engagement')
            : null),
        el('span', { class: 'card-head-actions' }, resetBtn, switchBtn)),

      // Channel controls at the top of the card - the thing most often adjusted on this tab.
      chanControls(r),

      el('dl', {},
        el('dt', {}, 'driver'), el('dd', {}, r.driver || '-'),
        el('dt', {}, 'mac'), el('dd', {}, r.mac || '-'),
        el('dt', {}, 'bands'), el('dd', {}, (r.bands || []).join(', ') || '-'),
        el('dt', {}, 'channels'), el('dd', {}, `${r.usable_channels || 0} usable`),
        el('dt', {}, 'injection'),
        el('dd', {},
          el('span', { class: injClass(r.injection), title: injNote(r.injection) },
            r.injection || 'unknown'),
          injNote(r.injection)
            ? el('div', { class: 'muted inj-note' }, injNote(r.injection))
            : null),
        el('dt', {}, 'modes'), el('dd', {}, (r.supported_iftypes || []).join(', ') || '-'),
        r.ap_monitor_concurrent ? el('dt', {}, 'concurrent') : null,
        r.ap_monitor_concurrent ? el('dd', {}, 'AP and monitor at the same time') : null,
        el('dt', {}, 'now'), el('dd', {}, now),
        l ? el('dt', {}, 'captured') : null,
        l ? el('dd', {}, `${l.capture?.frames || 0} frames, ${l.capture?.dropped || 0} dropped`) : null,
        el('dt', {}, 'assigned'),
        el('dd', {}, roles.length
          ? roles.join(', ')
          : el('span', { class: 'muted' }, 'idle - not serving a role')),
        can.length ? el('dt', {}, 'can serve') : null,
        can.length ? el('dd', {}, can.join(', ')) : null),

      cannot.length
        ? el('div', { class: 'note' },
          el('b', {}, 'Unavailable roles'),
          el('ul', {}, ...cannot.map((x) => el('li', {}, x.role + ': ' + x.reason))))
        : null);
  })));
}

/* ---------------------------------------------------------------- evil twin */

// eviltwinTargetPicker replaces the wall of per-AP cards with one dropdown and one focused panel.
//
// An enterprise site can put a hundred BSSIDs on the air under a handful of names, and a card per
// BSSID was unreadable and misleading - the rogue impersonates by ESSID, not BSSID, so a dozen
// cards for one network all did the same thing. This groups the in-scope enterprise APs by the
// name the operator actually targets, lets them pick one, and shows that target in full: the
// BSSIDs discovered broadcasting it (never configured - invariant 1), the channel and strongest
// radio to harvest from, whether a certificate is ready, and the two actions. Everything stays on
// screen whatever the AP count.
function eviltwinTargetPicker() {
  const isEnt = (a) => a.security?.class === 'wpa_enterprise'
    || a.security?.class === 'wpa3_enterprise_192';
  const enterprise = (S.data.aps || []).filter((a) => isEnt(a) && a.in_scope && a.essid);
  if (!enterprise.length) {
    return el('div', { class: 'note' },
      'No scoped WPA-Enterprise networks observed yet. Run recon, and add the network to '
      + 'scope if it is not already there.');
  }

  const byEssid = new Map();
  for (const a of enterprise) {
    if (!byEssid.has(a.essid)) byEssid.set(a.essid, []);
    byEssid.get(a.essid).push(a);
  }
  const essids = [...byEssid.keys()].sort();
  const sel = byEssid.has(S.eapTarget) ? S.eapTarget : essids[0];
  const group = byEssid.get(sel) || [];

  // Observed BSSIDs for this name, strongest first. The operator picks which one to clone from and
  // wear (the rogue mirrors a specific access point); it defaults to the strongest. Every entry is
  // discovered from the air - the dropdown can only offer addresses WARP has seen, never a typed
  // one, and the daemon validates the choice again (invariant 1).
  const ranked = group.slice().sort((a, b) =>
    (b.has_rssi ? b.last_rssi : -999) - (a.has_rssi ? a.last_rssi : -999));
  const strongest = ranked[0] || group[0];
  const chosenBSSID = ranked.some((a) => a.bssid === S.eapCloneBSSID[sel])
    ? S.eapCloneBSSID[sel]
    : strongest.bssid;
  const chosen = ranked.find((a) => a.bssid === chosenBSSID) || strongest;

  const certs = ((S.data.certs && S.data.certs.networks) || {})[sel] || [];
  const selectedCert = certs.find((c) => c.selected);
  const plural = (n, w) => n + ' ' + w + (n === 1 ? '' : 's');
  const bssidLabel = (a) => a.bssid + '  ch' + (a.channel || '?')
    + (a.has_rssi ? '  ' + a.last_rssi + ' dBm' : '')
    + (a === strongest ? '  (strongest)' : '');

  return el('div', {},
    el('h3', {}, 'Target'),
    el('div', { class: 'targetpick' },
      el('select', {
        class: 'target-select',
        onchange: (ev) => { S.eapTarget = ev.target.value; render(); },
      }, ...essids.map((name) => el('option', {
        value: name, ...(name === sel ? { selected: true } : {}),
      }, name + '  (' + plural(byEssid.get(name).length, 'BSSID') + ')'))),
      el('span', { class: 'muted' },
        plural(essids.length, 'scoped enterprise network') + ' in range')),

    el('div', { class: 'card target-card' },
      el('div', { class: 'card-head' },
        el('h3', {}, sel),
        el('div', { class: 'card-head-actions' },
          selectedCert
            ? el('span', { class: 'tag good', title: selectedCert.source_detail }, 'cert ready')
            : certs.length
              ? el('span', { class: 'tag warn' }, 'cert not selected')
              : el('span', { class: 'tag bad' }, 'no cert'))),

      // BSSID selector: which observed access point to clone and wear. One entry per discovered
      // BSSID, strongest first; the label carries its channel and signal. Picking one here drives
      // both Clone certificate and Start evil twin below.
      el('label', { class: 'bssid-pick' },
        el('span', { class: 'muted' },
          plural(group.length, 'BSSID') + ' broadcasting this name - clone/wear:'),
        el('select', {
          class: 'bssid-select', 'data-fkey': 'eap-bssid-' + sel,
          onchange: (ev) => { S.eapCloneBSSID[sel] = ev.target.value; render(); },
        }, ...ranked.map((a) => el('option', {
          value: a.bssid, ...(a.bssid === chosenBSSID ? { selected: true } : {}),
        }, bssidLabel(a))))),

      !selectedCert
        ? el('div', { class: 'note warn' },
          'No certificate selected for this network. The rogue would fall back to a self-signed '
          + 'certificate, which every client that checks will refuse. Clone the real one below, '
          + 'or prepare one in the certificate library.')
        : null,

      el('div', { class: 'actions' },
        el('button', {
          class: 'act',
          onclick: () => act('harvest:' + chosenBSSID, '/api/harvest',
            { bssid: chosenBSSID }, 'Reading the certificate at ' + sel + ' (' + chosenBSSID + ')'),
        }, 'Clone certificate'),
        el('button', {
          class: 'act primary',
          onclick: () => {
            confirmModal('WARP will beacon this scoped network as ' + chosenBSSID + ' and capture '
              + 'credentials from supplicants that try to authenticate.', {
              title: 'Impersonate "' + sel + '"?', okLabel: 'Start evil twin',
            }).then((ok) => {
              if (ok) act('eapstart', '/api/eap/start',
                { essid: sel, channel: chosen.channel || 0, bssid: chosenBSSID },
                'Impersonating ' + sel);
            });
          },
        }, 'Start evil twin'))));
}

// paneEvilTwin: what is being impersonated, with what certificate, and what came out of it.
function paneEvilTwin() {
  const e = S.data.eap || {};

  if (!e.running || !e.session) {
    // Recent rogue-AP output lingers in the shared stream after a stop, which is exactly what an
    // operator wants for a screenshot. Show the live box only when there is something in it.
    const feedKinds = new Set(['eap', 'harvest', 'certs']);
    const hasFeed = (S.log || []).some((x) => feedKinds.has(x.kind));

    return el('div', {},
      el('div', { class: 'empty compact' },
        el('b', {}, 'Not running.'),
        el('p', {}, 'A rogue access point beacons a scoped network name with WARP\u2019s own '
          + 'RADIUS server behind it, and records what supplicants are willing to send it. '
          + 'Clone the target\u2019s certificate first \u2014 a self-signed one carrying none of '
          + 'its naming is refused by every client that shows the user anything.')),

      eviltwinTargetPicker(),

      hasFeed ? el('h3', {}, 'Live output') : null,
      hasFeed ? eviltwinFeed() : null,

      certLibrary(),

      (e.captured || []).length
        ? el('div', {}, el('h3', {}, 'Captured earlier'), credentialTable(e))
        : null);
  }

  const s = e.session;
  const mimicked = String(s.certificate_source || '').includes('mimic');

  return el('div', {},
    el('div', { class: 'sitewide' },
      el('b', {}, 'IMPERSONATING ' + s.essid),
      ` - channel ${s.channel} on ${s.ifname}. `,
      el('span', { class: 'why' }, 'certificate: ' + (s.certificate_source || 'unknown'))),

    el('div', { class: 'actions', style: 'margin-top:14px' },
      el('button', {
        class: 'act danger',
        onclick: () => act('eapstop', '/api/eap/stop', null, 'Enterprise capture stopped'),
      }, 'Stop evil twin')),

    mimicked
      ? null
      : el('div', { class: 'note warn' },
        'This is a self-signed certificate carrying none of the target\u2019s naming. Every '
        + 'client that shows the user anything will refuse it. Clone the real certificate '
        + 'from the Access points tab and restart for the stronger pretext.'),

    // RADIUS activity as cards, so the one number that matters on site - captured credentials -
    // reads at a glance rather than being buried in a definition list. The card row has a stable
    // id so the running timer and counters can be refreshed in place every poll without rebuilding
    // the whole tab (renderEapLive).
    el('h3', {}, 'RADIUS'),
    el('div', { class: 'cards', id: 'eap-cards' }, ...eapCardsChildren(e, s)),

    // The presented certificate, in full. This is the pretext: if a client refused, this is what
    // it checked. Prefer the selected library entry (it has the whole picture) and fall back to
    // whatever the running session reported.
    el('h3', {}, 'Presented certificate'),
    (() => {
      const certList = ((S.data.certs && S.data.certs.networks) || {})[s.essid] || [];
      const activeCert = certList.find((c) => c.selected);
      if (activeCert) return certDetail(activeCert);
      return el('dl', { class: 'certdetail' },
        el('dt', {}, 'source'), el('dd', {}, s.certificate_source || 'unknown'),
        el('dt', {}, 'subject'), el('dd', { class: 'mono wrap' }, s.certificate_subject || '-'),
        el('dt', {}, 'issuer'), el('dd', { class: 'mono wrap' }, s.certificate_issuer || '-'),
        el('dt', {}, 'SHA-256'), el('dd', { class: 'mono wrap' }, s.certificate_fingerprint || '-'));
    })(),

    (e.clients || []).length
      ? el('div', {}, el('h3', {}, 'Associated'),
        el('ul', {}, ...e.clients.map((c) => el('li', {}, c.mac + ' since ' + hhmmss(c.since)))))
      : null,

    // Live output, eaphammer-style: associations, credential captures and certificate events as
    // they happen. Resizable for a clean screenshot.
    el('h3', {}, 'Live output'),
    eviltwinFeed(),

    el('h3', {}, 'Credentials'),
    credentialTable(e),

    certLibrary());
}

// certSrcClass colours a certificate by where it came from: a mimic of the real one is the strong
// pretext (good), an imported file is trusted input (info), a bare generated/self-signed one will
// be refused by any client that checks (warn).
const certSrcClass = (src) => ({
  mimic: 'good', imported: 'info', generated: '', 'self-signed': 'warn',
})[src] || '';

// certDetail is the full picture of one certificate, the feedback an operator wants after cloning:
// exactly what WARP captured and what the target's supplicant will be shown. Subject and issuer are
// the naming a user sees; the SAN list is what a strict client actually checks; the SHA-256 is how
// the clone is proven identical to the harvested original; the validity window and key say whether
// it is even usable. Nothing here is secret - it is all public certificate material.
function certDetail(c) {
  const sans = (c.sans || []).filter(Boolean);
  const fp = c.fingerprint_sha256 || c.fingerprint || '-';
  return el('dl', { class: 'certdetail' },
    el('dt', {}, 'subject'), el('dd', { class: 'mono wrap' }, c.subject || '-'),
    el('dt', {}, 'issuer'), el('dd', { class: 'mono wrap' }, c.issuer || '-'),
    el('dt', {}, 'SHA-256'), el('dd', { class: 'mono wrap' }, fp),
    el('dt', {}, 'SAN'),
    el('dd', { class: 'mono wrap' }, sans.length
      ? sans.join(', ')
      : el('span', { class: 'muted' }, 'none - a client that checks the name will refuse it')),
    el('dt', {}, 'valid'),
    el('dd', {}, c.expired
      ? el('span', { class: 'bad' }, 'EXPIRED (ended ' + day(c.not_after) + ')')
      : (day(c.not_before) + ' to ' + day(c.not_after))),
    el('dt', {}, 'key'),
    el('dd', {}, (c.key_algorithm || 'unknown') + (c.key_bits ? ' ' + c.key_bits + '-bit' : '')),
    el('dt', {}, 'source'),
    el('dd', {},
      el('span', { class: certSrcClass(c.source) }, c.source || 'unknown'),
      c.source_detail ? el('span', { class: 'muted' }, ' - ' + c.source_detail) : null),
    c.note ? el('dt', {}, 'note') : null,
    c.note ? el('dd', {}, c.note) : null,
    (c.cert_path || c.key_path) ? el('dt', {}, 'files') : null,
    (c.cert_path || c.key_path)
      ? el('dd', { class: 'mono wrap muted' }, [c.cert_path, c.key_path].filter(Boolean).join('   '))
      : null);
}

// eviltwinFeed is the live, resizable console for the rogue AP - WARP's answer to the scrolling
// output an operator watches in eaphammer. It filters the shared event stream to just what the
// evil twin produces (the RADIUS/EAP exchange, certificate harvest and selection) and labels each
// line by what it is: an association, a credential capture, a certificate rejection.
//
// The box and its scrolling body are built ONCE and cached on S, then re-used on every render
// rather than rebuilt. That is what makes it resizable in practice: a 2 s poll that recreated the
// element would abort an in-progress drag and flash the scrollbar each tick (the bug the field
// testers hit). Re-using the node means the poll only moves it, its dragged size lives on the node,
// and only the line contents are refreshed (fillEapFeed). A press anywhere inside it also sets an
// interacting flag so the poll holds off entirely until the mouse is released - so a drag is never
// interrupted mid-way.
function eviltwinFeed() {
  if (!S._eapfeedBody) {
    S._eapfeedBody = el('div', { class: 'console-body', id: 'eapfeed-body' });
    // Apply any remembered size through the CSSOM (CSP forbids a style attribute). Once the node
    // exists its own dragged size lives on it, so this only matters the first time it is built.
    let dims = 'resize:both;overflow:auto;';
    if (S.eapFeedH) dims += 'height:' + S.eapFeedH + 'px;';
    if (S.eapFeedW) dims += 'width:' + S.eapFeedW + 'px;';
    S._eapfeed = el('div', {
      class: 'console', id: 'eapfeed', style: dims,
      onpointerdown: () => { S._eapInteracting = true; },
      onpointerup: (e) => {
        S._eapInteracting = false;
        const n = e.currentTarget;
        if (n && n.offsetHeight) { S.eapFeedH = n.offsetHeight; S.eapFeedW = n.offsetWidth; }
      },
      onmouseleave: () => { S._eapInteracting = false; },
    }, S._eapfeedBody);
  }
  fillEapFeed();
  return S._eapfeed;
}

// fillEapFeed refreshes only the line contents of the cached console body, leaving the scrolling
// container (and its dragged size and scroll position) untouched. column-reverse keeps the newest
// line pinned to the bottom with no scroll bookkeeping.
function fillEapFeed() {
  if (!S._eapfeedBody) return;
  const interesting = new Set(['eap', 'harvest', 'certs']);
  const lines = (S.log || []).filter((e) => interesting.has(e.kind)).slice(-400);
  S._eapfeedBody.replaceChildren(...(lines.length
    ? lines.slice().reverse().map((e) => el('div', {
      class: 'cl ' + (e.level === 'good' ? 'good' : e.level === 'warn' ? 'warn' : 'dim'),
    }, el('span', { class: 'ts' }, e.at), feedTag(e), e.text))
    : [el('div', { class: 'muted' }, 'Waiting for the first supplicant. Associations, credential '
      + 'captures and certificate events will stream here as they happen.')]));
}

// eapCardsChildren builds the RADIUS activity cards for a running evil twin: the running timer and
// associations alongside the request/challenge/capture counters the field testers asked for. Kept
// as its own function so renderEapLive can refresh them in place each poll without a full rebuild.
function eapCardsChildren(e, s) {
  const stat = (k, v, cls, m) => el('div', { class: 'card' },
    el('div', { class: 'k' }, k),
    el('div', { class: 'v ' + (cls || '') }, v),
    m ? el('div', { class: 'm' }, m) : null);
  const assoc = (e.clients || []).length;
  return [
    s && s.started ? stat('running for', elapsed(s.started)) : null,
    stat('requests', e.stats?.requests ?? 0),
    stat('challenges', e.stats?.challenges ?? 0),
    stat('associations', assoc, assoc ? 'good' : ''),
    stat('captured', e.stats?.captured ?? 0, (e.stats?.captured ?? 0) ? 'good' : ''),
    (e.stats?.certificate_refused)
      // Correct client behaviour and a pass for those devices. Keeps the words "certificate
      // rejection" so it reads the same as the log line and the report.
      ? stat('cert refused', e.stats.certificate_refused, 'good',
        'certificate rejection(s) - the client validated the cert and refused it, correctly '
        + 'configured (no credential captured)')
      : null,
  ].filter(Boolean);
}

// renderEapLive refreshes the running evil twin's live regions - the counter/timer cards and the
// output console - in place every poll, so the timer ticks and the feed streams even when the rest
// of the tab is being held back (an in-progress resize, a text selection). It is a no-op off the
// tab or when stopped: the elements it targets do not exist.
function renderEapLive() {
  const e = S.data.eap || {};
  if (!e.running || !e.session) return;
  const cards = $('#eap-cards');
  if (cards) cards.replaceChildren(...eapCardsChildren(e, e.session));
  fillEapFeed();
}

// feedTag renders a short coloured label for a live feed line, read from the event's own fields so
// an association, a credential and a cert event are told apart at a glance.
function feedTag(e) {
  const f = e.fields || {};
  if (e.kind === 'harvest') return el('span', { class: 'cl-tag info' }, 'CERT');
  if (e.kind === 'certs') return el('span', { class: 'cl-tag info' }, 'CERT');
  if (e.kind === 'eap') {
    const t = String(e.text || '');
    if (t.indexOf('CLEARTEXT') >= 0) return el('span', { class: 'cl-tag bad' }, 'CRED');
    if (t.indexOf('MSCHAPv2') >= 0) return el('span', { class: 'cl-tag good' }, 'CRED');
    if (t.indexOf('rejected the certificate') >= 0) return el('span', { class: 'cl-tag warn' }, 'REJECT');
    if (f.event === 'client-join' || t.indexOf('associat') >= 0) return el('span', { class: 'cl-tag good' }, 'ASSOC');
    return el('span', { class: 'cl-tag' }, 'EAP');
  }
  return el('span', { class: 'cl-tag' }, '*');
}

// certLibrary renders every certificate the engagement could put on the air, per network.
//
// The certificate is the pretext, so this is not a detail of starting the rogue - it is the
// decision that determines whether anything is captured. Which one is selected, where each
// came from, and what a client will see are all on one screen.
function certLibrary() {
  const nets = (S.data.certs && S.data.certs.networks) || {};
  const names = Object.keys(nets).sort();

  return el('div', {},
    el('h3', {}, 'Certificate library'),

    names.length === 0
      ? el('div', { class: 'note' }, 'No scoped networks yet.')
      : el('div', {}, ...names.map((essid) => {
        const list = nets[essid] || [];
        return el('div', { class: 'certnet' },
          el('h4', {}, essid),

          list.length === 0
            ? el('div', { class: 'note warn' },
              'Nothing prepared. The rogue would generate a self-signed certificate, which '
              + 'every client that shows the user anything will refuse. Clone the real one '
              + 'from the Access points tab, or generate one below.')
            : el('table', { class: 'grid' },
              el('thead', {}, el('tr', {},
                el('th', {}, ''), el('th', {}, 'Source'), el('th', {}, 'Subject'),
                el('th', {}, 'Issuer'), el('th', {}, 'Expires'), el('th', {}, ''))),
              el('tbody', {}, ...list.map((c) => [el('tr', {},
                el('td', {},
                  c.selected
                    ? el('span', { class: 'good', title: 'the rogue will present this one' }, '●')
                    : el('span', { class: 'muted' }, '\u25cb')),
                el('td', {}, el('span', { class: certSrcClass(c.source), title: c.source_detail },
                  c.source)),
                el('td', { class: 'mono wrap' }, c.subject),
                el('td', { class: 'mono wrap muted' }, c.issuer),
                el('td', {}, c.expired
                  ? el('span', { class: 'bad' }, 'EXPIRED')
                  : day(c.not_after)),
                el('td', { class: 'actions' },
                  // Details reveals the full certificate - fingerprint, SANs, validity, key - so
                  // the operator can confirm what was cloned and what a client will be shown.
                  el('button', {
                    class: 'act tiny' + (S.certOpen[c.id] ? ' primary' : ''),
                    onclick: () => { S.certOpen[c.id] = !S.certOpen[c.id]; render(); },
                  }, S.certOpen[c.id] ? 'hide' : 'details'),
                  c.selected ? null : el('button', {
                    class: 'act tiny primary',
                    onclick: () => act('certsel:' + c.id, '/api/certs/select',
                      { essid: essid, id: c.id },
                      'The rogue will present ' + c.id + ' - restart it to take effect'),
                  }, 'use'),
                  el('button', {
                    class: 'act tiny danger',
                    onclick: () => {
                      confirmModal('Remove this saved certificate?', {
                        title: 'Delete ' + c.id + '?', okLabel: 'Delete', danger: true,
                      }).then((ok) => {
                        if (ok) act('certdel:' + c.id, '/api/certs/delete',
                          { essid: essid, id: c.id }, 'Certificate removed');
                      });
                    },
                  }, 'delete'))),
              S.certOpen[c.id]
                ? el('tr', { class: 'certdetail-row' },
                  el('td', { colspan: '6' }, certDetail(c)))
                : null]))),

          certWizard(essid));
      })),

    S.data.certs && S.data.certs.directory
      ? el('div', { class: 'note' }, 'Files: ' + S.data.certs.directory)
      : null);
}

// certWizard is the eaphammer-certwizard equivalent: type the fields, get a certificate.
//
// For when the target cannot be harvested - out of range, not yet observed, or an engagement
// that starts before the site visit - but the naming is known from a scoping call or a previous
// report. The fields are used verbatim: unlike a mimic, this is not a copy of anyone's real
// certificate, so nothing is silently mutated.
function certWizard(essid) {
  // Field values live in S, not in the DOM.
  //
  // The pane is rebuilt every poll - that is what keeps it live - and anything held only in an
  // input element goes with it. Typing a common name and watching it vanish two seconds later
  // is not a cosmetic problem: it makes the form unusable. The same applies to whether the
  // panel is open, which is why that is in S too.
  const form = (S.certForm[essid] = S.certForm[essid] || {});
  const key = (f) => 'cw-' + essid.replace(/[^A-Za-z0-9]/g, '_') + '-' + f;

  const field = (f, label, placeholder) => el('label', { class: 'field' },
    el('span', {}, label),
    el('input', {
      type: 'text',
      'data-fkey': key(f),
      value: form[f] || '',
      placeholder: placeholder || '',
      oninput: (e) => { form[f] = e.target.value; },
    }));

  return el('details', {
    class: 'wizard',
    ...(S.wizardOpen[essid] ? { open: 'open' } : {}),
    ontoggle: (e) => { S.wizardOpen[essid] = Boolean(e.target.open); },
  },
  el('summary', {
    // <details> toggling is native, but the shim has no such thing and a real browser only
    // fires ontoggle after the fact - tracking the click keeps S and the DOM in step either
    // way.
    onclick: () => { S.wizardOpen[essid] = !S.wizardOpen[essid]; },
  }, 'Generate a certificate for ' + essid),

  el('div', { class: 'note' },
    'Only the common name is required - it is what a trust prompt shows. The issuing '
    + 'authority matters nearly as much: most clients that prompt a human display it, and a '
    + 'certificate issued by an authority with its own name reads as self-signed in every '
    + 'viewer.'),

  el('div', { class: 'fields' },
    field('cn', 'Common name *', 'radius.acme-corp.internal'),
    field('o', 'Organization', 'ACME Corporation'),
    field('ou', 'Organizational unit', 'IT Infrastructure'),
    field('c', 'Country', 'US'),
    field('st', 'State'),
    field('l', 'Locality'),
    field('email', 'Email'),
    field('icn', 'Issuer common name', 'ACME Corporate Issuing CA'),
    field('io', 'Issuer organization', 'ACME Corporation'),
    field('dns', 'DNS names (comma separated)', 'radius.acme-corp.internal'),
    field('days', 'Validity in days', '825'),
    field('bits', 'RSA key bits', '2048')),

  el('div', { class: 'actions' },
    el('button', {
      class: 'act primary',
      onclick: () => {
        const cn = (form.cn || '').trim();
        if (!cn) {
          alertModal('A common name is required. It is what a supplicant\u2019s trust prompt '
            + 'shows, and a certificate without a plausible one is refused before anyone '
            + 'reads the rest.');
          return;
        }
        const days = parseInt(form.days, 10);
        const bits = parseInt(form.bits, 10);
        act('certgen:' + essid, '/api/certs/generate', {
          essid: essid,
          common_name: cn,
          organization: (form.o || '').trim(),
          organizational_unit: (form.ou || '').trim(),
          country: (form.c || '').trim(),
          province: (form.st || '').trim(),
          locality: (form.l || '').trim(),
          email: (form.email || '').trim(),
          issuer_common_name: (form.icn || '').trim(),
          issuer_organization: (form.io || '').trim(),
          dns_names: (form.dns || '').split(',').map((x) => x.trim()).filter(Boolean),
          validity_days: Number.isFinite(days) ? days : 0,
          key_bits: Number.isFinite(bits) ? bits : 0,
          note: 'generated from the browser',
        }, 'Certificate generated for ' + essid);
      },
    }, 'Generate'),
    el('button', {
      class: 'act',
      onclick: () => { S.certForm[essid] = {}; render(); },
    }, 'Clear')),

  el('div', { class: 'note' },
    'To import one made elsewhere, put the PEM files on the engagement box and run:'),
  el('pre', { class: 'mono' },
    'warp eap cert import ' + essid + ' --cert /path/cert.pem --key /path/key.pem'));
}

// credentialTable renders what the RADIUS server took. Nothing is redacted: it is the
// engagement's product, and a finding nobody can read is not a finding.
function credentialTable(e) {
  const rows = e.captured || [];
  if (!rows.length) {
    return el('div', { class: 'note' },
      'Nothing yet - a supplicant has to try to join.');
  }

  // The credential comes in two shapes: a cleartext password (TTLS-PAP, GTC) with no cracking step,
  // or an MSCHAPv2 hash line for hashcat -m 5500. The Type column says which; the Credential column
  // shows the actual value either way (the old table had only a "Hash line" column, which was blank
  // for a cleartext capture - hiding the very thing that was captured).
  const typeCell = (o) => (o.cleartext
    ? el('span', { class: 'bad' }, 'CLEARTEXT')
    : o.hash_line
      ? el('span', { class: 'info' }, 'MSCHAPv2')
      : el('span', { class: 'muted' }, 'none'));

  return el('div', {},
    el('table', { class: 'grid' },
      el('thead', {}, el('tr', {},
        el('th', {}, 'Identity'), el('th', {}, 'Outer'), el('th', {}, 'Method'),
        el('th', {}, 'Type'), el('th', {}, 'Credential'))),
      el('tbody', {}, ...rows.map((o) => el('tr', {},
        el('td', {}, el('span', { class: 'good' }, o.inner_identity || o.outer_identity || '-')),
        el('td', { class: 'muted' }, o.outer_identity || '-'),
        el('td', {}, o.method || '-'),
        el('td', {}, typeCell(o)),
        el('td', { class: 'mono wrap' }, o.cleartext || o.hash_line || '-'))))),
    rows.some((o) => o.cleartext)
      ? el('div', { class: 'note' },
        'Cleartext passwords (no cracking step) are written to '
        + (e.cleartext_file || 'creds/cleartext.txt') + '; MSCHAPv2 hashes to '
        + (e.creds_file || 'creds/mschapv2.5500') + ' (hashcat -m 5500).')
      : e.creds_file
        ? el('div', { class: 'note' }, 'Written to ' + e.creds_file + ' (hashcat -m 5500)')
        : null);
}

// jobDetail composes a job's Detail cell. A running hunt shows what it is tracking, live - the
// network, channel, and current/peak signal - rather than a static line, since the jobs tab is
// where an operator watching several attacks at once looks.
function jobDetail(j) {
  if (j.error) return j.error;
  if (j.kind === 'hunt' && j.state === 'running') {
    const h = (S.data.hunts || []).find((x) => x.target && x.target.addr === j.target);
    if (h) {
      const bits = [];
      if (h.target.essid) bits.push(h.target.essid);
      if (h.target.channel) bits.push('ch' + h.target.channel);
      if (h.has_signal) bits.push(h.current_rssi + ' dBm');
      if (h.has_peak) bits.push('peak ' + h.peak_rssi);
      return bits.join(' · ') || (j.detail || '');
    }
  }
  return j.detail || '';
}

function paneJobs() {
  const cols = [
    { key: 'id', label: '#', cell: (j) => j.id, sortVal: (j) => Number(j.id) },
    { key: 'kind', label: 'Kind', cell: (j) => j.kind, text: (j) => j.kind, sortVal: (j) => j.kind },
    { key: 'target', label: 'Target', cell: (j) => j.target || '-', text: (j) => j.target, sortVal: (j) => j.target || '' },
    {
      key: 'state', label: 'State',
      cell: (j) => el('span', {
        class: j.state === 'done' ? 'good' : j.state === 'running' ? 'warn'
          : (j.state === 'failed' || j.state === 'denied') ? 'bad' : 'muted',
      }, j.state),
      text: (j) => j.state, sortVal: (j) => j.state,
    },
    { key: 'started', label: 'Started', cell: (j) => hhmmss(j.started), sortVal: (j) => j.started || '' },
    { key: 'detail', label: 'Detail', wrap: true, cell: (j) => jobDetail(j), text: (j) => jobDetail(j) },
  ];
  return el('div', {}, toolbar('jobs'), table('jobs', cols, S.data.jobs, (j) => j.id));
}

// logText renders the whole in-memory log as plain text for copying or download.
function logText() {
  return (S.log || []).map((e) => `${e.at}  ${e.text}`).join('\n');
}

function paneLog() {
  return el('div', {},
    toolbar('log', [
      el('button', {
        class: 'act',
        onclick: async () => {
          try { await navigator.clipboard.writeText(logText()); toast('ok', 'Log copied to clipboard'); }
          catch { toast('err', 'Copy failed', 'the browser blocked clipboard access'); }
        },
      }, 'Copy whole log'),
      el('button', {
        class: 'act',
        onclick: () => {
          const blob = new Blob([logText()], { type: 'text/plain' });
          const url = URL.createObjectURL(blob);
          const a = el('a', { href: url, download: 'warp-log-' + Date.now() + '.txt' });
          document.body.append(a); a.click(); a.remove();
          setTimeout(() => URL.revokeObjectURL(url), 1000);
        },
      }, 'Download log'),
      el('span', { class: 'muted', style: 'margin-left:auto' }, `${(S.log || []).length} lines`),
    ]),
    el('div', { id: 'log' },
      ...S.log.slice(-500).map((e) =>
        el('div', { class: e.level === 'good' ? 'good' : e.level === 'warn' ? 'warn' : 'dim' },
          el('span', { class: 'ts' }, e.at), e.text))));
}

/* ----------------------------------------------------------------- sidebar */

function sideAP() {
  const ap = S.data.aps.find((a) => a.bssid === S.sel.aps);
  if (!ap) return el('div', { class: 'muted' }, 'Select an access point.');

  const mine = S.data.findings.filter((f) => f.bssid === ap.bssid);
  const stations = S.data.stations.filter((s) => s.bssid === ap.bssid);
  const busy = S.busy.has('ap:' + ap.bssid);

  return el('div', {},
    el('h2', { class: ap.rogue ? 'bad' : '' }, ap.bssid),
    el('div', { class: 'sub ' + (ap.rogue ? 'bad' : (ap.essid ? '' : 'muted')) },
      (ap.essid || '<hidden network>') + (ap.rogue ? '  (marked potential rogue)' : '')),

    el('dl', {},
      el('dt', {}, 'channel'), el('dd', {}, `${ap.channel || '-'}${ap.band ? ' · ' + ap.band : ''}${ap.phy ? ' · 802.11' + ap.phy : ''}`),
      el('dt', {}, 'signal'), el('dd', {}, signal(ap.last_rssi, ap.has_rssi, { stale: ap.has_rssi && !ap.active, ageSecs: ap.last_seen_secs })),
      el('dt', {}, 'peak'), el('dd', {}, ap.has_rssi ? `${ap.best_rssi} dBm${ap.best_rssi_radio ? ' · ' + ifnameFor(ap.best_rssi_radio) : ''}` : '-'),
      el('dt', {}, 'security'), el('dd', { class: secClassAP(ap) }, secLabel(ap)),
      el('dt', {}, 'mfp'), el('dd', {}, ap.security?.mfp || '-'),
      el('dt', {}, 'vendor'), el('dd', {}, ap.oui || '-'),
      el('dt', {}, 'beacons'), el('dd', {}, ap.beacons ?? 0),
      el('dt', {}, 'first seen'), el('dd', {}, hhmmss(ap.first_seen)),
      el('dt', {}, 'scope'), el('dd', {}, scopeCell(ap))),

    mine.length ? el('div', {}, el('h3', {}, 'Findings'),
      ...mine.map((f) => el('div', { class: 'finding ' + f.tier },
        el('b', { class: tierClass(f.tier) }, f.label),
        f.rationale ? el('p', {}, f.rationale) : null,
        f.differences?.length ? el('ul', {}, ...f.differences.map((d) => el('li', {}, d))) : null))) : null,

    // Clients are listed with their own deauthentication button rather than a single "deauth
    // a client" action, because which client gets knocked off is the operator's decision and
    // the audit log will name it.
    stations.length ? el('div', {}, el('h3', {}, `Clients (${stations.length})`),
      el('div', { class: 'stalist' },
        ...stations.slice(0, 20).map((s) => el('div', {},
          el('span', {}, s.mac),
          ap.in_scope && ap.security?.mfp !== 'required'
            ? el('button', {
              class: 'act tiny',
              onclick: (e) => {
                e.stopPropagation();
                deauthOptionsModal('Disconnect ' + s.mac + ' from ' + (ap.essid || ap.bssid)
                  + ' so it reauthenticates and a handshake can be captured.', {
                  title: 'Deauthenticate ' + s.mac + '?', okLabel: 'Deauth',
                }).then((o) => {
                  if (o) act('deauth:' + s.mac, '/api/psk/deauth',
                    { bssid: ap.bssid, station: s.mac, count: o.count, seconds: o.seconds },
                    'Deauthentication sent to ' + s.mac);
                });
              },
            }, 'deauth')
            : null)))) : null,

    el('h3', {}, 'Actions'),

    // Hunting is receive-only - it locks a radio to a channel and reads signal strength, it
    // transmits nothing - so it is offered at every access point, in scope or not. Walking
    // down an unknown transmitter in the client's footprint is the entire point of rogue
    // hunting, and gating it on scope would have removed the one thing you most want when a
    // device you cannot account for turns up.
    el('div', { class: 'actions' },
      ap.in_scope
        ? el('button', {
          class: 'act primary', ...(busy ? { disabled: 'disabled' } : {}),
          // On a WPA3/WPA2 transition BSS this is the downgrade: WARP associates offering only the
          // PSK AKM, forcing the WPA2 side, and reads the crackable PMKID from M1 - no client, no
          // passphrase. Labelled so the operator sees the downgrade for what it is.
          title: ap.security?.transition_mode
            ? 'Transition-mode downgrade: associate offering only the WPA2 (PSK) AKM, forcing the '
              + 'legacy side, and read the crackable PMKID from the AP\'s first message. No client '
              + 'or passphrase needed. WPA3-SAE itself has nothing to crack; the WPA2 path does.'
            : 'Associate and read the PMKID from the AP\'s first message - no client needed.',
          onclick: () => act('ap:' + ap.bssid, '/api/psk/solicit', { bssid: ap.bssid },
            ap.security?.transition_mode ? 'Transition downgrade started' : 'PMKID solicitation started'),
        }, ap.security?.transition_mode ? 'Downgrade & solicit PMKID' : 'Solicit PMKID')
        : null,

      // Broadcast deauthentication, matching the console's `d` on this tab. Acting on an
      // access point means acting on the access point: every client, which is what actually
      // provokes a handshake. Targeting one device is what the Clients tab is for, and the
      // browser had only that - so the most useful form of the attack was console-only.
      ap.in_scope && ap.security?.mfp !== 'required'
        ? el('button', {
          class: 'act danger', ...(busy ? { disabled: 'disabled' } : {}),
          title: 'Deauthenticate every client on this access point at once. This is an '
            + 'outage for the length of the campaign, and it is what provokes a handshake.',
          onclick: () => {
            const n = ap.clients || 0;
            deauthOptionsModal((n ? n + ' client(s) observed' : 'No clients observed yet')
              + ' - all of them are disconnected for the length of the campaign.', {
              title: 'Deauthenticate every client on "' + (ap.essid || ap.bssid) + '"?',
              okLabel: 'Deauth all',
            }).then((o) => {
              if (o) act('deauth:' + ap.bssid, '/api/psk/deauth',
                { bssid: ap.bssid, broadcast: true, count: o.count, seconds: o.seconds },
                'Broadcast deauthentication against ' + ap.bssid);
            });
          },
        }, 'Deauth all clients')
        : null,

      (() => {
        const live = (S.data.hunts || []).some((h) => h.target?.addr === ap.bssid);
        return el('button', {
          class: live ? 'act danger' : (ap.in_scope ? 'act' : 'act primary'),
          onclick: () => (live
            ? act('hunt:' + ap.bssid, '/api/hunt/stop', { addr: ap.bssid }, 'Hunt stopped')
            : act('hunt:' + ap.bssid, '/api/hunt/start', { addr: ap.bssid, audible: false },
              'Hunting ' + ap.bssid)),
        }, live ? 'Stop hunting' : 'Hunt');
      })(),

      // Mark this specific BSSID as a potential rogue. It is an operator judgement, not a
      // transmission, so it is offered on every access point - in scope or not, named or hidden -
      // and it never consults scope. It marks only this BSSID: siblings on the same ESSID are
      // untouched. The mark turns the name red and adds an evidence-tier finding whose evidence
      // points at manual evidence the operator supplies.
      el('button', {
        class: ap.rogue ? 'act danger' : 'act', ...(busy ? { disabled: 'disabled' } : {}),
        title: ap.rogue
          ? 'Remove the operator potential-rogue mark from this BSSID.'
          : 'Flag this specific BSSID as a potential rogue device (this BSSID only, not the whole '
            + 'ESSID). Adds an evidence-tier finding; you supply the evidence.',
        onclick: () => (ap.rogue
          ? act('ap:' + ap.bssid, '/api/rogue/unmark', { bssid: ap.bssid }, 'Rogue mark cleared')
          : act('ap:' + ap.bssid, '/api/rogue/mark', { bssid: ap.bssid },
            ap.bssid + ' marked as a potential rogue')),
      }, ap.rogue ? 'Unmark Rogue Device' : 'Mark Rogue Device'),

      (ap.in_scope && ap.essid)
        ? el('button', {
          class: 'act',
          title: 'Show the parsed beacon/probe-response encryption detail for this network '
            + '(any BSSID of this ESSID), in tshark-style output, with a copy button.',
          onclick: () => {
            const src = (S.data.aps || []).find((a) => a.essid === ap.essid && a.security
              && (a.security.ciphers || []).length) || ap;
            textModal('Encryption - ' + ap.essid,
              encryptionDetailText(src, ap.essid),
              cmdLine('Get it from the pcap yourself:', encryptionCommand(ap.essid)));
          },
        }, 'Encryption Packet')
        : null,
      (ap.in_scope && ap.essid)
        ? el('button', {
          class: 'act danger',
          title: 'Remove this network name from scope entirely. Active work there stops being '
            + 'authorized and its findings become out-of-scope context. Re-add it any time with '
            + '"Add to scope". Recorded in the audit log and written back to scope.txt.',
          onclick: () => {
            confirmModal('This removes "' + ap.essid + '" from scope - every access point '
              + 'broadcasting that name, not just this one. Active work there stops being '
              + 'authorized and its findings move to out-of-scope. You can re-add it any time.', {
              title: `Remove "${ap.essid}" from scope?`, okLabel: 'Remove from scope', danger: true,
            }).then((ok) => {
              if (ok) act('scoperm', '/api/scope/remove',
                { essid: ap.essid, note: 'removed from the browser interface' },
                ap.essid + ' removed from scope');
            });
          },
        }, 'Exclude')
        : null),

    ap.in_scope ? null : el('div', {},
      el('div', { class: 'note' },
        'Out of scope: this access point does not broadcast a scoped network name, so nothing ' +
        'here will transmit at it. Hunting is still available - it only listens.'),
      ap.essid
        ? el('div', { class: 'actions' },
          el('button', {
            class: 'act danger',
            title: 'Widen the engagement scope to this network name. Recorded in the audit '
              + 'log and written back to scope.txt.',
            onclick: () => {
              confirmModal('Active work becomes authorized at every access point broadcasting that '
                + 'name. This is recorded in the engagement audit log.', {
                title: `Add "${ap.essid}" to scope?`, okLabel: 'Add to scope', danger: true,
              }).then((ok) => {
                if (ok) act('scopeadd', '/api/scope/add',
                  { essid: ap.essid, note: 'added from the browser interface' },
                  ap.essid + ' added to scope');
              });
            },
          }, 'Add to scope'))
        : el('div', { class: 'note' },
          'Hidden network - there is no name to authorize until one is recovered.')),

    // Decloaking. Offered on any hidden network, in or out of scope, because "out of scope"
    // here only means "has no name yet" - that is the whole condition being fixed.
    ap.essid ? null : el('div', {},
      el('h3', {}, 'Hidden network'),
      el('div', { class: 'note' },
        'The name is not in the beacons, but it travels in clear text in every association '
        + 'request. Deauthenticating the clients makes them reassociate and name it. WARP '
        + 'holds every capture radio on channel ' + (ap.channel || '?') + ' and stops the '
        + 'moment the name arrives.'),
      ap.security?.mfp === 'required'
        ? el('div', { class: 'note warn' },
          '802.11w is required here, so the clients would ignore the deauthentication. The '
          + 'name cannot be recovered this way - keep listening instead.')
        // Decloaking is not gated on a confirmation. A cloaked network has no name to match
        // against scope, and the reason that matters is that it may well be in scope and there is
        // no way to find out except by decloaking it (invariant 1a) - so the action is always
        // available, in or out of scope. `scope confirm` stays advisory: it is recorded as context
        // in the audit log, never consulted when deciding. The one bar is 802.11w, handled above.
        : el('div', {},
          !ap.operator_confirmed ? el('div', { class: 'note' },
            'Out of scope only means the name is unknown. It may be in scope - decloaking is the '
            + 'only way to find out, so it is authorized here. Every frame is logged; you can '
            + 'record who this BSSID is with Confirm, but it is context, not a precondition.') : null,
          el('div', { class: 'actions' },
            el('button', {
              class: 'act primary', ...(busy ? { disabled: 'disabled' } : {}),
              title: 'Broadcast deauthentication until a client names the network.',
              onclick: () => act('decloak:' + ap.bssid, '/api/decloak', { bssid: ap.bssid },
                'Decloaking ' + ap.bssid),
            }, 'Decloak'),
            ap.operator_confirmed ? null : el('button', {
              class: 'act',
              title: 'Optional: record who this BSSID belongs to. Advisory only.',
              onclick: () => {
                promptModal('Recorded in the audit log as context. Decloaking does not require it.', '', {
                  title: 'Who is ' + ap.bssid + '?', okLabel: 'Confirm', placeholder: 'e.g. lobby AP, client-owned',
                }).then((note) => {
                  if (note) act('conf:' + ap.bssid, '/api/scope/confirm',
                    { bssid: ap.bssid, note: note }, ap.bssid + ' confirmed');
                });
              },
            }, 'Confirm (optional)')))),

    // WPS: one exchange, then the PIN falls offline - or it does not, and that is a pass.
    ap.security?.wps ? el('div', {},
      el('h3', {}, 'WPS'),
      el('div', { class: 'note' },
        'Pixie Dust runs one registration exchange - associate, four messages, disconnect - '
        + 'and recovers the PIN from it offline. Registration never completes and nothing '
        + 'joins the network. Online PIN brute force is not offered: it takes hours, locks '
        + 'WPS on the access point, and needs continuous contact.'),
      ap.security?.wps_locked
        ? el('div', { class: 'note warn' },
          'This access point advertises WPS as locked. The exchange will most likely be '
          + 'refused - which is the correct configuration and is recorded as a pass. Devices '
          + 'do misreport this and some unlock on a timer, so it is still worth trying.')
        : null,
      ap.in_scope
        ? el('div', { class: 'actions' },
          el('button', {
            class: 'act primary', ...(busy ? { disabled: 'disabled' } : {}),
            title: 'One WPS exchange; the PIN is recovered on this box afterwards.',
            onclick: () => act('wps:' + ap.bssid, '/api/wps', { bssid: ap.bssid },
              'Running one WPS exchange at ' + (ap.essid || ap.bssid)),
          }, 'Pixie Dust'))
        : el('div', { class: 'note warn' },
          'Out of scope: Pixie Dust associates to this access point, which is transmission. '
          + 'Add the network to scope first.')) : null,

    // Enterprise: the certificate is what makes the evil twin worth running.
    ap.security?.class === 'wpa_enterprise' ? el('div', {},
      el('h3', {}, 'Enterprise'),
      el('div', { class: 'note' },
        "Clone the RADIUS server's certificate before starting a rogue here. A self-signed "
        + 'certificate carrying none of this network’s naming is refused by every client '
        + 'that shows the user anything. The server presents its certificate in the clear to '
        + 'anyone starting a connection, so WARP associates to the access point itself and runs '
        + 'its own EAP-TLS client - like wpa_supplicant, minus the passphrase - and abandons the '
        + 'exchange the moment the certificate arrives. Nothing authenticates.'),
      ap.in_scope
        ? el('div', {},
          el('div', { class: 'actions' },
            el('button', {
              class: 'act', ...(busy ? { disabled: 'disabled' } : {}),
              title: 'Associate to the access point, run an EAP-TLS client, read the certificate it '
                + 'presents, and abandon the exchange. Saved to certs/ and used automatically the '
                + 'next time the rogue starts.',
              onclick: () => act('harvest:' + ap.bssid, '/api/harvest', { bssid: ap.bssid },
                'Reading the certificate at ' + ap.essid),
            }, 'Clone certificate'),

            // The evil twin itself. Cloning the certificate was the only enterprise action
            // here, which left the browser able to prepare the pretext and not to use it -
            // the capability existed and was reachable only from a console.
            (() => {
              const live = S.data.eap?.running && S.data.eap?.session?.essid === ap.essid;
              if (live) {
                return el('button', {
                  class: 'act danger',
                  onclick: () => act('eapstop', '/api/eap/stop', {}, 'Rogue access point stopped'),
                }, 'Stop evil twin');
              }
              return el('button', {
                class: 'act primary', ...(busy ? { disabled: 'disabled' } : {}),
                title: 'Beacon this network name and capture what supplicants send it. '
                  + 'Needs an adapter that can run AP mode.',
                onclick: () => {
                  confirmModal('WARP beacons this network name on channel ' + (ap.channel || '?')
                    + ' with its own RADIUS server behind it. Clients that do not validate the '
                    + 'certificate will send their credentials to it.', {
                    title: 'Impersonate "' + ap.essid + '"?', okLabel: 'Start evil twin',
                  }).then((ok) => {
                    if (ok) act('eapstart', '/api/eap/start',
                      { essid: ap.essid, channel: ap.channel || 0 }, 'Impersonating ' + ap.essid);
                  });
                },
              }, 'Start evil twin');
            })()),

          // Say which certificate will go on the air, before it does. Running the rogue with a
          // self-signed certificate is the weak pretext and it is worth knowing beforehand
          // rather than working it out from a client that refused.
          S.data.eap?.running && S.data.eap?.session?.essid === ap.essid
            ? el('div', { class: 'note' },
              'Running. Certificate: ' + (S.data.eap.session.certificate_source || 'unknown')
              + '. Captured credentials appear on the Credentials tab.')
            : el('div', { class: 'note' },
              'Clone the certificate first. Without one the rogue presents a self-signed '
              + 'certificate carrying none of this network\u2019s naming, which every client '
              + 'that shows the user anything will refuse.'))
        : el('div', { class: 'note warn' },
          'Out of scope: cloning the certificate and beaconing this name are both '
          + 'transmission. Add the network to scope first.')) : null,

    ap.security?.mfp === 'required'
      ? el('div', { class: 'note warn' },
        '802.11w is required here. Associated clients ignore unprotected deauthentication, so ' +
        'it is refused rather than transmitted - that is a hardening control on the network, ' +
        'not an exposure. Classification notes it as a control (802.11w required).')
      : null);
}

function sideStation() {
  const s = S.data.stations.find((x) => x.mac === S.sel.stations);
  if (!s) return el('div', { class: 'muted' }, 'Select a client device.');

  return el('div', {},
    el('h2', {}, s.mac),
    el('div', { class: 'sub' }, s.randomised_mac ? 'randomised MAC' : (s.oui || '')),
    el('dl', {},
      el('dt', {}, 'associated'), el('dd', {}, s.bssid || '-'),
      el('dt', {}, 'signal'), el('dd', {}, signal(s.last_rssi, s.has_rssi, { stale: s.has_rssi && !s.active, ageSecs: s.last_seen_secs })),
      el('dt', {}, 'peak'), el('dd', {}, s.has_rssi ? `${s.best_rssi} dBm` : '-'),
      el('dt', {}, 'frames'), el('dd', {}, s.frames ?? 0),
      el('dt', {}, 'first seen'), el('dd', {}, hhmmss(s.first_seen))),

    s.probed_essids?.length ? el('div', {}, el('h3', {}, 'Has looked for'),
      el('div', { style: 'font-family:var(--mono);font-size:12.5px;line-height:1.8' },
        ...s.probed_essids.map((e) => el('div', {}, e))),
      el('div', { class: 'note' },
        'Probed names leak where this device has connected before.')) : null,

    el('h3', {}, 'Actions'),

    // Targeted deauthentication: this device, from the access point it is actually on. The
    // most precise form there is, and it was console-only - the browser could deauthenticate
    // an entire access point but not one client, which is backwards.
    (() => {
      if (!s.bssid) {
        return el('div', { class: 'note' },
          'Not associated to anything, so there is nothing to deauthenticate it from. '
          + 'Hunting still works - it only listens.');
      }
      if (s.mfp === 'required') {
        return el('div', { class: 'note warn' },
          '802.11w is required on ' + (s.essid || s.bssid) + ', so this client ignores '
          + 'unprotected deauthentication. That is a hardening control on the network, not an '
          + 'exposure - classification records it as a control (802.11w required).');
      }
      if (!s.in_scope) {
        return el('div', { class: 'note warn' },
          'The network this client is on is not in scope, so nothing will transmit at it. '
          + 'Hunting still works - it only listens.');
      }
      return el('div', { class: 'actions' },
        el('button', {
          class: 'act danger',
          title: 'Disconnect this one device from ' + (s.essid || s.bssid)
            + ' so it reauthenticates and a handshake can be captured.',
          onclick: () => {
            deauthOptionsModal('Disconnect ' + s.mac + ' from ' + (s.essid || s.bssid)
              + ' so it reauthenticates and a handshake can be captured.', {
              title: 'Deauthenticate ' + s.mac + '?', okLabel: 'Deauth',
            }).then((o) => {
              if (o) act('deauth:' + s.mac, '/api/psk/deauth',
                { bssid: s.bssid, station: s.mac, count: o.count, seconds: o.seconds },
                'Deauthenticating ' + s.mac + ' from ' + (s.essid || s.bssid));
            });
          },
        }, 'Deauthenticate this client'));
    })(),

    el('div', { class: 'actions' },
      (() => {
        const live = (S.data.hunts || []).some((h) => h.target?.addr === s.mac);
        return el('button', {
          class: live ? 'act danger' : 'act',
          onclick: () => (live
            ? act('hunt:' + s.mac, '/api/hunt/stop', { addr: s.mac }, 'Hunt stopped')
            : act('hunt:' + s.mac, '/api/hunt/start', { addr: s.mac, audible: false },
              'Hunting ' + s.mac)),
        }, live ? 'Stop hunting' : 'Hunt this device');
      })()));
}

function sideFinding() {
  const f = S.data.findings.find((x) => x.bssid + '|' + x.label === S.sel.findings);
  if (!f) return el('div', { class: 'muted' }, 'Select a finding.');

  return el('div', {},
    el('h2', { class: tierClass(f.tier) }, f.tier.toUpperCase()),
    el('div', { class: 'sub' }, f.label),
    el('dl', {},
      el('dt', {}, 'bssid'), el('dd', {}, f.bssid),
      el('dt', {}, 'network'), el('dd', {}, f.essid || '-'),
      f.score !== undefined && f.score !== null ? el('dt', {}, 'similarity') : null,
      f.score !== undefined && f.score !== null ? el('dd', {}, f.score.toFixed(2)) : null),

    f.rationale ? el('div', {}, el('h3', {}, 'Why'),
      el('p', { style: 'font-size:13px;line-height:1.6;color:var(--text-dim);margin:0' }, f.rationale)) : null,

    f.differences?.length ? el('div', {}, el('h3', {}, 'Differing attributes'),
      el('ul', { style: 'font-size:12.5px;color:var(--text-dim);line-height:1.6;padding-left:18px;margin:0' },
        ...f.differences.map((d) => el('li', {}, d)))) : null,

    f.tier === 'evidence'
      ? el('div', { class: 'note warn' },
        'Evidence, not proof. An unusual but legitimate access point produces the same signal. ' +
        'Verify physically before acting.')
      : null);
}

function sideJob() {
  const j = S.data.jobs.find((x) => x.id === S.sel.jobs);
  if (!j) return el('div', { class: 'muted' }, 'Select a job.');
  return el('div', {},
    el('h2', {}, `Job ${j.id}`),
    el('div', { class: 'sub' }, j.kind),
    el('dl', {},
      el('dt', {}, 'target'), el('dd', {}, j.target || '-'),
      el('dt', {}, 'state'), el('dd', {}, j.state),
      el('dt', {}, 'started'), el('dd', {}, hhmmss(j.started))),
    j.error ? el('div', { class: 'note warn' }, j.error) : null,
    j.state === 'running'
      ? el('div', { class: 'actions' },
        el('button', {
          class: 'act danger',
          onclick: () => act('kill:' + j.id, '/api/jobs/kill', { id: j.id }, 'Job killed'),
        }, 'Kill job'))
      : null);
}

/* -------------------------------------------------------------------- render */

function render() {
  // The whole pane is rebuilt on every render, which would otherwise yank the cursor out of
  // the filter box mid-word on the next poll. Elements that hold a cursor carry a stable
  // data-fkey, and focus plus caret position are put back where they were.
  const was = document.activeElement;
  const fkey = was && was.dataset ? was.dataset.fkey : null;
  const start = fkey && was.selectionStart !== undefined ? was.selectionStart : null;
  const end = fkey && was.selectionEnd !== undefined ? was.selectionEnd : null;

  renderTabs();
  renderHeader();

  const panes = {
    overview: paneOverview, aps: paneAPs, stations: paneStations,
    hashes: paneHashes, findings: paneFindings, jobs: paneJobs, log: paneLog,
    radios: paneRadios, eviltwin: paneEvilTwin,
  };
  $('#pane').replaceChildren(panes[S.tab]());

  const sides = { aps: sideAP, stations: sideStation, findings: sideFinding, jobs: sideJob };
  const main = $('#main');
  if (sides[S.tab]) {
    main.classList.add('split');
    $('#side').replaceChildren(sides[S.tab]());
  } else {
    main.classList.remove('split');
    $('#side').replaceChildren();
  }

  if (fkey) {
    const next = document.querySelector(`[data-fkey="${CSS.escape(fkey)}"]`);
    if (next && next !== document.activeElement) {
      next.focus();
      if (start !== null) {
        try { next.setSelectionRange(start, end); } catch { /* not a text input */ }
      }
    }
  }
}

/* --------------------------------------------------------------------- data */

let lastSig = '';

// hasSelection reports whether the operator has a non-empty text selection right now, so a
// background redraw can hold off rather than deselecting what they are copying. Defensive about the
// environment: the test harness executes this JS with no window/getSelection.
function hasSelection() {
  try {
    const sel = (typeof window !== 'undefined' && window.getSelection) ? window.getSelection() : null;
    return !!(sel && !sel.isCollapsed && sel.toString().trim() !== '');
  } catch {
    return false;
  }
}

// isInteracting reports whether the operator is mid-interaction with a form control - an open or
// focused <select> (a country dropdown), or a focused text field. A background poll must not rebuild
// the body underneath that: it closes the dropdown and throws away what they were choosing/typing.
function isInteracting() {
  try {
    const a = document.activeElement;
    return !!a && (a.tagName === 'SELECT' || a.tagName === 'INPUT' || a.tagName === 'TEXTAREA');
  } catch {
    return false;
  }
}

// quietStatus strips the fields that change on every poll but never affect a decision, so the
// redraw signature ignores them: uptime, and each recon radio's live hopping channel.
function quietStatus(status) {
  if (!status) return status;
  const q = { ...status, uptime: null };
  if (status.recon && Array.isArray(status.recon.radios)) {
    // Null the fields that move every poll - the live hopping channel and the capture counters -
    // so a body rebuild is not forced constantly (which closes an open dropdown, drops a selection,
    // resets a half-typed field). The header updates these out-of-band on every poll regardless.
    q.recon = {
      ...status.recon,
      radios: status.recon.radios.map((r) => ({ ...r, channel: null, capture: null })),
    };
  }
  return q;
}

async function refresh() {
  try {
    const [status, aps, stations, findings, jobs, hashes, hunts, eap, radios, assignments, walkthroughs] =
      await Promise.all([
        api('/api/status'), api('/api/aps'), api('/api/stations'),
        api('/api/findings'), api('/api/jobs'), api('/api/hashes'), api('/api/hunt/state'),
        api('/api/eap'), api('/api/radios'), api('/api/assignments'), api('/api/walkthroughs'),
      ]);
    const certs = await api('/api/certs').catch(() => ({ networks: {} }));
    // Everything that should be a list is coerced to one. A handler that returns null, or an
    // error object, must not take the whole page down on the next render - the operator would
    // see a blank screen with no way to tell which call went wrong.
    const list = (v) => (Array.isArray(v) ? v : []);

    S.data.status = status;
    sampleRadioRates(status);
    S.data.aps = list(aps);
    S.data.stations = list(stations);
    S.data.findings = list(findings && findings.findings);
    S.data.unclassified = list(findings && findings.unclassified);
    S.data.jobs = list(jobs);
    // Keep the whole hashes object (wps_keys, counts, file paths) and only normalise the .hashes
    // list to an array. The old guard replaced the entire object when .hashes was null - which is
    // exactly what an empty PSK list serialises to - silently dropping a recovered WPS key that had
    // arrived with no PMKID/handshake alongside it.
    S.data.hashes = (hashes && typeof hashes === 'object')
      ? { ...hashes, hashes: Array.isArray(hashes.hashes) ? hashes.hashes : [] }
      : { hashes: [] };
    S.data.hunts = list(hunts);
    S.data.eap = eap || {};
    S.data.radios = list(radios);
    S.data.assignments = list(assignments);
    S.data.walkthroughs = list(walkthroughs);
    S.data.certs = (certs && certs.networks) ? certs : { networks: {} };

    // Only redraw when something actually moved. A rebuild every two seconds would wipe out
    // any text the operator had selected - and a BSSID they were halfway through copying is
    // exactly what they select. Uptime is excluded because it changes on every poll by
    // definition and never affects a decision. The per-radio *current* channel is excluded for
    // the same reason: a card sweeping hops it every dwell, and forcing a full rebuild on every
    // hop churned the radios tab constantly - losing a mid-edit channel form and any selection.
    const sig = JSON.stringify([
      quietStatus(status), aps, stations, findings, jobs, hashes, hunts, eap,
    ]);
    // The header (capture pill, per-radio live channel, counters) is cheap and touches only the
    // top bar, never the body - so refresh it every poll to keep the hopping channel live, even
    // when the body rebuild is being held off.
    renderHeader();

    // Keep any expanded walkthrough's device roll live while recon is still adding to it.
    if (S.tab === 'overview') refreshOpenWalkDevices();

    // Refresh the running evil twin's live cards and output console in place every poll, so the
    // timer ticks and the feed streams even when the full-body rebuild below is being held off.
    if (S.tab === 'eviltwin') renderEapLive();

    // Never rebuild the body while the operator has text selected: the rebuild deselects it, and
    // the hash line or BSSID they are mid-copy is exactly what they had selected. The evil-twin
    // output box adds one more hold: while the pointer is down inside it (a resize drag), a rebuild
    // would move the node and abort the drag. In every case lastSig is left unchanged so the redraw
    // happens on the next poll once the interaction is released.
    if (sig !== lastSig && !hasSelection() && !isInteracting() && !S._eapInteracting) {
      lastSig = sig;
      render();
    }
  } catch (err) {
    if (err.message !== 'not authenticated') console.error(err);
  }
}

// Server-sent events, so a captured PMKID appears the moment it lands rather than on the
// next poll.
function stream() {
  const es = new EventSource('/api/events');
  es.onmessage = (m) => {
    try {
      const ev = JSON.parse(m.data);
      S.log.push({ ...ev, at: new Date().toLocaleTimeString() });
      if (S.log.length > 2000) S.log = S.log.slice(-2000);
      if (ev.level === 'good' || ev.level === 'warn') {
        toast(ev.level === 'good' ? 'ok' : 'deny', ev.text);
      }
      if (S.tab === 'log' && !hasSelection()) render();
      // Stream rogue-AP events straight into the live console the moment they arrive, rather than
      // waiting for the 2 s poll. Only the cached feed body is touched, never the whole tab.
      if (S.tab === 'eviltwin') renderEapLive();
    } catch { /* ignore a malformed frame */ }
  };
  es.onerror = () => {
    // EventSource reconnects on its own; nothing to do but let it.
  };
}

// huntPoll refreshes just the hunt state on a fast timer while a hunt is live, so the signal in
// the banner tracks the antenna in near real time - 2 s is too slow to walk to a device by. It
// touches only the hunt banner (renderHunts), never the body, so it cannot disturb a selection.
async function huntPoll() {
  if (!Array.isArray(S.data.hunts) || !S.data.hunts.length) return;
  try {
    const hunts = await api('/api/hunt/state');
    S.data.hunts = Array.isArray(hunts) ? hunts : [];
    renderHunts();
  } catch { /* the 2 s poll will recover it */ }
}

function start() {
  showApp();
  render();
  refresh();
  stream();
  setInterval(refresh, 2000);
  // A hunt refreshes faster than the 2 s page poll so the signal tracks the antenna, but not so
  // fast it outruns the daemon's own sampling and makes the trend flicker. ~1.2 s is the sweet spot.
  setInterval(huntPoll, 1200);
}

// A token in the URL (as printed by warpd) logs straight in, then is scrubbed from the
// address bar so it does not linger in history.
(async function init() {
  const url = new URL(location.href);
  const token = url.searchParams.get('token');
  if (token) {
    try {
      await api('/login', { method: 'POST', body: { token } });
      history.replaceState(null, '', url.pathname);
      start();
      return;
    } catch { /* fall through to the login form */ }
  }

  try {
    await api('/api/status');
    start();
  } catch {
    showLogin();
    $('#token').focus();
  }
})();
