/* A DOM small enough to run the interface headlessly.
 *
 * Not a browser and not trying to be one: enough of the document, the event plumbing and the
 * network to let app.js load and render every tab, so a runtime error — a mistyped field
 * name, a helper that was renamed on one side only — fails a test instead of leaving a blank
 * page on an engagement box. See render_js_test.go.
 */

const ELEMENT_NODE = 1;
const TEXT_NODE = 3;

class Node {
  constructor(tag) {
    this.nodeType = ELEMENT_NODE;
    this.tagName = String(tag || 'div').toUpperCase();
    this.childNodes = [];
    this.parentNode = null;
    this.attributes = {};
    this.dataset = {};
    // Enough of CSSOM for the interface's use of it: app.js assigns cssText rather than a
    // style attribute, because CSP blocks the latter.
    this.style = { cssText: '' };
    this.className = '';
    this.title = '';
    this.listeners = {};
    this._value = '';
    this.selectionStart = 0;
    this.selectionEnd = 0;
  }

  get children() { return this.childNodes.filter((n) => n.nodeType === ELEMENT_NODE); }
  get firstElementChild() { return this.children[0] || null; }

  get value() { return this._value; }
  set value(v) { this._value = String(v); }

  get textContent() {
    return this.childNodes.map((n) => n.textContent).join('');
  }
  set textContent(v) { this.childNodes = [new TextNode(v)]; }

  get innerHTML() { return this.textContent; }
  set innerHTML(v) { this.textContent = v; }

  append(...nodes) {
    for (const n of nodes) {
      const node = (n && n.nodeType) ? n : new TextNode(n);
      node.parentNode = this;
      this.childNodes.push(node);
      register(node);
    }
  }

  replaceChildren(...nodes) {
    this.childNodes = [];
    this.append(...nodes);
  }

  // A download <a>.click() in the shim is a no-op: there is no file system or browser to save to,
  // and the tests only care that the action fired, not that a file landed.
  click() {}

  remove() {
    if (!this.parentNode) return;
    const i = this.parentNode.childNodes.indexOf(this);
    if (i >= 0) this.parentNode.childNodes.splice(i, 1);
    this.parentNode = null;
  }

  setAttribute(k, v) {
    this.attributes[k] = String(v);
    if (k === 'id') { this.id = String(v); byId[v] = this; }
    if (k === 'value') this._value = String(v);
    if (k.startsWith('data-')) {
      this.dataset[k.slice(5).replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = String(v);
    }
  }
  getAttribute(k) { return k in this.attributes ? this.attributes[k] : null; }

  addEventListener(type, fn) {
    (this.listeners[type] = this.listeners[type] || []).push(fn);
  }

  // fire drives a handler the way a click or a keystroke would. The tests use it to prove
  // the wiring exists, not to simulate a browser faithfully.
  fire(type, ev) {
    const e = ev || { preventDefault() {}, stopPropagation() {}, target: this };
    // A real DOM click fires both the onclick property and addEventListener handlers. renderHeader
    // sets onclick as a property (so a re-render replaces the handler rather than stacking), so the
    // shim must honour it too.
    const prop = this['on' + type];
    if (typeof prop === 'function') prop.call(this, e);
    for (const fn of this.listeners[type] || []) fn(e);
  }

  get classList() {
    const self = this;
    return {
      add(c) { if (!self.className.split(' ').includes(c)) self.className = (self.className + ' ' + c).trim(); },
      remove(c) { self.className = self.className.split(' ').filter((x) => x && x !== c).join(' '); },
      contains(c) { return self.className.split(' ').includes(c); },
    };
  }

  focus() { document.activeElement = this; }
  select() { /* text selection is a no-op here, but the method must exist */ }
  setSelectionRange(a, b) { this.selectionStart = a; this.selectionEnd = b; }

  // Test helpers, not part of the DOM.
  find(pred) {
    if (pred(this)) return this;
    for (const c of this.children) {
      const hit = c.find(pred);
      if (hit) return hit;
    }
    return null;
  }
  findAll(pred, out = []) {
    if (pred(this)) out.push(this);
    for (const c of this.children) c.findAll(pred, out);
    return out;
  }
}

class TextNode {
  constructor(t) {
    this.nodeType = TEXT_NODE;
    this.text = String(t);
    this.parentNode = null;
    this.childNodes = [];
  }
  get textContent() { return this.text; }
  get children() { return []; }
  find() { return null; }
  findAll(_, out = []) { return out; }
}

const byId = {};
function register(node) {
  if (node.nodeType !== ELEMENT_NODE) return;
  if (node.id) byId[node.id] = node;
  for (const c of node.children) register(c);
}

const document = {
  activeElement: null,
  createElement: (t) => new Node(t),
  createTextNode: (t) => new TextNode(t),
  // document-level events (the modal listens for Escape/Enter here). No-op: the tests drive
  // handlers directly rather than dispatching key events.
  addEventListener() {},
  removeEventListener() {},
  querySelector(sel) {
    if (sel.startsWith('#')) return byId[sel.slice(1)] || null;

    // [data-fkey="..."] — how the interface finds the element that had focus, and how the
    // certificate wizard reads its own fields back. A miss is a legitimate outcome.
    const m = /^\[data-fkey="(.*)"\]$/.exec(sel);
    if (m) {
      for (const root of roots()) {
        const hit = root.find((n) => n.dataset && n.dataset.fkey === m[1]);
        if (hit) return hit;
      }
      return null;
    }

    // .class — how modals and other appended-to-body elements are found. First match wins.
    if (sel.startsWith('.')) {
      const cls = sel.slice(1);
      for (const root of roots()) {
        const hit = root.find((n) => n.className && n.className.split(' ').includes(cls));
        if (hit) return hit;
      }
    }
    return null;
  },
};

// roots enumerates every subtree the shim might be asked to search: the shell elements by id, plus
// document.body (where modals and other detached overlays are appended).
function roots() {
  const all = Object.values(byId);
  if (document.body) all.push(document.body);
  return all;
}
document.body = new Node('body');

// The shell. __shellIds is injected from the real index.html by the Go harness, so the shim
// cannot drift away from the markup the browser actually gets.
for (const id of (globalThis.__shellIds || [])) {
  new Node('div').setAttribute('id', id);
}

const CSS = { escape: (s) => String(s) };
const console = { log() {}, error() {}, warn() {} };

function setTimeout() { return 0; }
function clearTimeout() {}
function setInterval() { return 0; }
function clearInterval() {}
function prompt() { return null; }

const location = { href: 'http://127.0.0.1:8443/', pathname: '/', search: '' };
const history = { replaceState() {} };

class URLSearchParams {
  constructor(q) {
    this.pairs = [];
    for (const part of String(q || '').split('&')) {
      if (!part) continue;
      const i = part.indexOf('=');
      this.pairs.push(i < 0 ? [part, ''] : [part.slice(0, i), decodeURIComponent(part.slice(i + 1))]);
    }
  }
  get(k) { const p = this.pairs.find((x) => x[0] === k); return p ? p[1] : null; }
  set(k, v) { this.pairs.push([k, String(v)]); }
  toString() { return this.pairs.map(([k, v]) => k + '=' + encodeURIComponent(v)).join('&'); }
  [Symbol.iterator]() { return this.pairs[Symbol.iterator](); }
}

class URL {
  constructor(href) {
    this.href = String(href);
    const i = this.href.indexOf('?');
    const path = i < 0 ? this.href : this.href.slice(0, i);
    this.pathname = '/' + path.split('/').slice(3).join('/');
    this.searchParams = new URLSearchParams(i < 0 ? '' : this.href.slice(i + 1));
  }
}

// Download plumbing: enough of Blob/URL/atob that the export helpers run without a real browser.
class Blob { constructor(parts, opts) { this.parts = parts || []; this.type = (opts && opts.type) || ''; } }
URL.createObjectURL = () => 'blob:shim';
URL.revokeObjectURL = () => {};
function atob(b64) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let s = String(b64).replace(/=+$/, '');
  let out = '';
  for (let bc = 0, bs = 0, i = 0; i < s.length; i += 1) {
    const c = chars.indexOf(s[i]);
    if (c < 0) continue;
    bs = bc % 4 ? bs * 64 + c : c;
    if (bc % 4) out += String.fromCharCode(255 & (bs >> ((-2 * bc) & 6)));
    bc += 1;
  }
  return out;
}

// Network: refused, so the load-time probe falls through to the login form and the tests
// drive state directly instead of racing a fetch.
function fetch() { return Promise.reject(new Error('no network in the shim')); }

class EventSource {
  constructor(url) { this.url = url; EventSource.last = this; }
  close() {}
}

// Test hook: the harness fills S.data and calls these.
function __byIdForTest() { return byId; }
function __render(tab) { S.tab = tab; render(); }
function __text(id) { return document.querySelector('#' + id).textContent; }

// __click finds a button by its visible text and clicks it.
//
// Buttons are how every action in this interface is reached, so a test that cannot press one
// can only check that text appeared — not that the control behind it does the right thing, or
// that a guard refuses before it does the wrong one.
function __click(label) {
  for (const root of Object.values(byId)) {
    const hit = root.find((n) =>
      n.tagName === 'BUTTON' && n.textContent.indexOf(label) !== -1);
    if (hit) { hit.fire('click'); return true; }
  }
  throw new Error('no button labelled ' + JSON.stringify(label));
}

// __fill sets an input's value by its data-fkey, the way an operator typing into it would.
function __fill(fkey, value) {
  const n = document.querySelector('[data-fkey="' + fkey + '"]');
  if (!n) throw new Error('no field ' + fkey);
  n.value = value;
  return true;
}

// __open expands every <details> so a collapsed section's contents are reachable. A browser
// would need a click; here the content exists either way and this makes that explicit.
function __open() {
  for (const root of Object.values(byId)) {
    for (const n of root.findAll((x) => x.tagName === 'DETAILS')) n.setAttribute('open', '');
  }
  return true;
}
