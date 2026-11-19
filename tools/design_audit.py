#!/usr/bin/env python3
"""Measure the UI instead of looking at it, across widths and both themes.

A screenshot proves a page rendered. It does not prove the text is readable,
that the layout does not overflow a phone, or that a control is reachable --
and a reviewer eyeballing a screenshot gets contrast wrong almost every time.
This drives a real browser and measures:

  * text contrast against the actually-painted background (walking up to the
    first non-transparent ancestor), against the WCAG AA threshold for that
    element's own size and weight;
  * tap targets on the real hit area -- the wrapping <label> where there is
    one, not the 16px checkbox inside it;
  * horizontal overflow at phone width;
  * keyboard focus visibility, by pressing Tab;
  * uncaught JS errors and console errors;
  * the type scale and font stacks in use, so drift is visible.

    python tools/design_audit.py                        # starts its own server
    python tools/design_audit.py --out /tmp/shots       # keep the screenshots
    python tools/design_audit.py --url http://host:5000/

Exits non-zero when something measured fails. Needs playwright
(requirements-dev.txt) and a browser; it skips with a message otherwise.

Three cautions this script exists to encode, each of which produced a false
finding before it was understood:

  * `el.focus()` does not put Chrome into `:focus-visible` for a button, so
    probing focus that way reports a correctly-styled page as having none.
    Tab is the only honest way to ask.
  * a focus ring often lives on a wrapper via `:focus-within`, so checking
    only `document.activeElement` reports composed controls as unfocusable.
  * a 16x16 checkbox is not a 16x16 tap target when it sits inside a 294x137
    label. Measure what the user can actually hit.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import pathlib
import socket
import sys
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent

# (name, path, width, height, theme)
#
# /api/docs is a second page with its own template and its own stylesheet.
# It was outside every earlier audit, which only ever loaded "/", so nothing
# had measured its contrast, its tap targets or its focus rings -- on the
# one page an integrator reads before writing a client.
# (name, path, width, height, theme, populate)
#
# `populate` runs a search against stubbed sources before measuring. Without
# it this tool only ever saw the empty landing screen: the results surface,
# which is where the operator spends the whole session, had never been
# measured at any width in either theme -- and that is where the severity
# badge, the EPSS bar, the per-card meta row and the warnings live. The
# first look at it found an empty <code> painted after the count, severity
# encoded twice, and a warning toast sitting on top of a card title.
STATES = [
    ("01-landing-dark", "", 1440, 900, "dark", False),
    ("02-landing-light", "", 1440, 900, "light", False),
    ("03-mobile-dark", "", 390, 844, "dark", False),
    ("04-mobile-light", "", 390, 844, "light", False),
    ("05-narrow", "", 320, 844, "dark", False),
    ("06-tablet", "", 820, 1180, "dark", False),
    ("07-wide", "", 1920, 1080, "light", False),
    ("08-apidocs-dark", "api/docs", 1440, 900, "dark", False),
    ("09-apidocs-light", "api/docs", 1440, 900, "light", False),
    ("10-apidocs-mobile", "api/docs", 390, 844, "dark", False),
    ("11-results-dark", "", 1440, 900, "dark", True),
    ("12-results-light", "", 1440, 900, "light", True),
    ("13-results-mobile", "", 390, 844, "dark", True),
    ("14-results-narrow", "", 320, 844, "light", True),
    # Overlays. Each floats above the page on its own surface -- two of
    # them translucent -- so their contrast is a property of the stack, not
    # of any rule in the sheet, and none of it had ever been measured. The
    # filter drawer is worse than unmeasured: below 1180px it IS the only
    # way to reach the controls, and its rules live solely inside a media
    # query, so no desktop state could have touched them either.
    ("15-filter-drawer", "", 390, 844, "dark", False, "drawer"),
    ("16-cwe-combo", "", 1440, 900, "light", False, "combo"),
    ("17-toast", "", 1440, 900, "dark", False, "toast"),
    ("18-history", "", 1440, 900, "light", False, "history"),
    ("19-auth-gate", "", 1440, 900, "dark", False, "gate"),
]

# Each opener puts exactly one extra surface on screen, and names the
# selector that must be VISIBLE before anything is measured. The wait is
# the point: without it a trigger that silently stopped working would let
# the state measure the ordinary page underneath and report a clean pass
# for a surface nobody had looked at. That is how "18-history" passed on
# its first run here -- it waited for a button that is always present, so
# it measured the results page twice and called it an overlay.
OVERLAYS = {
    "drawer": ".control-rail",
    "combo": ".combo-list li",
    "toast": ".toast",
    "history": "#history-section .history-list li",
    "gate": "#auth-gate .auth-gate-card",
}

# There is deliberately no "export" entry. open-findings.md listed the
# export popover among the surfaces this tool never opened, on the reasoning
# that a closed <details> gives its children zero-size rects. Measured, that
# is false: its three format buttons and its label appear in the ordinary
# results states whether the popover is open or shut, because the popover is
# positioned rather than display:none. A state for it measured 223 text
# nodes and 74 targets -- identical to 12-results-light, element for element
# -- which is the duplicate-coverage false pass this file already learned
# once from the recent-searches state. A state that measures nothing new is
# worse than no state, because the count implies coverage.

# One advisory per severity band, each carrying the fields the card renders:
# a KEV flag, several sources, a CWE label, a package range and an EPSS
# score. Stubbed at the network boundary, so no credentials and no requests.
_SEVERITIES = ("critical", "high", "medium", "low")


def _sample_advisory(index: int) -> dict:
    severity = _SEVERITIES[index % 4]
    return {
        "advisory_id": f"GHSA-aaaa-bbbb-{index:04d}",
        "ghsa_id": f"GHSA-aaaa-bbbb-{index:04d}",
        "cve_id": f"CVE-2026-{1000 + index}",
        "severity": severity,
        "summary": ("Improper access control allows an authenticated user to "
                    "read another tenant's records"),
        "description": "d" * 280,
        "cvss_score": (9.8, 8.1, 5.4, 3.1)[index % 4],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwes": ["639"],
        "cwe_labels": [{"id": "639",
                        "label": "Authorization Bypass Through User-Controlled Key"}],
        "packages": [{"ecosystem": "npm", "name": "lodash",
                      "vulnerable_version_range": "< 4.17.21",
                      "first_patched_version": "4.17.21"}],
        "ecosystems": ["npm"],
        "sources": ["ghsa", "nvd"],
        "published_at": "2026-08-15T00:00:00Z",
        "updated_at": "2026-09-01T00:00:00Z",
        "html_url": "https://github.com/advisories/GHSA-aaaa-bbbb",
        "epss_percentage": (0.97, 0.42, 0.08, 0.01)[index % 4],
        "epss_percentile": (0.99, 0.78, 0.31, 0.05)[index % 4],
        "kev": index % 4 == 0,
        "aliases": [f"CVE-2026-{1000 + index}"],
        # The verdict block is half the height of a scored card -- the
        # coloured state dot, the confidence bar, the reason prose and the
        # two notes on the score -- and none of it was measured, because
        # the fixture stopped at the advisory. `a.ai` is the render
        # fallback the UI already uses, so no endpoint needs stubbing.
        # All four verdict classes appear across the six records.
        "ai": _sample_verdict(index),
    }


_VERDICTS = (
    {"is_match": True, "confidence": 0.94, "vuln_type": "IDOR",
     "reason": "The advisory describes an authenticated user reading another "
               "tenant's records by supplying a different identifier, which "
               "is the access-control failure this class covers.",
     "cached": False, "has_errors": False},
    {"is_match": False, "confidence": 0.12, "vuln_type": "",
     "reason": "A denial of service in the parser; no authorization decision "
               "is involved.",
     "cached": True, "has_errors": False},
    {"is_match": True, "confidence": 0.71, "vuln_type": "Path traversal",
     "reason": "Reads a file outside the intended directory. Scored from the "
               "summary alone; the description was unavailable.",
     "cached": True, "has_errors": True},
    {"is_match": None, "confidence": 0.0, "vuln_type": "",
     "reason": "Scoring failed for one of the selected classes.",
     "cached": False, "has_errors": True},
)


def _sample_verdict(index: int) -> dict:
    return dict(_VERDICTS[index % 4])


def _stub_and_search(page) -> None:
    """Fill the workspace with results, without touching the network."""
    records = [_sample_advisory(i) for i in range(6)]
    body = json.dumps({
        "results": records,
        "count": len(records),
        "query": {"categories": ["bac"], "max_results": 100, "cwes": ["639"]},
        # One warning, so the slot that used to be a toast is measured too.
        "warnings": ["NVD cannot filter by ecosystem, so its rows were "
                     "filtered locally."],
        "stats": {"fetched_per_source": {"ghsa": 4, "nvd": 3},
                  "after_merge": 6, "after_filter": 6, "truncated": False},
    })
    page.route("**/api/search", lambda route: route.fulfill(
        status=200, content_type="application/json", body=body))
    page.evaluate("""() => {
      const box = document.querySelector('input[name=category]');
      box.checked = true;
      box.dispatchEvent(new Event('change', {bubbles: true}));
    }""")
    # Clicked through the DOM: below the panel breakpoint the rail is a
    # slide-over, so the button is off-screen and a real click cannot reach
    # it -- which would make the two narrow states silently measure the
    # empty page instead of the results.
    page.evaluate("() => document.querySelector('#search-btn').click()")
    page.wait_for_selector(".card", timeout=20000)

# Two recent searches, in the shape loadHistory() accepts: it drops any
# row whose categories do not survive sanitizeCategories(), so an invented
# class here would leave the list empty and the section hidden.
_HISTORY = json.dumps([
    {"sig": "a", "at": 1763000000000, "count": 128, "matches": 31,
     "query": {"categories": ["bac"], "sources": ["ghsa", "nvd"],
               "max_results": 100, "severity": [], "ecosystem": []}},
    {"sig": "b", "at": 1762800000000, "count": 6, "matches": 0,
     "query": {"categories": ["ssrf"], "sources": ["ghsa"],
               "max_results": 50, "severity": ["critical"], "ecosystem": ["npm"]}},
])


def _open_overlay(page, kind: str) -> None:
    """Put one more surface on screen and wait for it, or raise."""
    wanted = OVERLAYS[kind]
    if kind == "toast":
        # A real failure path, not a hand-made lookalike: with every source
        # unticked, Search refuses and says so. Going through the app's own
        # toast() is what makes this measure the element the UI builds.
        page.evaluate("""() => {
          document.querySelectorAll('input[name=source]').forEach(el => {
            el.checked = false;
            el.dispatchEvent(new Event('change', {bubbles: true}));
          });
          document.querySelector('#search-btn').click();
        }""")
    elif kind == "history":
        # Recent searches are read from localStorage at load, so they have
        # to be seeded before the page runs rather than after.
        page.evaluate(
            "rows => localStorage.setItem('vulnsight_history', rows)", _HISTORY)
        page.reload(wait_until="networkidle")
    elif kind == "gate":
        # Nothing to do: this state runs against a server started with a
        # token, and the page raises the gate itself on load.
        pass
    elif kind == "combo":
        page.fill("#cwe-search", "sql")
    else:
        page.click("#filters-toggle")
    page.wait_for_selector(wanted, state="visible", timeout=8000)
    if kind == "drawer":
        # Sources and Options ship folded, and a <details> that is shut
        # renders nothing to measure -- so folding them would have quietly
        # dropped every control inside from the contrast and tap-target
        # counts, and this state is the only one that opens the rail at all.
        # Expanding here keeps the drawer measuring the whole rail.
        page.evaluate(
            "() => document.querySelectorAll('.control-rail details')"
            ".forEach(el => { el.open = true; })")
        # A control from inside a fold, not the heading: the heading is
        # visible whether the section is open or shut, so waiting on it
        # would pass over a rail that never expanded -- and this state is
        # the only one that opens the rail at all, so everything inside
        # both folds would silently leave the counts.
        page.wait_for_selector("#max_results", state="visible", timeout=8000)


MEASURE = r"""
() => {
  const srgb = c => (c /= 255) <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  const lum = ([r, g, b]) => 0.2126 * srgb(r) + 0.7152 * srgb(g) + 0.0722 * srgb(b);
  // getComputedStyle returns two unrelated notations: rgb()/rgba() in 0-255,
  // and color(srgb r g b) -- which is what color-mix() resolves to -- in
  // 0-1. Reading the second as the first made #eff1f3 look almost black and
  // reported 16:1 text as 1.17:1. Normalise before comparing anything.
  const parse = s => {
    const n = (String(s).match(/[\d.]+/g) || []).slice(0, 4).map(Number);
    if (/^color\(/i.test(String(s).trim())) {
      return n.slice(0, 3).map(v => v * 255).concat(n.slice(3));
    }
    return n;
  };
  const shown = el => {
    const s = getComputedStyle(el);
    return s.display !== 'none' && s.visibility !== 'hidden' && s.opacity !== '0';
  };
  // The painted background is what the stack of ancestors actually composites
  // to, not the element's own `background-color`, which is usually
  // transparent.
  //
  // This used to return the first ancestor with any alpha at all and throw
  // the alpha away -- so a 12%-opacity tint over a panel was measured as if
  // it were the tint at full strength. That is wrong in both directions: it
  // invented a failure for accent-coloured text on a faint accent wash, and
  // it would equally have passed white text on a 5% black veil over white.
  // Four surfaces in this sheet are translucent by design (--topbar-bg,
  // --rail-bg, --empty-bg, --scrim-bg), so every contrast figure measured
  // through one of them was approximate at best.
  const bgOf = el => {
    const layers = [];
    for (let n = el; n; n = n.parentElement) {
      const c = parse(getComputedStyle(n).backgroundColor);
      if (c.length < 3) continue;
      const a = c.length === 3 ? 1 : c[3];
      if (a <= 0) continue;
      layers.push([c[0], c[1], c[2], a]);
      if (a >= 1) break;          // nothing below an opaque layer shows
    }
    // Composite bottom-up, source-over. If no opaque layer was found the
    // canvas shows through; `color-scheme` paints that white in light mode
    // and near-black in dark, and the UA exposes it on the root.
    const bottom = layers.length && layers[layers.length - 1][3] >= 1
      ? layers.pop().slice(0, 3)
      : parse(getComputedStyle(document.documentElement).backgroundColor)
          .slice(0, 3);
    let out = bottom.length >= 3 ? bottom : [255, 255, 255];
    for (let i = layers.length - 1; i >= 0; i--) {
      const [r, g, b, a] = layers[i];
      out = [r * a + out[0] * (1 - a),
             g * a + out[1] * (1 - a),
             b * a + out[2] * (1 - a)];
    }
    return out;
  };
  const ratio = (fg, bg) => {
    const [a, b] = [lum(fg), lum(bg)].sort((x, y) => y - x);
    return (a + 0.05) / (b + 0.05);
  };

  const text = [];
  const seen = new Set();
  for (const el of document.querySelectorAll('body *')) {
    if (!shown(el)) continue;
    const own = [...el.childNodes]
      .filter(n => n.nodeType === 3 && n.textContent.trim())
      .map(n => n.textContent.trim()).join(' ');
    if (!own) continue;
    const box = el.getBoundingClientRect();
    if (box.width < 2 || box.height < 2) continue;   // visually hidden
    const style = getComputedStyle(el);
    const size = parseFloat(style.fontSize);
    const weight = Number(style.fontWeight) || 400;
    const r = ratio(parse(style.color).slice(0, 3), bgOf(el));
    const large = size >= 24 || (size >= 18.66 && weight >= 700);
    const need = large ? 3.0 : 4.5;
    const key = `${own.slice(0, 40)}|${size}|${Math.round(r * 100)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    text.push({
      sample: own.slice(0, 56), size, weight,
      ratio: Math.round(r * 100) / 100, required: need, passes: r >= need,
      tag: el.tagName.toLowerCase(),
      cls: (typeof el.className === 'string' ? el.className.split(/\s+/)[0] : ''),
    });
  }

  // The hit area is the wrapping label where there is one: a 16px checkbox
  // inside a 294x137 label is a 294x137 target.
  const targets = [];
  for (const el of document.querySelectorAll(
      'button, a[href], input, select, summary, [role="button"]')) {
    if (!shown(el)) continue;
    const lab = el.closest('label')
      || (el.id && document.querySelector(`label[for="${CSS.escape(el.id)}"]`));
    const own = el.getBoundingClientRect();
    const wrap = lab && lab.getBoundingClientRect();
    // Clicking the caption focuses the control, so the caption counts -- but
    // only when it is the bigger surface. A caption-only or .sr-only label
    // is smaller than the control and is not the hit area.
    const useLabel = wrap && wrap.width * wrap.height > own.width * own.height;
    const box = useLabel ? wrap : own;
    if (!box.width || !box.height) continue;
    targets.push({
      tag: el.tagName.toLowerCase(), type: el.type || '',
      via: useLabel ? 'label' : 'self',
      label: (el.textContent || el.getAttribute('aria-label') || '').trim().slice(0, 36),
      w: Math.round(box.width), h: Math.round(box.height),
    });
  }

  const sizes = {};
  for (const el of document.querySelectorAll('body *')) {
    if (!shown(el)) continue;
    const px = parseFloat(getComputedStyle(el).fontSize);
    if (px) sizes[px] = (sizes[px] || 0) + 1;
  }

  // Characters per line, for the blocks a reader has to read rather than
  // scan. Measured from the element's own font -- the `ch` unit is the
  // width of a zero, which for a proportional face is far wider than the
  // average glyph, so a CSS cap in `ch` does not tell you what you got.
  // The AI's reasoning ran 150 characters a line at 1440 and 186 at 1920,
  // which is the one block on the page that has to be read closely.
  const prose = [];
  for (const el of document.querySelectorAll('p, .desc, .lede, .search-warnings li, .hint')) {
    const words = (el.innerText || '').trim();
    if (words.length < 70 || !shown(el)) continue;
    const box = el.getBoundingClientRect();
    if (!box.width) continue;
    const style = getComputedStyle(el);
    const probe = document.createElement('canvas').getContext('2d');
    probe.font = `${style.fontStyle} ${style.fontWeight} ${style.fontSize} ${style.fontFamily}`;
    const advance = probe.measureText('abcdefghijklmnopqrstuvwxyz ').width / 27;
    if (!advance) continue;
    const inner = box.width
      - parseFloat(style.paddingLeft) - parseFloat(style.paddingRight);
    prose.push({
      cls: String(el.className || el.tagName).slice(0, 30),
      chars: Math.round(inner / advance),
      sample: words.slice(0, 40),
    });
  }

  return {
    text, targets, prose,
    typeScale: Object.entries(sizes).sort((a, b) => b[1] - a[1]).slice(0, 12),
    fonts: [...new Set([...document.querySelectorAll('body *')]
      .map(e => getComputedStyle(e).fontFamily))].slice(0, 6),
    overflowX: document.documentElement.scrollWidth > window.innerWidth + 1,
    scrollWidth: document.documentElement.scrollWidth,
    innerWidth: window.innerWidth,
    h1: [...document.querySelectorAll('h1')].map(h => h.textContent.trim()),
  };
}
"""

# Walks ancestors: a wrapper with :focus-within is the normal pattern for a
# composed control, and checking only activeElement reports those as bare.
FOCUS_RING = r"""
() => {
  const ident = el => ({
    tag: el.tagName.toLowerCase(), id: el.id,
    text: (el.textContent || el.getAttribute('aria-label') || '').trim().slice(0, 30),
  });
  const el = document.activeElement;
  if (!el || el === document.body) return null;
  for (let n = el; n && n !== document.body; n = n.parentElement) {
    const s = getComputedStyle(n);
    const outline = s.outlineStyle !== 'none' && parseFloat(s.outlineWidth) > 0;
    const shadow = s.boxShadow && s.boxShadow !== 'none';
    // Identity is returned either way: keying only the failures collapsed
    // every passing stop into one and reported "1/1 focus stops".
    if (outline || shadow) return { ok: true, ...ident(el), on: n.tagName.toLowerCase() };
  }
  return { ok: false, ...ident(el) };
}
"""


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@contextlib.contextmanager
def serve(token: str | None = None):
    """Run the app on a loopback port, as the e2e suite does.

    `token` configures VULNSIGHT_API_TOKEN for this server only. The auth
    gate is reachable no other way: the UI shows it when the *server* said
    a token is required, so flipping a flag in the page would audit a
    lookalike rather than the dialog an operator actually meets -- and
    would skip the background-inert and focus-trap the real path applies,
    which is most of what there is to measure about a modal.
    """
    import wsgiref.simple_server
    from wsgiref.simple_server import WSGIRequestHandler

    sys.path.insert(0, str(ROOT))
    os.environ.setdefault("VULNSIGHT_BIND", "127.0.0.1")
    os.environ["VULNSIGHT_RATE_LIMIT"] = "off"
    previous = os.environ.get("VULNSIGHT_API_TOKEN")
    if token:
        os.environ["VULNSIGHT_API_TOKEN"] = token
    else:
        os.environ.pop("VULNSIGHT_API_TOKEN", None)
    import app as app_module

    class Quiet(WSGIRequestHandler):
        # The parameter name matches BaseHTTPRequestHandler's, shadowing the
        # builtin; renaming it is a signature mismatch to a type checker.
        def log_message(self, format, *args):
            pass

    port = free_port()
    httpd = wsgiref.simple_server.make_server(
        "127.0.0.1", port, app_module.create_app(), handler_class=Quiet)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}/"
    finally:
        httpd.shutdown()
        httpd.server_close()      # shutdown() alone leaks the listening socket
        thread.join(timeout=5)
        if previous is None:
            os.environ.pop("VULNSIGHT_API_TOKEN", None)
        else:
            os.environ["VULNSIGHT_API_TOKEN"] = previous


def launch(pw):
    try:
        return pw.chromium.launch()
    except Exception:
        return pw.chromium.launch(channel="chrome")


def duplicate_states(report: dict, states) -> list[str]:
    """Overlay states that measured exactly what the page at rest did.

    This is the check the recent-searches state needed and did not have.
    It waited for `.history-drop`, a button that is present whether or not
    the panel is open, so it measured the results page element for element
    -- 223 text nodes, 74 targets -- and reported a clean pass for a
    surface nobody had opened. Waiting for a *visible* selector is not
    enough, because the selector was visible.

    So each overlay state is compared against the plain state of the same
    shape (same path, viewport, theme and populate flag). Identical counts
    mean the opener did nothing and the state is counting the page twice,
    which is worse than having no state at all: the number of states
    implies coverage.
    """
    base_by_shape = {state[1:6]: state[0] for state in states
                     if len(state) == 6}
    found: list[str] = []
    for state in states:
        if len(state) <= 6:
            continue
        name = state[0]
        if name not in report:
            continue
        base = base_by_shape.get(tuple(state[1:6]))
        if not base or base == name or base not in report:
            continue
        here, there = report[name], report[base]
        if (len(here["text"]), len(here["targets"])) == (
                len(there["text"]), len(there["targets"])):
            found.append(
                f"{name}: measured {len(here['text'])} text nodes and "
                f"{len(here['targets'])} targets -- identical to {base}, so "
                f"the overlay added nothing and this state is counting the "
                f"page at rest a second time")
    return found


def audit(base: str, out: pathlib.Path | None,
          states=None, report=None, problems=None) -> tuple[dict, list]:
    from playwright.sync_api import sync_playwright

    report = {} if report is None else report
    problems = [] if problems is None else problems
    with sync_playwright() as pw:
        browser = launch(pw)
        for state in (STATES if states is None else states):
            name, path, width, height, theme, populate = state[:6]
            overlay = state[6] if len(state) > 6 else None
            page = browser.new_page(viewport={"width": width, "height": height})
            errors: list[str] = []
            page.on("pageerror",
                    lambda exc, sink=errors: sink.append(f"pageerror: {exc}"))
            page.on("console",
                    lambda msg, sink=errors: sink.append(f"console: {msg.text}")
                    if msg.type == "error" else None)
            response = page.goto(base + path, wait_until="networkidle")
            # Flask's 404 body is exactly one <h1>, with no overflow and no
            # JS errors -- so it satisfies every structural check here. If
            # /api/docs ever stopped registering, the three states added to
            # cover that page would have audited the 404 and reported clean.
            if response is not None and response.status >= 400:
                problems.append(
                    f"{name}: {base + path} returned HTTP {response.status}; "
                    f"nothing below measured the intended page")
                page.close()
                continue
            page.evaluate(f"() => document.documentElement.dataset.theme = '{theme}'")
            if populate:
                _stub_and_search(page)
            if overlay:
                try:
                    _open_overlay(page, overlay)
                except Exception as exc:  # the trigger moved or broke
                    problems.append(
                        f"{name}: could not open the {overlay} overlay "
                        f"({type(exc).__name__}: {exc}); the page beneath it "
                        f"was not measured in its place")
                    page.close()
                    continue
            page.wait_for_timeout(300)

            data = page.evaluate(MEASURE)
            data["jsErrors"] = errors

            no_ring, seen = [], set()
            for _ in range(40):
                page.keyboard.press("Tab")
                ring = page.evaluate(FOCUS_RING)
                if not ring:
                    continue
                key = (ring.get("tag"), ring.get("id"), ring.get("text"))
                if key in seen:
                    continue
                seen.add(key)
                if not ring["ok"]:
                    no_ring.append(ring)
            data["focusStops"] = len(seen)
            data["noFocusRing"] = no_ring

            if out:
                out.mkdir(parents=True, exist_ok=True)
                page.screenshot(path=str(out / f"{name}.png"))
            report[name] = data
            page.close()
        browser.close()
    return report, problems


def summarise(report: dict, problems: list, out: pathlib.Path | None) -> int:
    print(f"{'state':<18} {'contrast':>12}  {'targets':>10}  {'focus':>8}  "
          f"{'overflow':>8}  {'js':>3}")
    for name, data in report.items():
        bad = [t for t in data["text"] if not t["passes"]]
        small = [t for t in data["targets"] if t["h"] < 24 or t["w"] < 24]
        total_t, total_g = len(data["text"]), len(data["targets"])
        print(f"{name:<18} {total_t - len(bad):>5}/{total_t:<6} "
              f"{total_g - len(small):>4}/{total_g:<5} "
              f"{data['focusStops'] - len(data['noFocusRing']):>3}/"
              f"{data['focusStops']:<4} "
              f"{data['overflowX']!s:>8}  {len(data['jsErrors']):>3}")
        problems += [
            f"{name}: contrast {t['ratio']} < {t['required']} on "
            f"{t['size']}px/{t['weight']} <{t['tag']}.{t['cls']}> {t['sample']!r}"
            for t in bad
        ]
        problems += [
            f"{name}: tap target {t['w']}x{t['h']} (via {t['via']}) "
            f"<{t['tag']} {t['type']}> {t['label']!r}"
            for t in small
        ]
        problems += [
            f"{name}: no focus ring on <{r['tag']}> #{r['id']} {r['text']!r}"
            for r in data["noFocusRing"]
        ]
        if data["overflowX"]:
            problems.append(f"{name}: horizontal overflow "
                            f"({data['scrollWidth']} > {data['innerWidth']})")
        problems += [f"{name}: {err}" for err in data["jsErrors"]]
        if len(data["h1"]) != 1:
            problems.append(f"{name}: expected exactly one <h1>, got {data['h1']}")
        if data["focusStops"] == 0:
            problems.append(f"{name}: nothing is reachable by Tab")
        # 80 is the brief's cap; 85 is where it is called a defect, so a
        # word landing awkwardly does not fail a run on its own.
        problems += [
            f"{name}: {row['chars']} characters a line in "
            f".{row['cls']} {row['sample']!r} (over 80)"
            for row in data.get("prose", []) if row["chars"] > 85
        ]

    # An overlay state has to measure something the page at rest does not.
    # This is the check the recent-searches state needed and did not have:
    # it waited for a button that is always present, measured 223 text
    # nodes and 74 targets -- the results page, element for element -- and
    # reported a clean pass for a surface nobody had opened. Comparing
    # against the matching base state is what makes "19 states" mean
    # nineteen surfaces rather than nineteen runs.
    problems += duplicate_states(report, STATES)

    first = report[STATES[0][0]]
    print("\ntype scale (landing):",
          ", ".join(f"{px}px x{n}" for px, n in first["typeScale"][:8]))
    print("fonts:")
    for font in first["fonts"]:
        print(f"  {font}")

    if out:
        (out / "report.json").write_text(json.dumps(report, indent=1))
        print(f"\nscreenshots and report.json in {out}")

    if problems:
        print(f"\n{len(problems)} problem(s):")
        for line in problems:
            print(f"  {line}")
        return 1
    print("\nno problems measured")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", help="audit a running server instead of starting one")
    parser.add_argument("--out", type=pathlib.Path, help="directory for screenshots")
    args = parser.parse_args(argv)

    try:
        import playwright.sync_api  # noqa: F401
    except ImportError:
        # 77, the conventional "skipped" code, not 0. Returning success
        # meant this tool wired into CI without a browser passed forever
        # having measured nothing -- indistinguishable from "measured
        # everything, all good", which is the failure mode it exists to
        # catch in other people's work.
        print("playwright is not installed (pip install -r requirements-dev.txt)",
              file=sys.stderr)
        print("SKIPPED: nothing was measured", file=sys.stderr)
        return 77

    if args.url:
        # An already-running server has whatever token policy it was
        # started with, so the gate cannot be forced; say so rather than
        # report 18 clean states and imply 19 were measured.
        states = [s for s in STATES if (len(s) < 7 or s[6] != "gate")]
        report, problems = audit(args.url, args.out, states=states)
        problems.append("19-auth-gate: skipped; --url cannot configure a "
                        "token, so the gate was not measured")
        return summarise(report, problems, args.out)

    gate = [s for s in STATES if len(s) > 6 and s[6] == "gate"]
    rest = [s for s in STATES if s not in gate]
    with serve() as base:
        time.sleep(0.3)
        report, problems = audit(base, args.out, states=rest)
    # A second server, configured with a token, so the auth gate is
    # measured on the path that really raises it.
    with serve(token="audit-only-token") as base:
        time.sleep(0.3)
        report, problems = audit(base, args.out, states=gate,
                                 report=report, problems=problems)
    return summarise(report, problems, args.out)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
