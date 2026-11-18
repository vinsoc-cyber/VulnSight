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
STATES = [
    ("01-landing-dark", "", 1440, 900, "dark"),
    ("02-landing-light", "", 1440, 900, "light"),
    ("03-mobile-dark", "", 390, 844, "dark"),
    ("04-mobile-light", "", 390, 844, "light"),
    ("05-narrow", "", 320, 844, "dark"),
    ("06-tablet", "", 820, 1180, "dark"),
    ("07-wide", "", 1920, 1080, "light"),
    ("08-apidocs-dark", "api/docs", 1440, 900, "dark"),
    ("09-apidocs-light", "api/docs", 1440, 900, "light"),
    ("10-apidocs-mobile", "api/docs", 390, 844, "dark"),
]

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
  // The painted background is the first non-transparent ancestor, not the
  // element's own `background-color`, which is usually transparent.
  const bgOf = el => {
    for (let n = el; n; n = n.parentElement) {
      const c = parse(getComputedStyle(n).backgroundColor);
      if (c.length >= 3 && (c.length === 3 || c[3] > 0)) return c.slice(0, 3);
    }
    return [0, 0, 0];
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

  return {
    text, targets,
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
def serve():
    """Run the app on a loopback port, as the e2e suite does."""
    import wsgiref.simple_server
    from wsgiref.simple_server import WSGIRequestHandler

    sys.path.insert(0, str(ROOT))
    os.environ.setdefault("VULNSIGHT_BIND", "127.0.0.1")
    os.environ["VULNSIGHT_RATE_LIMIT"] = "off"
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


def launch(pw):
    try:
        return pw.chromium.launch()
    except Exception:
        return pw.chromium.launch(channel="chrome")


def audit(base: str, out: pathlib.Path | None) -> int:
    from playwright.sync_api import sync_playwright

    report, problems = {}, []
    with sync_playwright() as pw:
        browser = launch(pw)
        for name, path, width, height, theme in STATES:
            page = browser.new_page(viewport={"width": width, "height": height})
            errors: list[str] = []
            page.on("pageerror",
                    lambda exc, sink=errors: sink.append(f"pageerror: {exc}"))
            page.on("console",
                    lambda msg, sink=errors: sink.append(f"console: {msg.text}")
                    if msg.type == "error" else None)
            page.goto(base + path, wait_until="networkidle")
            page.evaluate(f"() => document.documentElement.dataset.theme = '{theme}'")
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
        print("playwright is not installed (pip install -r requirements-dev.txt)",
              file=sys.stderr)
        return 0

    if args.url:
        return audit(args.url, args.out)
    with serve() as base:
        time.sleep(0.3)
        return audit(base, args.out)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
