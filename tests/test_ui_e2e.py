"""End-to-end UI tests driven through a real browser.

The rest of the suite is offline and dependency-free; this module is the one
exception and **skips itself** unless Playwright and a browser are both present:

    pip install -r requirements-dev.txt
    playwright install chromium      # or rely on a system Chrome

It exists because `static/app.js` carries the parts of this tool that decide
what the user believes — which advisories are hidden, which verdict belongs to
which advisory, and when real AI budget gets spent — and none of that is
reachable from a Python unit test. Every assertion here corresponds to a defect
that actually shipped.

Assert on **rendered** state, not on DOM properties. A `.cat { display: grid }`
rule once beat the UA sheet's `[hidden] { display: none }`, so the class filter
set `hidden` on every row and changed nothing on screen while a property-based
test stayed green.
"""

import json
import os
import socket
import sys
import threading
import unittest
import urllib.request
from unittest import mock
import wsgiref.simple_server
from wsgiref.simple_server import WSGIRequestHandler

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:  # pragma: no cover - import guard
    from playwright.sync_api import sync_playwright
except ImportError:  # pragma: no cover
    sync_playwright = None

import app as app_module
from modules import cache
from modules import ghsa_client as ghsa


class _QuietHandler(WSGIRequestHandler):
    """The default handler prints every request to stderr."""

    def log_message(self, format, *args):
        pass


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _launch(playwright):
    """Prefer the Playwright browser, fall back to a system Chrome."""
    try:
        return playwright.chromium.launch()
    except Exception:
        return playwright.chromium.launch(channel="chrome")


def _advisory(index, **overrides):
    record = {
        "advisory_id": f"GHSA-{index}", "ghsa_id": f"GHSA-{index}",
        "cve_id": f"CVE-2026-{index}", "summary": f"advisory {index}",
        "severity": "high", "cvss_score": 7.5, "sources": ["ghsa"],
        "ecosystems": ["maven"], "packages": [], "cwes": ["639"],
        "cwe_labels": [{"id": "639", "label": "Authorization Bypass"}],
        "published_at": "2026-01-01T00:00:00Z", "html_url": "https://example.test/a",
    }
    record.update(overrides)
    return record


def _search_body(records, max_results=100):
    return json.dumps({
        "count": len(records), "warnings": [],
        "query": {"categories": ["bac"], "cwes": ["639", "862"],
                  "ecosystem": "maven", "severity": "any", "affects": None,
                  "max_results": max_results, "sources": ["ghsa"],
                  "per_source": {"ghsa": len(records)}},
        "results": records,
    })


def _verdicts_body(request, is_match=True):
    payload = json.loads(request.post_data or "{}")
    categories = payload.get("categories", [])
    return json.dumps({
        "categories": categories, "by_category": {}, "missing": [],
        "verdicts": {
            advisory_id: {"is_match": is_match, "confidence": 0.9,
                          "vuln_type": "t", "reason": "r",
                          "scored_categories": categories,
                          "cached": False, "has_errors": False}
            for advisory_id in payload.get("advisory_ids", [])
        },
    })


@unittest.skipIf(sync_playwright is None, "playwright is not installed")
class UITestCase(unittest.TestCase):
    """Serves the real app once for the whole class; a fresh page per test."""

    @classmethod
    def setUpClass(cls):
        cls._db = os.path.join(os.path.dirname(__file__), "_e2e_cache.db")
        cls._orig_db = cache.DB_PATH
        cache.DB_PATH = cls._db
        for name in ("VULNSIGHT_API_TOKEN", "VULNSIGHT_RATE_LIMIT"):
            os.environ.pop(name, None)
        os.environ["VULNSIGHT_RATE_LIMIT"] = "off"
        # This harness binds 127.0.0.1 below, but it reaches create_app()
        # through the WSGI path, where the bind is not discoverable and so
        # counts as exposed -- which on a developer box with `gh` credentials
        # would mint an API token and 401 every request. Declare the real bind.
        cls._orig_bind = os.environ.get("VULNSIGHT_BIND")
        os.environ["VULNSIGHT_BIND"] = "127.0.0.1"

        # The browser suite renders the real shell, which reports gh auth
        # status -- unmocked that is a real `gh auth status` with the
        # operator's credentials, from a suite documented as needing
        # neither network nor credentials.
        cls._gh = mock.patch.object(ghsa, "gh_auth_ok", return_value=True)
        cls._gh.start()

        cls.port = _free_port()
        cls.server = wsgiref.simple_server.make_server(
            "127.0.0.1", cls.port, app_module.create_app(),
            handler_class=_QuietHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

        assert sync_playwright is not None   # guarded by skipIf on the class
        cls.playwright = sync_playwright().start()
        try:
            cls.browser = _launch(cls.playwright)
        except Exception as exc:  # pragma: no cover - no browser available
            cls.playwright.stop()
            cls._stop_server()
            cache.DB_PATH = cls._orig_db
            raise unittest.SkipTest(f"no usable browser: {exc}") from exc
        cls.base = f"http://127.0.0.1:{cls.port}/"

    @classmethod
    def _stop_server(cls):
        """shutdown() only stops serve_forever; the listening socket stays
        open until server_close(). Without it each test class leaked a
        descriptor and held its port for the rest of the run."""
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    @classmethod
    def tearDownClass(cls):
        cls._gh.stop()
        cls.browser.close()
        cls.playwright.stop()
        cls._stop_server()
        cache.DB_PATH = cls._orig_db
        if cls._orig_bind is None:
            os.environ.pop("VULNSIGHT_BIND", None)
        else:
            os.environ["VULNSIGHT_BIND"] = cls._orig_bind
        for suffix in ("", "-wal", "-shm"):
            path = cls._db + suffix
            if os.path.exists(path):
                os.unlink(path)

    def setUp(self):
        self.errors = []
        # Substrings a test declares it expects to see logged, e.g. when it
        # deliberately makes an endpoint return 500.
        self.tolerated_errors: list[str] = []
        self.page = self.browser.new_page(viewport={"width": 1400, "height": 1000})
        self.page.on("pageerror", lambda e: self.errors.append(str(e)))
        self.page.on(
            "console",
            lambda m: self.errors.append(m.text) if m.type == "error" else None,
        )

    def tearDown(self):
        self.page.close()
        unexpected = [
            message for message in self.errors
            if not any(allowed in message for allowed in self.tolerated_errors)
        ]
        self.assertEqual(unexpected, [], "unexpected JS errors")

    # -- helpers ----------------------------------------------------------
    def open(self, records=None, max_results=100, classify=True, is_match=True):
        records = records if records is not None else [_advisory(i) for i in range(4)]
        self.searches = []
        self.classifies = []

        def on_search(route):
            self.searches.append(json.loads(route.request.post_data or "{}"))
            route.fulfill(status=200, content_type="application/json",
                          body=_search_body(records, max_results))
        self.page.route("**/api/search", on_search)

        if classify:
            def on_classify(route):
                self.classifies.append(json.loads(route.request.post_data or "{}"))
                route.fulfill(status=200, content_type="application/json",
                              body=_verdicts_body(route.request, is_match))
            self.page.route("**/api/ai/classify", on_classify)

        self.page.goto(self.base, wait_until="networkidle")

    def visible_classes(self):
        return self.page.eval_on_selector_all(
            "#taxonomy-list .taxonomy-item",
            "els => els.filter(e => getComputedStyle(e).display !== 'none')"
            "         .map(e => e.dataset.key)")

    def search_and_wait(self):
        self.page.click("#search-btn")
        self.page.wait_for_selector(".card")


class TestCweFinder(UITestCase):
    def test_community_alias_finds_the_cwe_with_its_full_name(self):
        self.open()
        self.page.fill("#cwe-search", "idor")
        self.page.wait_for_selector("#cwe-options .combo-option")
        rows = self.page.eval_on_selector_all(
            "#cwe-options .combo-option",
            "els => els.map(e => ({code: e.querySelector('.combo-code').textContent.trim(),"
            " label: e.querySelector('.combo-label').textContent.trim()}))")
        match = next((r for r in rows if r["code"] == "CWE-639"), None)
        self.assertIsNotNone(match, f"CWE-639 not offered for 'idor': {rows[:5]}")
        assert match is not None
        self.assertEqual(match["label"],
                         "Authorization Bypass Through User-Controlled Key")

    def test_exact_id_outranks_everything_else(self):
        self.open()
        for query, expected in (("639", "CWE-639"), ("CWE-1321", "CWE-1321")):
            self.page.fill("#cwe-search", query)
            self.page.wait_for_selector("#cwe-options .combo-option")
            first = self.page.text_content("#cwe-options .combo-option .combo-code")
            self.assertEqual((first or "").strip(), expected, query)

    def test_enter_adds_a_chip_and_does_not_start_a_search(self):
        self.open()
        self.page.fill("#cwe-search", "CWE-1321")
        self.page.wait_for_selector("#cwe-options .combo-option")
        self.page.press("#cwe-search", "Enter")
        self.page.wait_for_selector(".chip-cwe")
        self.assertEqual(
            self.page.eval_on_selector_all(".chip-cwe .chip-code",
                                           "els => els.map(e => e.textContent.trim())"),
            ["CWE-1321"])
        self.assertEqual(self.searches, [], "picking a CWE must not run a search")

    def test_dropdown_closes_when_focus_leaves(self):
        self.open()
        self.page.fill("#cwe-search", "auth")
        self.page.wait_for_selector("#cwe-options .combo-option")
        self.page.press("#cwe-search", "Tab")
        self.page.wait_for_timeout(150)
        self.assertTrue(self.page.evaluate(
            "() => getComputedStyle(document.querySelector('#cwe-options'))"
            "        .display === 'none'"))


class TestTheComboboxSaysWhatEnterWillDo(UITestCase):
    """`Enter` has always added match 0, but nothing carried
    aria-selected and no row was styled, so there was no way -- by eye or
    by screen reader -- to see which CWE you were about to add. The listbox
    also rendered its "no matches" line as a bare <li>, which inside
    role="listbox" is announced as a selectable option that cannot be
    selected."""

    def _type(self, query):
        box = self.page.query_selector("#cwe-search")
        assert box is not None
        box.click()
        box.fill(query)
        self.page.wait_for_timeout(250)

    def test_a_match_is_highlighted_before_any_key_is_pressed(self):
        self.open()
        self._type("idor")
        state = self.page.evaluate("""() => {
          const opts = [...document.querySelectorAll('#cwe-options .combo-option')];
          return {
            count: opts.length,
            selected: opts.filter(o => o.getAttribute('aria-selected') === 'true').length,
            firstIsSelected: opts.length
              ? opts[0].getAttribute('aria-selected') === 'true' : false,
            activedescendant: document.querySelector('#cwe-search')
              .getAttribute('aria-activedescendant'),
          };
        }""")
        self.assertGreater(state["count"], 0, "no matches for a known alias")
        self.assertEqual(state["selected"], 1,
                         "exactly one option must be marked selected")
        self.assertTrue(state["firstIsSelected"],
                        "Enter adds match 0, so match 0 is what must be marked")
        self.assertTrue(state["activedescendant"],
                        "the input must point at the highlighted option")

    def test_enter_adds_the_option_that_was_highlighted(self):
        self.open()
        self._type("idor")
        expected = self.page.evaluate(
            "() => document.querySelector('#cwe-options .combo-option[aria-selected=\"true\"]')"
            ".textContent.trim().slice(0, 24)")
        self.page.keyboard.press("Enter")
        self.page.wait_for_timeout(250)
        chips = self.page.evaluate(
            "() => [...document.querySelectorAll('#selected-chips .chip-text')]"
            ".map(c => c.textContent.trim())")
        self.assertTrue(
            any(expected.split()[0] in c for c in chips),
            f"Enter added something other than the highlighted row: "
            f"{expected!r} not in {chips}")

    def test_the_no_matches_row_is_not_announced_as_an_option(self):
        self.open()
        self._type("zzzzz-no-such-bug-class")
        rows = self.page.evaluate("""() => {
          const list = document.querySelector('#cwe-options');
          return [...list.querySelectorAll('li')].map(li => ({
            role: li.getAttribute('role'),
            text: li.textContent.trim().slice(0, 30),
          }));
        }""")
        self.assertTrue(rows, "the listbox rendered nothing at all")
        for row in rows:
            self.assertIn(
                row["role"], ("presentation", "none"),
                f"a non-option row inside role=listbox must be presentational: {row}")


class TestToastsShareOneLiveRegion(UITestCase):
    """Each toast used to be appended to <body> with its own aria-live, so
    two at once were two competing live regions: screen readers interleave
    or drop them, and the visual stack had nothing positioning it.

    The toast is driven through a real user path with no network behind it
    -- clearing the class selection and pressing the scan button -- so the
    assertion is unconditional. An earlier version of this test only
    checked the region "if one exists", which passed vacuously whenever no
    toast fired, and so stayed green with the defect reinstated.
    """

    tolerated_errors: list[str] = []

    def _raise_a_toast(self):
        """Remove every selected class, then ask for a scan."""
        for _ in range(12):
            chip = self.page.query_selector("#selected-chips .chip-x")
            if not chip:
                break
            chip.click()
            self.page.wait_for_timeout(60)
        self.page.click("#auto-btn")
        self.page.wait_for_selector(".toast", timeout=4000)

    def test_a_toast_appears_at_all(self):
        """If this fails the other two prove nothing."""
        self.open()
        self._raise_a_toast()
        self.assertGreater(
            self.page.evaluate("() => document.querySelectorAll('.toast').length"), 0)

    def test_every_toast_lives_in_one_named_region(self):
        self.open()
        self._raise_a_toast()
        state = self.page.evaluate("""() => {
          const regions = [...document.querySelectorAll('.toast-region')];
          return {
            regions: regions.length,
            role: regions[0] && regions[0].getAttribute('role'),
            label: regions[0] && regions[0].getAttribute('aria-label'),
            strays: [...document.querySelectorAll('.toast')]
              .filter(t => !t.closest('.toast-region')).length,
          };
        }""")
        self.assertEqual(state["regions"], 1,
                         "there must be exactly one toast region, so exactly "
                         "one live region")
        self.assertEqual(state["role"], "region")
        self.assertTrue(state["label"], "the toast region needs an accessible name")
        self.assertEqual(state["strays"], 0,
                         "a toast rendered outside the shared region")

    def test_a_second_toast_joins_the_same_region(self):
        self.open()
        self._raise_a_toast()
        self.page.click("#auto-btn")
        self.page.wait_for_timeout(400)
        state = self.page.evaluate("""() => ({
          regions: document.querySelectorAll('.toast-region').length,
          toasts: document.querySelectorAll('.toast-region .toast').length,
        })""")
        self.assertEqual(state["regions"], 1,
                         "a second toast must not create a second live region")
        self.assertGreaterEqual(state["toasts"], 1)


class TestClassFilter(UITestCase):
    def test_filter_hides_rows_on_screen_not_just_in_the_dom(self):
        self.open()
        before = self.visible_classes()
        self.assertGreaterEqual(len(before), 20, "expected the full taxonomy")
        self.page.fill("#class-search", "prototype")
        self.page.wait_for_timeout(150)
        after = self.visible_classes()
        self.assertIn("protopollution", after)
        self.assertLess(len(after), len(before))
        self.assertNotIn("sqli", after)

    def test_a_selected_class_is_never_hidden(self):
        self.open()
        self.page.fill("#class-search", "prototype")
        self.page.wait_for_timeout(150)
        # 'bac' is preselected and does not match the filter.
        self.assertIn("bac", self.visible_classes())

    def test_community_terms_are_searchable(self):
        self.open()
        for query, expected in (("__proto__", "protopollution"), ("toctou", "race"),
                                ("samesite", "csrf"), ("webshell", "upload")):
            self.page.fill("#class-search", query)
            self.page.wait_for_timeout(120)
            self.assertIn(expected, self.visible_classes(), query)

    def test_group_heading_is_shown_exactly_when_it_has_visible_rows(self):
        self.open()
        self.page.fill("#class-search", "prototype")
        self.page.wait_for_timeout(150)
        self.assertTrue(self.page.evaluate("""() => {
          const shown = el => getComputedStyle(el).display !== 'none';
          const items = [...document.querySelectorAll('#taxonomy-list .taxonomy-item')];
          return [...document.querySelectorAll('.taxonomy-group')].every(h =>
            shown(h) === items.some(i => shown(i) && i.dataset.group === h.dataset.group));
        }"""))


class TestAiSpendRequiresConsent(UITestCase):
    def test_keyboard_shortcut_runs_the_free_search(self):
        self.open()
        self.page.evaluate("() => document.activeElement.blur()")
        self.page.keyboard.press("Control+Enter")
        self.page.wait_for_selector(".card")
        self.assertEqual(len(self.searches), 1)
        self.assertEqual(self.classifies, [],
                         "the shortcut is advertised on the free button")

    def test_confirmed_only_asks_before_scoring_and_reverts_on_cancel(self):
        self.open()
        self.search_and_wait()
        prompts = []

        def on_dialog(dialog):
            prompts.append(dialog.message)
            dialog.dismiss()
        self.page.on("dialog", on_dialog)
        self.page.click("#only_match")
        self.page.wait_for_timeout(400)
        self.assertEqual(len(prompts), 1, "no confirmation was shown")
        self.assertIn("AI call", prompts[0])
        self.assertEqual(self.classifies, [], "cancelling must not spend budget")
        self.assertFalse(self.page.is_checked("#only_match"))

    def test_a_failed_ai_pass_restores_the_raw_queue(self):
        self.open(classify=False)
        self.tolerated_errors.append("500 (Internal Server Error)")
        self.page.route("**/api/ai/classify", lambda route: route.fulfill(
            status=500, content_type="application/json",
            body='{"error": "AI quota exhausted"}'))
        self.search_and_wait()
        self.page.on("dialog", lambda d: d.accept())
        self.page.click("#only_match")
        self.page.wait_for_timeout(700)
        self.assertFalse(self.page.is_checked("#only_match"))
        self.assertEqual(self.page.locator(".card").count(), 4)


class TestVerdictsFollowTheQuery(UITestCase):
    def test_changing_the_class_marks_verdicts_stale_and_blocks_the_filter(self):
        self.open()
        self.search_and_wait()
        self.page.click("#ai-btn")
        self.page.wait_for_timeout(600)
        self.assertTrue(self.page.evaluate(
            "() => getComputedStyle(document.querySelector('#stale-banner'))"
            "        .display === 'none'"))

        self.page.evaluate("""() => {
          const boxes = [...document.querySelectorAll('input[name=category]')];
          boxes[0].checked = false;
          boxes[0].dispatchEvent(new Event('change', {bubbles: true}));
          boxes[1].checked = true;
          boxes[1].dispatchEvent(new Event('change', {bubbles: true}));
        }""")
        self.page.wait_for_timeout(200)
        self.assertFalse(self.page.evaluate(
            "() => getComputedStyle(document.querySelector('#stale-banner'))"
            "        .display === 'none'"),
            "stale verdicts were not flagged")
        self.assertTrue(self.page.is_disabled("#only_match"),
                        "filtering on stale verdicts must be blocked")

    def test_a_partial_rescore_does_not_clear_the_stale_banner(self):
        """Staleness used to be one global flag for the whole verdict map.

        Scoring ANY subset overwrote it. So: score everything against BAC,
        switch the class, then hit "Retry failed" for the one advisory that
        errored -- the flag became ['the new class'] and the banner vanished,
        re-enabling "Confirmed only" while every other verdict still answered
        "is this BAC?". The user then filters and exports verdicts the UI has
        just told them are trustworthy. Staleness is per verdict now.
        """
        records = [_advisory(i) for i in range(3)]
        self.searches = []
        self.classifies = []

        def on_search(route):
            self.searches.append(json.loads(route.request.post_data or "{}"))
            route.fulfill(status=200, content_type="application/json",
                          body=_search_body(records, 100))
        self.page.route("**/api/search", on_search)

        # The first advisory always errors, so "Retry failed" stays available
        # and re-scores exactly one row.
        def on_classify(route):
            payload = json.loads(route.request.post_data or "{}")
            self.classifies.append(payload)
            categories = payload.get("categories", [])
            verdicts = {}
            for advisory_id in payload.get("advisory_ids", []):
                if advisory_id == records[0]["advisory_id"]:
                    verdicts[advisory_id] = {"error": "upstream refused",
                                             "has_errors": True}
                else:
                    verdicts[advisory_id] = {
                        "is_match": True, "confidence": 0.9, "vuln_type": "t",
                        "reason": "r", "scored_categories": categories,
                        "cached": False, "has_errors": False}
            route.fulfill(status=200, content_type="application/json",
                          body=json.dumps({"categories": categories,
                                           "by_category": {}, "missing": [],
                                           "verdicts": verdicts}))
        self.page.route("**/api/ai/classify", on_classify)
        self.page.goto(self.base, wait_until="networkidle")

        self.search_and_wait()
        self.page.click("#ai-btn")
        self.page.wait_for_timeout(600)
        self.assertTrue(self.page.evaluate(
            "() => getComputedStyle(document.querySelector('#stale-banner'))"
            "        .display === 'none'"),
            "verdicts scored for the current selection are not stale")

        # Switch the query. Every verdict now answers the wrong question.
        self.page.evaluate("""() => {
          const boxes = [...document.querySelectorAll('input[name=category]')];
          boxes[0].checked = false;
          boxes[0].dispatchEvent(new Event('change', {bubbles: true}));
          boxes[1].checked = true;
          boxes[1].dispatchEvent(new Event('change', {bubbles: true}));
        }""")
        self.page.wait_for_timeout(200)
        self.assertFalse(self.page.evaluate(
            "() => getComputedStyle(document.querySelector('#stale-banner'))"
            "        .display === 'none'"))

        # Re-score ONLY the errored advisory against the new selection.
        self.page.click("#retry-btn")
        self.page.wait_for_timeout(700)
        self.assertEqual(len(self.classifies[-1]["advisory_ids"]), 1,
                         "retry should re-score only the failed advisory")
        self.assertFalse(self.page.evaluate(
            "() => getComputedStyle(document.querySelector('#stale-banner'))"
            "        .display === 'none'"),
            "a one-row rescore cleared the banner for rows still scored "
            "against the previous selection")
        self.assertTrue(self.page.is_disabled("#only_match"),
                        "filtering on stale verdicts must stay blocked")

    def test_summary_reports_the_visible_count(self):
        self.open(records=[_advisory(i) for i in range(4)], is_match=False)
        self.search_and_wait()
        self.assertIn("4 advisories", self.page.text_content("#summary") or "")
        self.page.click("#ai-btn")
        self.page.wait_for_timeout(600)
        self.page.on("dialog", lambda d: d.accept())
        self.page.click("#only_match")
        self.page.wait_for_timeout(400)
        self.assertIn("0 of 4 shown", self.page.text_content("#summary") or "")


class TestFocusSurvivesARerender(UITestCase):
    """render() replaces all of #results in one innerHTML write.

    A keyboard user who Tabbed to the Retry button on a card and pressed
    Enter lost focus to <body>, lost their scroll position, and Tabbed from
    the top of the document again -- with nothing announcing the retry had
    worked. The toolbar buttons survive a re-render; the per-card one does
    not, because it is destroyed by the write that follows it.
    """

    def _open_with_one_failing_verdict(self, count=12):
        """One advisory always errors, so renderCard draws a real Retry."""
        records = [_advisory(i) for i in range(count)]
        self.searches, self.classifies = [], []

        def on_search(route):
            self.searches.append(json.loads(route.request.post_data or "{}"))
            route.fulfill(status=200, content_type="application/json",
                          body=_search_body(records, 100))
        self.page.route("**/api/search", on_search)

        def on_classify(route):
            payload = json.loads(route.request.post_data or "{}")
            self.classifies.append(payload)
            cats = payload.get("categories", [])
            verdicts = {}
            for advisory_id in payload.get("advisory_ids", []):
                if advisory_id == records[0]["advisory_id"]:
                    verdicts[advisory_id] = {"error": "upstream refused",
                                             "has_errors": True}
                else:
                    verdicts[advisory_id] = {
                        "is_match": True, "confidence": 0.9, "vuln_type": "t",
                        "reason": "r", "scored_categories": cats,
                        "cached": False, "has_errors": False}
            route.fulfill(status=200, content_type="application/json",
                          body=json.dumps({"categories": cats, "by_category": {},
                                           "missing": [], "verdicts": verdicts}))
        self.page.route("**/api/ai/classify", on_classify)
        self.page.goto(self.base, wait_until="networkidle")
        self.search_and_wait()
        self.page.click("#ai-btn")
        self.page.wait_for_timeout(700)
        return records

    def test_the_card_retry_button_keeps_focus_across_the_rerender(self):
        self.open()
        self._open_with_one_failing_verdict()
        found = self.page.evaluate("""() => {
          const button = document.querySelector('#results .verdict-retry');
          if (!button) return false;
          button.focus();
          return document.activeElement === button;
        }""")
        self.assertTrue(found, "no per-card Retry button was rendered")

        # A sort change re-renders every card without changing the data.
        self.page.select_option("#sort", "cve_id")
        self.page.wait_for_timeout(300)

        still = self.page.evaluate("""() => {
          const active = document.activeElement;
          return !!(active && active.classList
                    && active.classList.contains('verdict-retry'));
        }""")
        self.assertTrue(still, "focus fell off the Retry button on re-render")

    def test_a_rerender_does_not_jump_the_scroll_position(self):
        self.open()
        self._open_with_one_failing_verdict(count=40)
        self.page.evaluate("() => window.scrollTo(0, 400)")
        self.page.wait_for_timeout(100)
        before = self.page.evaluate("() => Math.round(window.scrollY)")
        self.page.evaluate("""() => {
          const button = document.querySelector('#results .verdict-retry');
          if (button) button.focus({preventScroll: true});
        }""")
        self.page.select_option("#sort", "cve_id")
        self.page.wait_for_timeout(300)
        after = self.page.evaluate("() => Math.round(window.scrollY)")
        self.assertLess(abs(after - before), 200,
                        f"scroll jumped from {before} to {after}")


class TestAuthGateTrapsFocus(UITestCase):
    """The card carries role="dialog" aria-modal="true" and trapped nothing.

    A keyboard user could Tab past "Continue" into the CWE search box behind
    the scrim -- invisible, focus ring under the overlay, and every control
    they reached would 401. A screen reader honouring aria-modal was
    meanwhile told there was nothing outside the dialog.

    These used to set `inert` from the test and then assert it was there,
    which is the test performing the behaviour it is checking: with
    `setAuthGateBackgroundInert` reduced to a no-op *and* `trapAuthGateTab`
    returning immediately, both still passed. They drive the real path now
    -- the page is served with AUTH_REQUIRED true and no stored token, so
    app.js calls showAuthGate() on init exactly as it would in production.
    """

    def _page_with_auth_required(self):
        """A page whose BOOT says a token is required, so the gate opens
        through showAuthGate() rather than by the test opening it."""
        with urllib.request.urlopen(self.base, timeout=10) as response:
            html = response.read().decode("utf-8")
        self.assertIn("AUTH_REQUIRED: false", html,
                      "the e2e server is already requiring a token")
        html = html.replace("AUTH_REQUIRED: false", "AUTH_REQUIRED: true")

        page = self.browser.new_page(viewport={"width": 1400, "height": 1000})
        # Fulfilled from here rather than route.fetch(): fetching through the
        # same page that is blocked on the route deadlocks.
        page.route(self.base,
                   lambda route: route.fulfill(status=200, body=html,
                                               content_type="text/html"))
        page.goto(self.base, wait_until="networkidle")
        page.wait_for_function(
            "() => !document.getElementById('auth-gate').hidden", timeout=5000)
        return page

    def test_the_gate_opens_by_itself_when_a_token_is_required(self):
        """If this fails the other two prove nothing."""
        self.open()
        page = self._page_with_auth_required()
        try:
            self.assertFalse(page.evaluate(
                "() => document.getElementById('auth-gate').hidden"))
        finally:
            page.close()

    def test_the_background_is_inert_while_the_gate_is_open(self):
        self.open()
        page = self._page_with_auth_required()
        try:
            inert = page.evaluate(
                "() => [...document.querySelectorAll('.topbar, .layout')]"
                "        .every(el => el.hasAttribute('inert'))")
            self.assertTrue(inert, "the page behind the gate stayed interactive")
        finally:
            page.close()

    def test_tabbing_cannot_reach_the_page_behind_the_gate(self):
        self.open()
        page = self._page_with_auth_required()
        try:
            page.evaluate("() => document.getElementById('auth-token').focus()")
            for _ in range(8):
                page.keyboard.press("Tab")
                # No `|| activeElement === body` escape hatch: focus landing
                # nowhere is a trap that lost the user, not a trap that held.
                self.assertTrue(
                    page.evaluate(
                        "() => document.getElementById('auth-gate')"
                        "        .contains(document.activeElement)"),
                    "Tab escaped into the page behind the scrim")
        finally:
            page.close()

    def test_shift_tab_is_trapped_too(self):
        self.open()
        page = self._page_with_auth_required()
        try:
            page.evaluate("() => document.getElementById('auth-token').focus()")
            for _ in range(8):
                page.keyboard.press("Shift+Tab")
                self.assertTrue(
                    page.evaluate(
                        "() => document.getElementById('auth-gate')"
                        "        .contains(document.activeElement)"),
                    "Shift+Tab escaped backwards out of the dialog")
        finally:
            page.close()


class TestFailureStates(UITestCase):
    def test_search_without_a_source_keeps_the_previous_view(self):
        self.open()
        self.search_and_wait()
        self.page.evaluate(
            "() => document.querySelectorAll('input[name=source]')"
            ".forEach(b => { b.checked = false; })")
        self.page.click("#search-btn")
        self.page.wait_for_timeout(400)
        self.assertFalse(self.page.evaluate(
            "() => !!document.querySelector('#results .spinner')"),
            "a rejected search left a spinner behind")
        self.assertEqual(self.page.locator(".card").count(), 4)

    def test_missing_epss_is_not_rendered_as_a_measured_zero(self):
        self.open(records=[
            _advisory(0, epss_percentage=None, epss_percentile=None),
            _advisory(1),
            _advisory(2, epss_percentage=0.5, epss_percentile=0.9),
        ])
        self.search_and_wait()
        meters = self.page.eval_on_selector_all(
            ".card", "els => els.map(e => e.querySelectorAll('.epss-meter').length)")
        self.assertEqual(meters, [0, 0, 1],
                         "Number(null) is 0 and finite — it must not print 0.00%")


class TestRecentSearches(UITestCase):
    def test_repeating_a_search_does_not_duplicate_the_entry(self):
        self.open()
        self.search_and_wait()
        self.page.click("#search-btn")
        self.page.wait_for_timeout(400)
        self.assertEqual(
            self.page.locator("#history-list .history-run").count(), 1)

    def test_entries_are_keyed_by_signature_not_position(self):
        self.open()
        self.search_and_wait()
        self.assertTrue(self.page.evaluate(
            "() => [...document.querySelectorAll('#history-list .history-run')]"
            ".every(r => r.dataset.sig && !r.dataset.index)"))

    def test_restoring_reapplies_the_stored_filters(self):
        self.open()
        self.search_and_wait()
        self.page.select_option("#ecosystem", "npm")
        self.page.click("#history-list .history-run")
        self.page.wait_for_selector(".card")
        self.assertEqual(self.page.input_value("#ecosystem"), "maven")


class TestAccessibility(UITestCase):
    def test_the_page_has_exactly_one_h1(self):
        self.open()
        self.assertEqual(
            self.page.evaluate("() => document.querySelectorAll('h1').length"), 1)

    def test_labelled_containers_expose_their_label(self):
        self.open()
        # aria-label is ignored on a bare <div> (role=generic prohibits it).
        self.assertTrue(self.page.evaluate("""() =>
          [...document.querySelectorAll('div[aria-label]')].every(el => el.getAttribute('role'))
        """))

    def test_mobile_panel_takes_focus_and_traps_it(self):
        self.open()
        page = self.browser.new_page(viewport={"width": 390, "height": 844})
        try:
            page.goto(self.base, wait_until="networkidle")
            page.click("#filters-toggle")
            page.wait_for_function(
                "() => document.activeElement.id === 'filters-close'", timeout=3000)
            self.assertTrue(page.evaluate(
                "() => document.querySelector('#workspace').inert"))
            for _ in range(25):
                page.keyboard.press("Tab")
                self.assertTrue(page.evaluate(
                    "() => !!document.activeElement.closest('#control-panel')"),
                    "focus escaped the modal panel")
        finally:
            page.close()


class TestTopbarLayoutHolds(UITestCase):
    """The topbar's brand column is `minmax(0, 1fr)`, so it shrinks before
    the status pills do. Nothing stopped the wordmark from painting outside
    the box it had shrunk to, and at phone width it ran underneath the
    pills: the page rendered "VulnSigh" with a badge over the rest. Every
    property-based check passed while it did -- the element was the right
    size, the text was the right string, contrast was fine. Only geometry
    catches this, so assert on geometry."""

    BOXES = """() => {
      const pick = s => [...document.querySelectorAll(s)]
        .filter(el => {
          const c = getComputedStyle(el);
          if (c.display === 'none' || c.visibility === 'hidden') return false;
          // A visually-hidden element is clipped to 1px and paints nothing.
          const b = el.getBoundingClientRect();
          return b.width > 2 && b.height > 2;
        })
        .map(el => {
          const b = el.getBoundingClientRect();
          return {name: el.className || el.tagName,
                  l: b.left, r: b.right, t: b.top, b: b.bottom};
        });
      // The logo as well as the wordmark: the brand column was
      // minmax(0, 1fr), so at 320px it collapsed to 21px and the 32px mark
      // painted straight over the first status pill.
      return {brand: pick('.topbar .brand-name, .topbar .logo'),
              status: pick('.topbar .system-status > *')};
    }"""

    def _overlaps(self, page):
        boxes = page.evaluate(self.BOXES)
        hits = []
        for a in boxes["brand"]:
            for c in boxes["status"]:
                if (a["l"] < c["r"] and c["l"] < a["r"]
                        and a["t"] < c["b"] and c["t"] < a["b"]):
                    hits.append((a["name"], c["name"]))
        return hits, boxes

    def _at(self, width, height=844):
        page = self.browser.new_page(viewport={"width": width, "height": height})
        page.goto(self.base, wait_until="networkidle")
        return page

    def test_the_brand_never_paints_under_the_status_pills(self):
        self.open()
        for width in (320, 360, 390, 414, 460, 480, 700, 900, 1400):
            page = self._at(width)
            try:
                hits, _boxes = self._overlaps(page)
                self.assertEqual(
                    hits, [],
                    f"at {width}px the brand overlaps the status pills: {hits}")
                self.assertFalse(
                    page.evaluate("() => document.documentElement.scrollWidth"
                                  " > window.innerWidth + 1"),
                    f"the page scrolls horizontally at {width}px")
            finally:
                page.close()

    def test_the_wordmark_is_never_cut_off_where_it_is_shown(self):
        """Hidden is fine; half-painted is not. Where the name is on screen
        it must fit the box it is given."""
        self.open()
        shown_somewhere = False
        for width in (320, 390, 414, 480, 700, 900, 1400):
            page = self._at(width)
            try:
                state = page.evaluate("""() => {
                  const el = document.querySelector('.brand-name');
                  const b = el.getBoundingClientRect();
                  return {shown: b.width > 2,
                          scrollW: el.scrollWidth, clientW: el.clientWidth};
                }""")
                if state["shown"]:
                    shown_somewhere = True
                    self.assertLessEqual(
                        state["scrollW"], state["clientW"] + 1,
                        f"at {width}px the wordmark overflows its box")
            finally:
                page.close()
        # Hiding it at every width would satisfy "never cut off where shown".
        self.assertTrue(shown_somewhere,
                        "the wordmark is never shown at any width")

    def test_the_brand_link_is_still_announced_in_full_when_hidden(self):
        """At narrow widths the name is clipped out of view rather than
        removed, so the home link does not degrade to just "VS"."""
        self.open()
        page = self._at(390)
        try:
            self.assertIn("VulnSight", page.evaluate(
                "() => document.querySelector('.brand').textContent"))
        finally:
            page.close()

    def test_a_disabled_action_does_not_keep_its_warning_colour(self):
        """`button.warn-btn` is declared after `button:disabled` at equal
        specificity, so "Retry failed" stayed full amber while unclickable --
        the loudest control on an empty page, and not clickable."""
        self.open()
        state = self.page.evaluate("""() => {
          const el = document.getElementById('retry-btn');
          const faint = getComputedStyle(document.documentElement)
            .getPropertyValue('--faint').trim();
          const probe = document.createElement('span');
          probe.style.color = faint;
          document.body.appendChild(probe);
          const want = getComputedStyle(probe).color;
          probe.remove();
          return {disabled: el.disabled, color: getComputedStyle(el).color,
                  want, cursor: getComputedStyle(el).cursor};
        }""")
        self.assertTrue(state["disabled"], "retry should be disabled with no results")
        self.assertEqual(state["color"], state["want"],
                         "a disabled button must not keep its accent colour")
        self.assertEqual(state["cursor"], "not-allowed")


class TestNothingLeaksToTheWindow(UITestCase):
    """static/app.js had no wrapper, so every function and every piece of
    its state was a property of `window`. That is not theoretical: `let AI
    = {}` shares a name with the browser's own `AI` global, and anything
    the platform adds later is free to collide with the other ~79."""

    # Names the file defines at its top level. If the wrapper goes, these
    # are the first things to appear on window.
    EXPECTED_PRIVATE = [
        "AI", "LAST", "SEARCH_META", "CLASSES", "POPULAR", "PICKED", "ENTRIES",
        "search", "renderCard", "renderSummary", "renderHistory", "toast",
        "esc", "safeUrl", "safeAttr", "classHaystack", "classEntries",
        "scoreEntry", "pickEntry", "setFilterPanel", "focusAnchor",
        "restoreFocus", "refreshPackages", "sanitizeCategories",
        "stateSignature", "relativeTime", "publishedWindow", "refineAI",
    ]

    def test_app_js_puts_nothing_on_window(self):
        self.open()
        leaked = self.page.evaluate(
            "names => names.filter(n => Object.prototype.hasOwnProperty.call(window, n))",
            self.EXPECTED_PRIVATE)
        self.assertEqual(leaked, [], f"app.js leaked {leaked} onto window")

    def test_the_page_still_works_under_strict_mode(self):
        """The wrapper brought 'use strict' with it, which turns silent
        failures (assigning to an undeclared name, writing a read-only
        property) into thrown errors. If any of those existed, the page
        would break where it previously limped."""
        errors = []
        self.page.on("pageerror", lambda e: errors.append(str(e)))
        self.open()
        # Exercise the paths that write state: the picker, a class tick, the
        # theme cycle and the history list. Under sloppy mode an assignment
        # to an undeclared or read-only name here would be silent.
        self.page.fill("#cwe-search", "idor")
        self.page.wait_for_timeout(250)
        self.page.keyboard.press("Escape")
        box = self.page.query_selector("#class-list input[type=checkbox]")
        if box:
            box.click()
        toggle = self.page.query_selector("#theme-toggle")
        if toggle:
            for _ in range(3):
                toggle.click()
                self.page.wait_for_timeout(80)
        self.page.wait_for_timeout(200)
        self.assertEqual(errors, [], f"strict mode surfaced: {errors}")

    def test_the_boot_payload_is_the_only_thing_the_server_sets(self):
        self.open()
        self.assertTrue(self.page.evaluate(
            "() => Object.prototype.hasOwnProperty.call(window, 'BOOT')"),
            "window.BOOT is the server->client contract and must stay")


class TestTheOpeningScreenIsTheTaxonomy(UITestCase):
    """The workspace used to open on a centred card of instructions -- a
    headline, a paragraph, three numbered steps and a tip telling you to go
    and tick a class in a 320px rail you then had to scroll -- with the rest
    of the pane empty. It opens on the classes themselves now, and picking
    one is a click.

    These assert the behaviour, not the look: every class is offered, the
    map and the rail cannot disagree, and the thing is operable by keyboard.
    """

    def _map(self):
        return self.page.evaluate("""() => ({
          tiles: [...document.querySelectorAll('.map-class')].map(b => b.dataset.class),
          picked: [...document.querySelectorAll('.map-class.is-picked')]
            .map(b => b.dataset.class).sort(),
          pressed: [...document.querySelectorAll('.map-class[aria-pressed="true"]')]
            .map(b => b.dataset.class).sort(),
          boxes: [...document.querySelectorAll('input[name=category]:checked')]
            .map(c => c.value).sort(),
          groups: [...document.querySelectorAll('.map-group-name')]
            .map(h => h.textContent.trim()),
        })""")

    def test_every_bug_class_is_on_the_opening_screen(self):
        self.open()
        state = self._map()
        count = self.page.evaluate("() => window.BOOT.CLASSES.length")
        self.assertEqual(len(state["tiles"]), count,
                         "the map does not offer every class")
        self.assertEqual(len(set(state["tiles"])), count, "a class is listed twice")
        self.assertTrue(state["groups"], "classes are not grouped by family")

    def test_the_map_and_the_rail_can_never_disagree(self):
        """Both are views of the same checkboxes. If they drift, the page
        shows one selection and searches another."""
        self.open()
        for key in ("xss", "sqli", "ssrf"):
            self.page.click(f'.map-class[data-class="{key}"]')
            self.page.wait_for_timeout(150)
            state = self._map()
            with self.subTest(after=key):
                self.assertEqual(state["picked"], state["boxes"])
                self.assertEqual(state["pressed"], state["boxes"])
                self.assertIn(key, state["boxes"])

    def test_a_second_click_removes_the_class(self):
        """A one-way door with no visible way back is not a toggle."""
        self.open()
        self.page.click('.map-class[data-class="xss"]')
        self.page.wait_for_timeout(150)
        self.assertIn("xss", self._map()["boxes"])
        self.page.click('.map-class[data-class="xss"]')
        self.page.wait_for_timeout(150)
        self.assertNotIn("xss", self._map()["boxes"])

    def test_picking_a_class_leaves_focus_where_it_was_clicked(self):
        """pickEntry() hands focus to the rail's search box, which is right
        when you got there by typing and wrong when you got there by
        clicking a tile -- it throws a keyboard user across the page."""
        self.open()
        self.page.click('.map-class[data-class="sqli"]')
        self.page.wait_for_timeout(200)
        self.assertEqual(
            self.page.evaluate("() => document.activeElement.dataset.class"), "sqli")

    def test_the_map_is_operable_from_the_keyboard(self):
        self.open()
        picked = self.page.evaluate("""() => {
          const tile = document.querySelector('.map-class[data-class="xss"]');
          tile.focus();
          return document.activeElement === tile;
        }""")
        self.assertTrue(picked, "a tile cannot take focus")
        self.page.keyboard.press("Enter")
        self.page.wait_for_timeout(200)
        self.assertIn("xss", self._map()["boxes"])

    def test_each_class_states_how_many_cwes_it_covers(self):
        """The number is the reason to pick one class over another."""
        self.open()
        counts = self.page.evaluate(
            "() => [...document.querySelectorAll('.map-count')].map(e => e.textContent.trim())")
        self.assertTrue(counts)
        for text in counts:
            self.assertRegex(text, r"^\d+ CWEs?$", f"unreadable count: {text!r}")

    def test_running_a_search_replaces_the_map_with_results(self):
        """The map is the opening screen, not a permanent fixture."""
        self.open()
        self.page.evaluate("""() => {
          document.querySelector('#results').innerHTML = '<div class="card"></div>';
        }""")
        self.assertEqual(
            self.page.evaluate("() => document.querySelectorAll('.map-class').length"), 0)
        # And re-rendering the selection must not crash with the map gone.
        self.page.evaluate("""() => {
          const box = document.querySelector('input[name=category]');
          box.checked = !box.checked;
          box.dispatchEvent(new Event('change', {bubbles: true}));
        }""")
        self.page.wait_for_timeout(150)


if __name__ == "__main__":
    unittest.main()
