"""Tests for cwe_categories: category tables, CWE resolution and id helpers."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import unittest

from modules import cwe_categories as cwe
from modules.cwe_catalog import NAMES


class TestCweCategories(unittest.TestCase):
    def test_bac_core_present(self):
        core = cwe.category_cwes("bac", include_extended=False)
        for c in ["639", "862", "863", "285", "284"]:
            self.assertIn(c, core)

    def test_extended_superset(self):
        core = set(cwe.category_cwes("bac", False))
        ext = set(cwe.category_cwes("bac", True))
        self.assertTrue(core.issubset(ext))
        self.assertGreater(len(ext), len(core))

    def test_resolve_dedups_across_categories(self):
        merged = cwe.resolve_cwes(["bac", "sqli", "bac"])
        self.assertEqual(len(merged), len(set(merged)))
        self.assertIn("89", merged)

    def test_unknown_category_empty(self):
        self.assertEqual(cwe.category_cwes("nope"), [])

    def test_label_uses_official_mitre_name(self):
        self.assertEqual(
            cwe.cwe_label("639"), "Authorization Bypass Through User-Controlled Key"
        )
        self.assertEqual(cwe.cwe_label("CWE-639"), cwe.cwe_label("639"))
        self.assertEqual(cwe.cwe_label("999999"), "CWE-999999")

    def test_community_terms_are_findable(self):
        """The terms people actually type must match, not just MITRE's names.

        The UI searches name + aliases together, so a term already present in
        the official name (SSRF, XXE) is deliberately not duplicated as an
        alias — assert on the combined searchable text instead.
        """
        searches = {
            "639": ("IDOR", "BOLA"),
            "918": ("SSRF",),
            "611": ("XXE",),
            "79": ("XSS",),
            "89": ("SQLi",),
            "1321": ("prototype pollution",),
            "862": ("BFLA",),
            "22": ("path traversal",),
            "502": ("deserialization",),
            "1336": ("SSTI", "template injection"),
        }
        for cwe_id, terms in searches.items():
            haystack = " ".join(
                (cwe.cwe_label(cwe_id), *cwe.cwe_aliases(cwe_id))).lower()
            for term in terms:
                with self.subTest(cwe=cwe_id, term=term):
                    self.assertIn(term.lower(), haystack)

    def test_aliases_of_unknown_cwe_are_empty(self):
        self.assertEqual(cwe.cwe_aliases("999999"), ())


class TestCwePseudoCategories(unittest.TestCase):
    """Any single CWE can act as an ad-hoc bug class via the 'cwe:<id>' key."""

    def test_round_trip(self):
        self.assertEqual(cwe.cwe_key("CWE-639"), "cwe:639")
        self.assertEqual(cwe.cwe_key("639"), "cwe:639")
        self.assertEqual(cwe.parse_cwe_key("cwe:639"), "639")
        self.assertEqual(cwe.parse_cwe_key("CWE:639"), "639")

    def test_non_keys_return_none(self):
        for value in ("bac", "cwe:", "cwe:0", "cwe:012", "cwe:79a", "cwe-79", "639",
                      "cwe:" + "9" * (cwe.MAX_CWE_ID_DIGITS + 1)):
            with self.subTest(value=value):
                self.assertIsNone(cwe.parse_cwe_key(value))

    def test_is_known_category(self):
        self.assertTrue(cwe.is_known_category("bac"))
        self.assertTrue(cwe.is_known_category("cwe:1321"))
        self.assertFalse(cwe.is_known_category("nope"))
        self.assertFalse(cwe.is_known_category("cwe:0"))

    def test_unknown_cwe_ids_are_rejected(self):
        """A typo must not reach the AI as a contentless class."""
        self.assertFalse(cwe.is_known_category("cwe:9999999"))
        self.assertNotIn("9999999", cwe.NAMES)

    def test_deprecated_cwe_ids_are_still_accepted(self):
        """Advisories still carry them, so they must stay queryable."""
        from modules import cwe_catalog

        deprecated = sorted(cwe_catalog.DEPRECATED, key=int)[0]
        self.assertTrue(cwe.is_known_category(f"cwe:{deprecated}"))

    def test_canonical_category_folds_equivalent_spellings(self):
        self.assertEqual(cwe.canonical_category("CWE:639"), "cwe:639")
        self.assertEqual(cwe.canonical_category("cwe:639"), "cwe:639")
        self.assertEqual(cwe.canonical_category("bac"), "bac")
        self.assertEqual(cwe.canonical_category("nope"), "nope")

    def test_resolves_to_exactly_that_cwe(self):
        self.assertEqual(cwe.category_cwes("cwe:1321"), ["1321"])
        self.assertEqual(cwe.category_cwes("cwe:1321", include_extended=False), ["1321"])
        # Composed with a curated class, the pseudo-category contributes its
        # one CWE and nothing else. Asserted against the class's own core set
        # rather than a copy of it, so correcting the taxonomy does not fail a
        # test that is really about `cwe:<id>` resolution.
        self.assertEqual(
            cwe.resolve_cwes(["sqli", "cwe:1321"], False),
            [*cwe.CATEGORIES["sqli"]["core"], "1321"],
        )

    def test_label_and_description_are_ai_ready(self):
        """The AI prompt is built from these, so neither may be empty."""
        label = cwe.category_label("cwe:639")
        self.assertIn("CWE-639", label)
        self.assertIn("Authorization Bypass", label)
        description = cwe.category_description("cwe:639")
        self.assertIn("IDOR", description)
        self.assertTrue(cwe.category_description("cwe:9999999"))
        self.assertEqual(cwe.category_label("bac"), cwe.CATEGORIES["bac"]["label"])

    def test_keywords_prefer_aliases_over_the_official_name(self):
        keywords = cwe.category_keywords(["cwe:918"])
        self.assertIn("ssrf", keywords)
        self.assertTrue(all(k == k.lower() for k in keywords))
        self.assertEqual(len(keywords), len(set(keywords)))
        # Mixing a curated class with a CWE key yields both keyword sets.
        mixed = cwe.category_keywords(["sqli", "cwe:918"])
        self.assertIn("sql injection", mixed)
        self.assertIn("ssrf", mixed)


class TestPickerCatalog(unittest.TestCase):
    def test_shape_and_coverage(self):
        catalog = cwe.picker_catalog()
        self.assertEqual(catalog["columns"], ["id", "label", "aliases", "level"])
        self.assertGreater(len(catalog["rows"]), 900)
        self.assertRegex(catalog["version"], r"^\d+\.\d+$")
        ids = [row[0] for row in catalog["rows"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(ids, sorted(ids, key=int))
        for row in catalog["rows"]:
            self.assertEqual(len(row), 4)
            self.assertTrue(row[1], msg=f"CWE-{row[0]} has no label")

    def test_deprecated_cwes_are_hidden_but_still_labelled(self):
        from modules import cwe_catalog

        listed = {row[0] for row in cwe.picker_catalog()["rows"]}
        self.assertTrue(cwe_catalog.DEPRECATED, "expected some deprecated CWEs")
        for cwe_id in cwe_catalog.DEPRECATED:
            self.assertNotIn(cwe_id, listed)
            # A historical advisory tag must still render a name.
            self.assertNotEqual(cwe.cwe_label(cwe_id), f"CWE-{cwe_id}")

    def test_every_curated_class_cwe_is_in_the_catalog(self):
        listed = {row[0] for row in cwe.picker_catalog()["rows"]}
        for key, cat in cwe.CATEGORIES.items():
            for cwe_id in cat["core"] + cat["extended"]:
                self.assertIn(cwe_id, listed,
                              msg=f"class '{key}' uses CWE-{cwe_id}, missing from catalog")


class TestNormalizeCweId(unittest.TestCase):
    def test_normalize_variants(self):
        self.assertEqual(cwe.normalize_cwe_id("CWE-639"), "639")
        self.assertEqual(cwe.normalize_cwe_id("cwe-89 "), "89")
        self.assertEqual(cwe.normalize_cwe_id(" 22 "), "22")
        self.assertEqual(cwe.normalize_cwe_id("639"), "639")


class TestDataIntegrity(unittest.TestCase):
    """The static tables must stay mutually consistent as categories grow."""

    def test_every_category_is_completely_specified(self):
        """A half-filled class silently degrades search and the AI prompt."""
        for key, cat in cwe.CATEGORIES.items():
            with self.subTest(category=key):
                self.assertTrue(cat.get("code"), "missing code")
                self.assertTrue(cat.get("group"), "missing group")
                self.assertTrue(cat.get("label"), "missing label")
                # The description is injected into the AI prompt as the class
                # definition; a stub makes the verdict meaningless.
                self.assertGreaterEqual(len(cat.get("description", "")), 40)
                self.assertTrue(cat.get("core"), "core CWE set may not be empty")
                self.assertIn(key, cwe.KEYWORDS,
                              "no keyword prefilter -> OSV-native finds nothing")
                self.assertTrue(cwe.KEYWORDS[key])

    def test_no_cwe_is_both_core_and_extended(self):
        for key, cat in cwe.CATEGORIES.items():
            overlap = set(cat["core"]) & set(cat["extended"])
            with self.subTest(category=key):
                self.assertEqual(overlap, set(), f"CWE {overlap} listed twice")

    def test_no_duplicate_cwe_within_a_bucket(self):
        for key, cat in cwe.CATEGORIES.items():
            for bucket in ("core", "extended"):
                ids = cat[bucket]
                with self.subTest(category=key, bucket=bucket):
                    self.assertEqual(len(ids), len(set(ids)))

    def test_cwe_ids_are_canonical_bare_numbers(self):
        for key, cat in cwe.CATEGORIES.items():
            for cwe_id in cat["core"] + cat["extended"]:
                with self.subTest(category=key, cwe=cwe_id):
                    self.assertRegex(cwe_id, r"^[1-9][0-9]*$")
                    self.assertEqual(cwe_id, cwe.normalize_cwe_id(cwe_id))

    def test_keywords_are_lowercase_and_deduplicated(self):
        for key, words in cwe.KEYWORDS.items():
            with self.subTest(category=key):
                self.assertEqual(words, [w.lower() for w in words])
                self.assertEqual(len(words), len(set(words)))
                self.assertTrue(all(w.strip() for w in words))

    def test_every_category_resolves_to_at_least_one_cwe(self):
        for key in cwe.CATEGORIES:
            with self.subTest(category=key):
                self.assertTrue(cwe.resolve_cwes([key], include_extended=False))

    def test_class_labels_are_unique(self):
        labels = [c["label"] for c in cwe.CATEGORIES.values()]
        self.assertEqual(len(labels), len(set(labels)))

    def test_every_category_has_a_short_unique_code(self):
        """The UI renders these in a fixed-width column; long codes eat the name."""
        codes = [cat["code"] for cat in cwe.CATEGORIES.values()]
        self.assertEqual(len(codes), len(set(codes)), msg=f"duplicate codes: {codes}")
        for key, cat in cwe.CATEGORIES.items():
            code = cat["code"]
            with self.subTest(category=key):
                self.assertTrue(code)
                # Five characters: the picker renders the code in a
                # fixed-width column beside the CWE name, and a longer
                # one pushes the name out of a ~300px rail.
                self.assertLessEqual(len(code), 5)
                self.assertEqual(code, code.upper())

    def test_keyword_keys_are_known_categories(self):
        for key in cwe.KEYWORDS:
            self.assertIn(key, cwe.CATEGORIES,
                          msg=f"KEYWORDS['{key}'] has no matching category")

    def test_every_category_cwe_is_in_the_mitre_catalog(self):
        """A curated id that MITRE does not define renders as the bare
        "CWE-639" placeholder in the picker and in every result row, which
        looks like a missing label rather than the typo it is."""
        for key, cat in cwe.CATEGORIES.items():
            for c in cat["core"] + cat["extended"]:
                with self.subTest(category=key, cwe=c):
                    self.assertIn(c, NAMES, f"category '{key}': CWE-{c} "
                                            "is not in the MITRE catalog")
                    self.assertEqual(cwe.cwe_label(c), NAMES[c])



class TestATaxonomyClassCanFindItsOwnBug(unittest.TestCase):
    """Core is the documented precision mode: "an advisory carrying this CWE
    is almost certainly this class" (docs/bug-classes.md).

    The split had been applied backwards in a systematic way -- the vaguest
    umbrellas (CWE-284 Pillar, CWE-200 Class) sat in `core` while the most
    specific tags sat in `extended`, so six classes could not find, in
    precision mode, the bug their own label names. A false negative is the
    worst failure mode this tool has, because the result still looks like an
    answer.
    """

    #  class            CWE     what it is
    PROMISED = [
        ("crlf", "444", "HTTP Request/Response Smuggling"),
        ("session", "613", "Insufficient Session Expiration"),
        ("cors", "346", "Origin Validation Error"),
        ("hardcodedcreds", "1392", "Use of Default Credentials"),
        ("hardcodedcreds", "259", "Use of Hard-coded Password"),
        ("queryinj", "652", "XQuery Injection"),
        ("sqli", "943", "NoSQL / data query logic"),
        ("pathtraversal", "23", "Relative Path Traversal"),
        ("pathtraversal", "36", "Absolute Path Traversal"),
        ("xss", "80", "Basic XSS"),
        ("ssti", "95", "Eval Injection"),
        ("searchpath", "428", "Unquoted Search Path"),
        ("intoverflow", "191", "Integer Underflow"),
        ("infoleak", "522", "Insufficiently Protected Credentials"),
    ]

    def test_precision_mode_reaches_the_bug_each_class_is_named_for(self):
        for key, cwe_id, what in self.PROMISED:
            with self.subTest(category=key, cwe=cwe_id):
                core_only = cwe.category_cwes(key, include_extended=False)
                self.assertIn(cwe_id, core_only,
                              f"{key} cannot find CWE-{cwe_id} ({what}) without extended")

    def test_the_dynamic_code_family_is_not_filed_under_access_control(self):
        """CWE-913's children are 502 (deserialization), 915 (prototype
        pollution) and 470 (unsafe reflection). Nothing under it is
        authorization, and it sits under CWE-664, not CWE-284."""
        self.assertNotIn("913", cwe.category_cwes("bac"))
        self.assertIn("913", cwe.category_cwes("deserialization"))

    def test_request_smuggling_and_its_parent_are_in_the_same_class(self):
        """CWE-436 Interpretation Conflict is CWE-444's parent. They were in
        two unrelated classes and the parent was in neither's."""
        crlf = cwe.category_cwes("crlf")
        self.assertIn("444", crlf)
        self.assertIn("436", crlf)
        self.assertNotIn("436", cwe.category_cwes("upload"))

    def test_the_credential_exposure_cluster_is_reachable(self):
        """822 tag occurrences were in no class at all, so an analyst ticking
        the two obvious classes concluded an ecosystem was clean of
        cleartext-credential bugs."""
        reachable = set(cwe.category_cwes("infoleak")) | set(
            cwe.category_cwes("hardcodedcreds"))
        for cwe_id in ("522", "311", "312", "319", "256", "922"):
            self.assertIn(cwe_id, reachable, f"CWE-{cwe_id} is unreachable")

    def test_keyword_promises_are_backed_by_a_cwe(self):
        """A keyword advertises a bug on the OSV-native path; the CWE path
        has to be able to reach the same bug."""
        for key, cwe_id in (("pathtraversal", "59"),    # zip slip
                            ("dos", "835"),             # infinite loop
                            ("dos", "1325"),            # stack exhaustion
                            ("race", "833")):           # deadlock
            with self.subTest(category=key, cwe=cwe_id):
                self.assertIn(cwe_id, cwe.category_cwes(key))

    def test_no_keyword_is_a_substring_trap(self):
        """docs/bug-classes.md warns about this by name ('"dos" matches
        "kudos"'). The matcher is a bare `k in text`, so "acl" matched oracle
        -- and "padding oracle" is itself a crypto keyword, which quietly sent
        crypto advisories into the BAC AI queue at one paid call each."""
        # Words that no bug-class keyword should appear *inside*. A keyword
        # that IS one of these is a real term, not a trap, so exact matches
        # are allowed -- it is the accidental substring that misfires.
        decoys = ("oracle", "retrieval", "evaluation", "kudos", "miracle",
                  "medieval", "obstacle", "tentacle", "reevaluated")
        # An empty KEYWORDS would satisfy "no keyword is a trap" vacuously.
        self.assertGreater(sum(len(v) for v in cwe.KEYWORDS.values()), 50,
                           "KEYWORDS looks empty; this check proves nothing")
        for category, keywords in cwe.KEYWORDS.items():
            for keyword in keywords:
                for decoy in decoys:
                    if keyword != decoy and keyword in decoy:
                        self.fail(f"KEYWORDS[{category!r}] entry {keyword!r} "
                                  f"matches inside the unrelated word {decoy!r}")

    def test_no_derived_keyword_is_a_substring_trap(self):
        """The sweep above covers the curated classes. The incident it is
        named for came from the *derived* side: CWE-616's name ends in
        "(PHP)", so `cwe:616` prefiltered on "php" and matched essentially
        every PHP advisory. Nothing checked that half.

        No trap exists today across all ~940 catalog ids -- this keeps it
        that way, because the terms are generated from MITRE's text and a
        future catalog release can introduce one without anyone editing
        this repo.
        """
        # "resource" and friends are here because they were not: the sweep
        # asserted "no trap exists today across all ~940 catalog ids" while
        # "rce" was whitelisted and sat inside five of these words. A decoy
        # list is only as good as the words somebody thought to put in it.
        decoys = ("oracle", "retrieval", "evaluation", "kudos", "miracle",
                  "medieval", "obstacle", "tentacle", "reevaluated",
                  "php", "association", "classification", "serialisation",
                  "resource", "source", "enforce", "forced", "coerce",
                  "reinforced", "outsourced")
        ids = [row[0] for row in cwe.picker_catalog()["rows"]]
        self.assertGreater(len(ids), 500, "the catalog looks truncated")

        for cwe_id in ids:
            for keyword in cwe.category_keywords([f"cwe:{cwe_id}"]):
                for decoy in decoys:
                    if keyword != decoy and keyword in decoy:
                        self.fail(
                            f"cwe:{cwe_id} derives the term {keyword!r}, which "
                            f"matches inside the unrelated word {decoy!r}")



class TestDerivedPrefilterTermsAreUseful(unittest.TestCase):
    """KEYWORDS are matched as bare substrings against advisory text.

    _cwe_keywords derived terms from any 3+-character parenthesised fragment
    of a CWE's name, with no quality filter, so `cwe:616` -- whose name ends
    "(PHP)" -- prefiltered on "php" and matched essentially every PHP
    advisory, at one paid AI call each.
    """

    def test_junk_short_forms_are_dropped(self):
        for category, junk in (("cwe:616", "php"),
                               ("cwe:1192", "soc"),
                               ("cwe:462", "alist")):
            with self.subTest(category=category):
                self.assertNotIn(junk, cwe.category_keywords([category]))

    def test_real_acronyms_survive(self):
        self.assertIn("xss", cwe.category_keywords(["cwe:79"]))
        self.assertIn("csrf", cwe.category_keywords(["cwe:352"]))
        self.assertIn("ssrf", cwe.category_keywords(["cwe:918"]))

    def test_an_alias_that_is_a_common_word_is_dropped(self):
        """MITRE lists CSS as a historical alternate term for cross-site
        scripting; as a substring it matches every stylesheet advisory."""
        self.assertNotIn("css", cwe.category_keywords(["cwe:79"]))

    def test_the_full_name_is_always_kept(self):
        terms = cwe.category_keywords(["cwe:616"])
        self.assertTrue(any("uploaded file variables" in t for t in terms), terms)

    def test_bac_no_longer_prefilters_on_a_bare_bypass(self):
        """It was 52% of this class's prefilter passes, matching "bypass the
        cache", "filter bypass" and every other unrelated use."""
        keywords = cwe.KEYWORDS["bac"]
        self.assertNotIn("bypass", keywords)
        self.assertTrue([k for k in keywords if k.endswith("bypass")],
                        "the specific bypass phrases must remain")

    def test_the_specific_bypass_phrases_still_match(self):
        keywords = cwe.KEYWORDS["bac"]
        for text in ("authorization bypass in the admin api",
                     "authentication bypass via crafted header",
                     "access control bypass"):
            with self.subTest(text=text):
                self.assertTrue(any(k in text for k in keywords), text)

    def test_an_unrelated_bypass_no_longer_matches(self):
        keywords = cwe.KEYWORDS["bac"]
        for text in ("allows an attacker to bypass the cache",
                     "regex filter bypass leads to redos"):
            with self.subTest(text=text):
                self.assertFalse(any(k in text for k in keywords), text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
