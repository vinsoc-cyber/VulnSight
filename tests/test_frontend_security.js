'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const appSource = fs.readFileSync(
  path.join(__dirname, '..', 'static', 'app.js'),
  'utf8',
);
const functionStart = appSource.indexOf('function csvCell');
const functionEnd = appSource.indexOf('\n    function doExport', functionStart);
assert.notEqual(functionStart, -1, 'csvCell must exist in app.js');
assert.notEqual(functionEnd, -1, 'csvCell must end before doExport');

const csvCell = Function(
  `'use strict'; ${appSource.slice(functionStart, functionEnd)}; return csvCell;`,
)();

for (const value of ['=2+2', '+CMD', '-1+2', '@SUM(A1:A2)', '  =HYPERLINK("x")']) {
  assert.match(csvCell(value), /'?'/, `dangerous CSV cell was not neutralized: ${value}`);
  const decoded = csvCell(value).replace(/^"|"$/g, '').replace(/""/g, '"');
  assert.equal(decoded[0], "'", `cell must begin with an apostrophe: ${value}`);
}

assert.equal(csvCell('\tformula-like'), "'\tformula-like");
assert.equal(csvCell('ordinary text'), 'ordinary text');
assert.match(appSource, /function apiPost/);
assert.match(appSource, /X-VulnSight-Token/);
assert.match(appSource, /AUTH_REQUIRED/);
assert.equal(csvCell('alpha,beta'), '"alpha,beta"');
assert.equal(csvCell('say "hello"'), '"say ""hello"""');

// --- Escaping -----------------------------------------------------------
// Advisory text is attacker-influenced: OSV ingests from many community
// sources and the `malware` advisory type is supported. esc() and safeUrl()
// are what stand between a hostile description and the DOM, and neither had
// a single test -- the file named "security" tested CSV formula injection
// only.
function extract(name, endMarker) {
  // The signature, not just the name: `function esc` also matches
  // `function escapeRe`, which is declared earlier and would be extracted
  // instead, yielding an undefined helper and a confusing failure.
  const start = appSource.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `${name} must exist in app.js`);
  const end = appSource.indexOf(endMarker, start);
  assert.notEqual(end, -1, `${name} must end before ${endMarker}`);
  return appSource.slice(start, end);
}

const escSource = extract('esc', '\n    const safeAttr');
// Newline before the return: the slice can end on a // comment, which
// would otherwise swallow it.
const esc = Function(`'use strict'; ${escSource}\n; return esc;`)();

for (const [raw, expected] of [
  ['<img src=x onerror=alert(1)>',
   '&lt;img src=x onerror=alert(1)&gt;'],
  ['"><script>alert(1)</script>',
   '&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;'],
  ["' onmouseover='alert(1)", '&#39; onmouseover=&#39;alert(1)'],
  ['a & b', 'a &amp; b'],
]) {
  assert.equal(esc(raw), expected, `esc did not neutralize: ${raw}`);
}

// Every character that can break out of text or a double-quoted attribute.
for (const ch of ['&', '<', '>', '"', "'"]) {
  assert.notEqual(esc(ch), ch, `esc left ${ch} unescaped`);
}

// esc() must not throw on the shapes a JSON payload can actually contain.
// safeAttr was a second escaper that lacked this coercion, so a numeric
// advisory_id threw inside renderCard and blanked the whole result list --
// render() builds every card in one expression.
for (const value of [null, undefined, 0, 42, true, {}, []]) {
  assert.doesNotThrow(() => esc(value), `esc threw on ${String(value)}`);
}
assert.equal(esc(42), '42');
assert.match(appSource, /const safeAttr = esc;/,
  'safeAttr must be esc, not a second implementation that can throw');

// safeUrl(): a javascript: or data: href is script execution on click.
const safeUrlSource = extract('safeUrl', '\n    function severityRank');
// safeUrl closes over `window` (for the resolution base) and `esc`, so the
// sandbox has to supply both or every URL throws and comes back as '#'.
const safeUrl = Function('window', 'esc',
  `'use strict'; ${safeUrlSource}\n; return safeUrl;`,
)({ location: { origin: 'https://vulnsight.test' } }, esc);

for (const hostile of [
  'javascript:alert(1)',
  'JaVaScRiPt:alert(1)',
  '  javascript:alert(1)',
  'data:text/html,<script>alert(1)</script>',
  'vbscript:msgbox(1)',
  'file:///etc/passwd',
]) {
  assert.equal(safeUrl(hostile), '#', `safeUrl allowed: ${hostile}`);
}
for (const ok of [
  'https://github.com/advisories/GHSA-x',
  'http://example.test/a',
]) {
  assert.equal(safeUrl(ok), ok, `safeUrl rejected a legitimate URL: ${ok}`);
}
// The result is escaped, so it is safe to drop straight into an attribute.
assert.equal(safeUrl('https://x.test/a?b=1&c=2'), 'https://x.test/a?b=1&amp;c=2');
for (const value of [null, undefined, 0, {}]) {
  assert.doesNotThrow(() => safeUrl(value), `safeUrl threw on ${String(value)}`);
}

console.log('frontend escaping checks passed');
console.log('frontend CSV security checks passed');
