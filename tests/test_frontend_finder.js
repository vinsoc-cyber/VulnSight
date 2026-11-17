'use strict';

// Unit tests for the CWE finder and recent-search helpers in static/app.js.
// The functions are lifted out of the file and evaluated in isolation, so the
// tested source is always the shipped source.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const appSource = fs.readFileSync(
  path.join(__dirname, '..', 'static', 'app.js'),
  'utf8',
);

// Slice a named function out of app.js by matching braces. Safe here because
// every brace inside these bodies (including regex quantifiers) is balanced.
function extract(name) {
  const start = appSource.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `${name}() must exist in app.js`);
  let depth = 0;
  for (let i = appSource.indexOf('{', start); i < appSource.length; i++) {
    if (appSource[i] === '{') depth++;
    else if (appSource[i] === '}' && --depth === 0) {
      return appSource.slice(start, i + 1);
    }
  }
  throw new Error(`unbalanced braces while extracting ${name}`);
}

function build(names, preamble = '') {
  const bodies = names.map(extract).join('\n');
  return Function(`'use strict'; ${preamble}\n${bodies}\nreturn {${names.join(',')}};`)();
}

// --- sanitizeCategories: localStorage is user-writable, so this is a trust boundary
{
  const CLASSES = [{key: 'bac'}, {key: 'sqli'}];
  const {sanitizeCategories} = build(
    ['sanitizeCategories'],
    `const CLASSES = ${JSON.stringify(CLASSES)};`,
  );

  assert.deepEqual(sanitizeCategories(['bac', 'cwe:639']), ['bac', 'cwe:639']);
  assert.deepEqual(sanitizeCategories(['cwe:1']), ['cwe:1']);
  assert.deepEqual(sanitizeCategories(['cwe:1234567']), ['cwe:1234567']);

  // Anything the backend would reject must never leave the browser.
  const rejected = [
    'nope', 'cwe:', 'cwe:0', 'cwe:012', 'cwe:79a', 'cwe-79', '639',
    'cwe:12345678', 'CWE:639', '__proto__', 'bac; drop table',
  ];
  for (const value of rejected) {
    assert.deepEqual(sanitizeCategories([value]), [], `must reject ${value}`);
  }
  assert.deepEqual(sanitizeCategories([{key: 'bac'}, null, 42, undefined]), []);
  assert.deepEqual(sanitizeCategories('bac'), []);
  assert.deepEqual(sanitizeCategories(undefined), []);
  assert.deepEqual(sanitizeCategories(['bac', 'evil', 'cwe:639']), ['bac', 'cwe:639']);
}

// --- scoreEntry: ranking is what makes a 944-row catalog usable
{
  const CLASS_BY_CWE = {639: ['Broken Access Control (BAC)']};
  const {scoreEntry, escapeRe} = build(
    ['scoreEntry', 'escapeRe'],
    `const CLASS_BY_CWE = ${JSON.stringify(CLASS_BY_CWE)};`,
  );

  const cwe = (id, label, aliases) => ({
    kind: 'cwe', id: id, label: label, aliases: aliases || [],
    hay: (id + ' ' + label + ' ' + (aliases || []).join('|')).toLowerCase(),
  });
  const klass = (label) => ({
    kind: 'class', label: label, aliases: [], hay: label.toLowerCase(),
  });

  const score = (entry, query) => {
    const q = query.toLowerCase();
    const idQuery = /^(cwe[-\s]?)?\d+$/.test(q) ? q.replace(/^cwe[-\s]?/, '') : '';
    return scoreEntry(entry, q, idQuery, q.split(/\s+/).filter(Boolean),
      new RegExp('\\b' + escapeRe(q)));
  };

  const c639 = cwe('639', 'Authorization Bypass Through User-Controlled Key',
    ['Insecure Direct Object Reference', 'IDOR', 'BOLA']);
  const c63 = cwe('63', 'Some Other Weakness', []);
  const c1321 = cwe('1321', 'Improperly Controlled Modification of Object Prototype '
    + "Attributes ('Prototype Pollution')", []);

  // An exact id beats a prefix match on a shorter id.
  assert.ok(score(c639, '639') > score(c63, '639'));
  assert.ok(score(c639, '63') < score(c63, '63'), 'exact id wins over prefix');
  // The "CWE-" prefix is accepted.
  assert.equal(score(c639, 'cwe-639'), score(c639, '639'));
  // Community aliases resolve.
  assert.ok(score(c639, 'idor') > 0);
  assert.ok(score(c639, 'bola') > 0);
  // Multi-word names resolve, and unrelated queries do not.
  assert.ok(score(c1321, 'prototype pollution') > 0);
  assert.equal(score(c1321, 'sql injection'), 0);
  assert.equal(score(c639, 'zzzz'), 0);
  // A curated class outranks a bare CWE on an equal textual match.
  assert.ok(score(klass('Prototype Pollution'), 'prototype pollution')
    > score(c1321, 'prototype pollution'));
  // A CWE a class already covers outranks one it does not.
  const covered = cwe('639', 'Authorization Bypass', []);
  const uncovered = cwe('700', 'Authorization Bypass', []);
  assert.ok(score(covered, 'authorization bypass') > score(uncovered, 'authorization bypass'));
  // A word-boundary hit beats a mid-word hit.
  assert.ok(score(cwe('1', 'Open Redirect', []), 'redirect')
    > score(cwe('2', 'Undirected Thing', []), 'direct'));
}

// --- stateSignature: dedupes history regardless of selection order
{
  const {stateSignature} = build(['stateSignature']);
  const base = {
    categories: ['bac', 'cwe:639'], include_extended: true, ecosystem: 'maven',
    severity: 'any', affects: '', published: '1y', max_results: 100,
    sort: 'published', direction: 'desc', type: 'reviewed', sources: ['ghsa', 'osv'],
  };
  const reordered = Object.assign({}, base, {
    categories: ['cwe:639', 'bac'], sources: ['osv', 'ghsa'],
  });
  assert.equal(stateSignature(base), stateSignature(reordered),
    'order of categories/sources must not create a duplicate history entry');
  assert.notEqual(stateSignature(base),
    stateSignature(Object.assign({}, base, {ecosystem: 'go'})));
  assert.notEqual(stateSignature(base),
    stateSignature(Object.assign({}, base, {include_extended: false})));
  // Signatures must not mutate the caller's arrays.
  assert.deepEqual(base.categories, ['bac', 'cwe:639']);
}

// --- relativeTime: never renders "NaN" for a corrupted timestamp
{
  const {relativeTime} = build(['relativeTime']);
  const now = Date.now();
  assert.equal(relativeTime(now), 'just now');
  assert.equal(relativeTime(now - 5 * 60000), '5m ago');
  assert.equal(relativeTime(now - 3 * 3600000), '3h ago');
  assert.equal(relativeTime(now - 26 * 3600000), 'yesterday');
  assert.equal(relativeTime(now - 5 * 86400000), '5d ago');
  for (const bad of [undefined, null, NaN, 'nonsense', {}]) {
    assert.equal(relativeTime(bad), 'just now', `bad timestamp: ${String(bad)}`);
  }
}

// --- publishedWindow: the date filter the backend validates
{
  const {publishedWindow} = build(['publishedWindow']);
  assert.equal(publishedWindow('any'), '');
  assert.equal(publishedWindow(''), '');
  assert.equal(publishedWindow('bogus'), '');
  assert.equal(publishedWindow('2020'), '>=2020-01-01');
  assert.match(publishedWindow('1y'), /^>=\d{4}-\d{2}-\d{2}$/);
}

// --- A curated class outranks its own CWE, whatever its KEYWORDS order ---
// docs/cwe-catalog.md explains the +60 class bonus: "a curated class is
// usually the better query target. That is why 'prototype pollution'
// surfaces the PROTO class above CWE-1321." That only held when the term
// happened to be in the first four KEYWORDS entries, because classEntries
// capped the alias list used for *scoring* at four. "xss" is 3rd in
// KEYWORDS["xss"] and won; "idor" is 6th in KEYWORDS["bac"] and lost to
// CWE-639 -- the exact weakness commit 0a1e9c7 was about.
{
  const CLASSES = [{
    key: 'bac',
    code: 'BAC',
    label: 'Broken Access Control (BAC / BOLA / BFLA / IDOR)',
    cwes: ['284', '285', '639'],
    description: 'Authorization and access-control flaws.',
    // Deliberately long, with the community term late in the list.
    terms: ['authoriz', 'authorisation', 'access control', 'access-control',
            'permission', 'idor', 'bola', 'bfla'],
  }];
  const {classEntries} = build(['classEntries', 'classHaystack'], `
    const CLASS_HAY = {};
    const CLASSES = ${JSON.stringify(CLASSES)};
  `);
  const entry = classEntries()[0];
  assert.ok(entry.aliases.includes('idor'),
    'the scoring alias list must not be capped: "idor" is 6th in KEYWORDS["bac"]');
  assert.ok(entry.aliases.includes('bfla'),
    'the scoring alias list must not be capped: "bfla" is 8th');
  assert.equal(entry.aliases.length, CLASSES[0].terms.length,
    'every community term must be searchable');
}

console.log('frontend finder + history checks passed');
