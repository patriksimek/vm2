# Attack Catalog Restructure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split `docs/ATTACKS.md` into one index document plus eight per-family files, verify every category against current `main`, and guard the result with a test.

**Architecture:** A one-off script moves text mechanically (no prose edits) and generates metadata from data already in the file; that becomes a pure-move baseline commit. Eight reviewers then edit one family file each under a fixed checklist, a cross-cutting reviewer reconciles the shared files, and `test/docs-catalog.js` keeps numbering and links honest from then on.

**Tech Stack:** Node (scripts run on the current Node, the committed test must run on Node 8+), Mocha, ESLint, git.

**Spec:** `docs/specs/2026-09-02-attacks-catalog-restructure-design.md`

## Global Constraints

- No changes under `lib/`. This is documentation and test infrastructure only.
- No category is renumbered, merged, split, or deleted. Numbers 1 through 52 are permanent identifiers.
- `## Attack Category N: <title>` heading lines are copied byte-for-byte, so GitHub anchors are unchanged.
- Category links always carry the file name: `family.md#anchor` between family files, `attacks/family.md#anchor` from the index, `../ATTACKS.md#anchor` from a family file to common material.
- Present tense only in catalog entries. "NOW FIXED", "historically", "was dangerous" are not used.
- Every entry has `**Advisories**:` and `**Tests**:` lines directly after its heading.
- `test/docs-catalog.js` runs on the CI matrix in `.github/workflows/test.yml`, which includes Node 8. No `matchAll`, `flat`, `fromEntries`, `??`, `?.`, optional catch binding, or regex named groups in that file.
- Code style: tabs, `'use strict'`, single quotes, `/* eslint-env mocha */` in test files. `npm run lint` must pass.
- Reviewers report missing regression tests; they do not write them.
- One-off scripts live in the session scratchpad, never in the repo.
- Family review tasks (Tasks 3–10) edit only their own family file plus their own report file. Shared files (`docs/ATTACKS.md`, other families, `lib/`, `test/`) are off limits to them.
- Commit messages end with the attribution trailer:
  ```
  Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01QtbYDJQFjzpbFa6aVYaqqR
  ```
- Deviation from spec §4 recorded here: the category index table has no `Tests` column. The `**Tests**:` line in the entry is the single source of truth; a second copy in the index would drift. The index keeps `#`, `Category`, `Family`, `Kind`, `Advisories`, and the test asserts the `Advisories` cell matches the entry.

## File Structure

| Path | Responsibility |
|---|---|
| `docs/ATTACKS.md` (rewritten) | Index and common material: how to use, family table, category index, entry format, fundamentals, invariants, summary, checklist, runtime note, considered surfaces, future risks. Contains no `## Attack Category` heading. |
| `docs/attacks/host-reference-primitives.md` | Categories 1, 2, 3, 5, 8, 10, 15, 18. |
| `docs/attacks/error-sanitization.md` | Categories 4, 16, 17, 38, 39, 48, 49. |
| `docs/attacks/promise-async.md` | Categories 7, 19, 29, 31, 33, 43, 51, plus the "Key Security Invariant: Promise Species Resolution Timing" note as preamble. |
| `docs/attacks/host-prototype-mutation.md` | Categories 20, 26, 30, 32, 37, 50. |
| `docs/attacks/bridge-internals.md` | Categories 6, 9, 11, 14, 27, 28, 44. |
| `docs/attacks/transformer-and-modules.md` | Categories 12, 13. |
| `docs/attacks/nodevm-require.md` | Categories 21, 24, 25, 34, 35, 40, 45, 46, 47, 52. |
| `docs/attacks/host-resources.md` | Categories 22, 23, 36, 41, 42. |
| `test/docs-catalog.js` (new) | Mocha test: numbering, links, metadata lines, index parity. |
| `docs/specs/2026-09-02-attacks-catalog-review-findings.md` (new) | Compiled reviewer reports: findings needing a human, unverified PoCs, coverage gaps. |
| `<scratchpad>/split-attacks.js` | One-off split script. Not committed. |
| `<scratchpad>/verify-split.js` | One-off checker comparing the new files with a baseline ref. Not committed. |
| `<scratchpad>/reports/<family>.md` | Per-family reviewer reports. Compiled by Task 11. |
| `CLAUDE.md`, `.claude/skills/{fix-vulnerability,hacker,maintainer,merge-fix}/SKILL.md` | Consumers updated in Task 12. |

`<scratchpad>` is `/private/tmp/claude-501/-Users-patriksimek-Projects-vm2/1391a0bb-d785-4a1c-b58a-0c5d16b5cad6/scratchpad`. Repo root is `/Users/patriksimek/Projects/vm2`.

## Shared definition: the slug function

GitHub builds a heading anchor by lowercasing, deleting every character that is not a word character, hyphen or space, then replacing spaces with hyphens. Both the split script and the docs test use exactly this:

```js
function slug(heading) {
	return heading.toLowerCase().replace(/[^\w\- ]/g, '').replace(/ /g, '-');
}
```

Checked against the file: `Attack Category 22: Promise Executor Unhandled Rejection — Host Process DoS` gives `attack-category-22-promise-executor-unhandled-rejection--host-process-dos`, which is the anchor the document already links to. Of the 42 distinct anchors the document uses, 36 resolve with this function. The other six are dead today, and four of them carry the **wrong category number** (left over from a past renumbering), so the split script must not trust the number in a dead anchor. It resolves each category anchor in this order: exact slug match on the numbered category; the anchor is a truncated prefix of that category's slug; an entry in the explicit `LINK_OVERRIDES` map below; otherwise it throws. Every override use is printed with its source line, and the family task that owns that line fixes the visible link text.

| Dead anchor in the current file | Source line | Really means | Link text to fix |
|---|---|---|---|
| `#attack-category-10-array-species-self-return-via-constructor-manipulation` | 264 (Category 3) | 18 | "Category 10: Array Species Self-Return" becomes "Category 18: Array Species Self-Return" |
| `#attack-category-20-cross-realm-symbol-extraction-via-host-object-prototype-walk` | 785 (Category 8), 2766 (Category 32) | 8 | "Category 8 / Category 20" becomes "Category 8"; "Category 8 / Category 20 / GHSA-m5q2-4fm3-vfqp" becomes "Category 8 / GHSA-m5q2-4fm3-vfqp" |
| `#attack-category-47x8` | 1532 (Category 20) | 8 | "Category 47x8" becomes "Category 8 (GHSA-47x8-96vw-5wg6)" |
| `#attack-category-21-nodevm-builtin-allowlist-bypass` | 1653 (Category 21) | 21 | none (truncated prefix, number correct) |
| `#attack-category-30-nodevm-process-wide-observability-builtins-host-data-info-leak` | 1699 (Category 21) | 35 | "Category 30" becomes "Category 35" |
| `#attack-category-32-nodevm-nesting--non-configuration-require-value` | 4104 (Category 47) | 25 | "Category 32" becomes "Category 25" |
| `#attack-category-36-buffallocLimit-bypass-via-arraybuffer--typedarray--webassemblymemory` | 1881 (Category 23) | 36 | none (typo "buffalloc" and mixed case; the script lowercases anchors before resolving and this literal is in the override map) |

## Shared definition: the family table

Used verbatim by the split script (Task 2) and by the reviewer prompts. `scope` is the preamble paragraph of the family file.

```js
const FAMILIES = [
	{
		file: 'host-reference-primitives.md',
		title: 'Host Reference Primitives',
		categories: [1, 2, 3, 5, 8, 10, 15, 18],
		invariants: [1, 4, 7, 8],
		mechanism: 'Reaching a raw host object or host `Function` through language-level channels',
		scope: 'Ways for sandbox code to obtain a raw host-realm object or the host `Function` constructor through language-level channels: constructor chains, prototype walks, well-known and cross-realm symbols, `caller`/`callee`, property descriptors, built-in functions used as conduits, and `ArraySpeciesCreate`. These are the atomic building blocks every compound escape starts from.',
	},
	{
		file: 'error-sanitization.md',
		title: 'Error and Exception Sanitization',
		categories: [4, 16, 17, 38, 39, 48, 49],
		invariants: [2, 3, 5],
		mechanism: 'Exceptions and error containers as carriers of host references past `handleException`',
		scope: 'Exceptions and error containers as carriers of host references. Every value entering a `catch` must pass through `handleException`; the entries here are the paths that carried a raw host error, a host `Error.cause`, a host stack string, or a live proxy past it.',
	},
	{
		file: 'promise-async.md',
		title: 'Promise and Async',
		categories: [7, 19, 29, 31, 33, 43, 51],
		invariants: [4, 12, 14],
		mechanism: 'Deferred execution: species, thenable assimilation, cross-realm Promise prototypes, engine protectors, `allowAsync`',
		scope: 'Deferred execution as a way to run sandbox code against unsanitized values: Promise species, thenable assimilation, cross-realm Promise prototypes, engine protector state, async generators, and the `allowAsync: false` boundary.',
	},
	{
		file: 'host-prototype-mutation.md',
		title: 'Host Prototype Mutation',
		categories: [20, 26, 30, 32, 37, 50],
		invariants: [6],
		mechanism: 'Writing into host intrinsic prototypes through bridge write traps, setter primitives, or `Receiver` confusion',
		scope: 'Writing into host-realm intrinsic prototypes from the sandbox: bridge `set`/`defineProperty` write-through, bridged setter primitives reached through the apply trap, `Receiver` confusion, and raw `__proto__` accessors.',
	},
	{
		file: 'bridge-internals.md',
		title: 'Bridge Internals',
		categories: [6, 9, 11, 14, 27, 28, 44],
		invariants: [8, 11],
		mechanism: 'Exploiting the bridge\'s own machinery: traps, handler exposure, monkey-patched primitives, internal containers and state, read-only views',
		scope: 'Attacks on the bridge\'s own machinery rather than on the objects it wraps: proxy trap handlers, handler exposure through `util.inspect`, monkey-patched `call`/`apply`/`defineProperty`, bridge-internal containers reachable through sandbox prototypes, the internal state object, and the read-only view.',
	},
	{
		file: 'transformer-and-modules.md',
		title: 'Transformer and Module Loading',
		categories: [12, 13],
		invariants: [9, 10],
		mechanism: 'Syntax the transformer cannot see, and dynamic code or module loading paths',
		scope: 'Syntax the Acorn transformer (`ecmaVersion: 2022`) cannot see, and the dynamic code and module loading paths. Every future transformer blind spot belongs here.',
	},
	{
		file: 'nodevm-require.md',
		title: 'NodeVM require and Allowlists',
		categories: [21, 24, 25, 34, 35, 40, 45, 46, 47, 52],
		invariants: [13],
		mechanism: '`NodeVM` builtin and external allowlists, `require.root`, `nesting`, host-authority members of allowed builtins',
		scope: '`NodeVM`\'s module boundary: the builtin allowlist and its wildcard, `require.root`, `nesting`, the external-package matcher, host-authority members of allowed builtins, and `util` passthrough.',
	},
	{
		file: 'host-resources.md',
		title: 'Host Resources',
		categories: [22, 23, 36, 41, 42],
		invariants: [],
		mechanism: 'Host memory, heap, process lifetime and the `timeout` guarantee: DoS and memory disclosure',
		scope: 'Host memory, heap and process lifetime: unbounded allocation, unhandled rejections that kill the host process, shared buffer pool disclosure, and callbacks that outlive `timeout`. No defense invariant covers this family yet; each guarantee is stated inside its Mitigation section (see the design spec, section 8).',
	},
];
```

Kind by number: 1–5 `primitive`, 6–15 `technique`, 16 and above `compound`.

---

### Task 1: The docs catalog test

**Files:**
- Create: `test/docs-catalog.js`

**Interfaces:**
- Consumes: `docs/ATTACKS.md`, `docs/attacks/*.md` (produced by Task 2).
- Produces: a Mocha suite `docs catalog` that Tasks 2, 11, 12 run to prove the layout holds. Nothing imports it.

- [ ] **Step 1: Write the test**

```js
/* eslint-env mocha */

'use strict';

// Guards the attack catalog layout: docs/ATTACKS.md is the index, one file per
// mechanism family lives under docs/attacks/. Category numbers are permanent
// identifiers referenced from CHANGELOG.md, test/ghsa/*/repro.js and the
// skills, so a renumbering or a dead link must fail the suite, not be found
// by a reader. Runs on Node 8, so keep the syntax and APIs conservative.

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const DOCS = path.join(__dirname, '..', 'docs');
const INDEX = path.join(DOCS, 'ATTACKS.md');
const FAMILY_DIR = path.join(DOCS, 'attacks');

const CATEGORY_RE = /^## Attack Category (\d+): (.+)$/;
const HEADING_RE = /^#{1,6} (.+)$/;
const GHSA_RE = /GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}/g;

// Same algorithm GitHub uses to build heading anchors.
function slug(heading) {
	return heading.toLowerCase().replace(/[^\w\- ]/g, '').replace(/ /g, '-');
}

function read(file) {
	return fs.readFileSync(file, 'utf8').split('\n');
}

// Fenced code blocks contain `](` sequences that are not links.
function stripFences(lines) {
	const out = [];
	let inFence = false;
	for (let i = 0; i < lines.length; i++) {
		if (/^\s*```/.test(lines[i])) {
			inFence = !inFence;
			out.push('');
			continue;
		}
		out.push(inFence ? '' : lines[i]);
	}
	return out;
}

function ghsaSet(text) {
	const set = {};
	const found = text.match(GHSA_RE) || [];
	for (let i = 0; i < found.length; i++) set[found[i]] = true;
	return Object.keys(set).sort();
}

function familyFiles() {
	return fs.readdirSync(FAMILY_DIR)
		.filter(name => /\.md$/.test(name))
		.sort()
		.map(name => path.join(FAMILY_DIR, name));
}

// {file, line, number, title, meta: {Advisories, Tests, ...}}
function categoriesIn(file) {
	const lines = read(file);
	const result = [];
	for (let i = 0; i < lines.length; i++) {
		const m = CATEGORY_RE.exec(lines[i]);
		if (!m) continue;
		const meta = {};
		for (let j = i + 1; j < lines.length && !/^#{1,3} /.test(lines[j]); j++) {
			const mm = /^\*\*([A-Za-z]+)\*\*:\s*(.*)$/.exec(lines[j]);
			if (mm) meta[mm[1]] = mm[2];
		}
		result.push({file: file, line: i + 1, number: Number(m[1]), title: m[2], meta: meta});
	}
	return result;
}

function headingSlugs(file) {
	const set = {};
	const lines = stripFences(read(file));
	for (let i = 0; i < lines.length; i++) {
		const m = HEADING_RE.exec(lines[i]);
		if (m) set[slug(m[1])] = true;
	}
	return set;
}

// Every markdown link target that carries an anchor or points at a .md file.
function linksIn(file) {
	const lines = stripFences(read(file));
	const links = [];
	const re = /\]\(([^)\s]+)\)/g;
	for (let i = 0; i < lines.length; i++) {
		let m;
		while ((m = re.exec(lines[i])) !== null) {
			const target = m[1];
			if (/^[a-z]+:/.test(target)) continue; // http(s), mailto
			if (target.indexOf('#') === -1 && !/\.md$/.test(target)) continue;
			links.push({line: i + 1, target: target});
		}
	}
	return links;
}

describe('docs catalog', function () {
	const files = familyFiles();
	const all = [];
	files.forEach(file => { categoriesIn(file).forEach(c => all.push(c)); });
	const byNumber = {};
	all.forEach(c => { byNumber[c.number] = c; });

	it('has at least one family file', function () {
		assert.ok(files.length > 0, 'docs/attacks/ is empty');
	});

	it('keeps every category heading out of the index', function () {
		assert.deepStrictEqual(categoriesIn(INDEX), []);
	});

	it('numbers categories 1..N with no gaps or duplicates', function () {
		const numbers = all.map(c => c.number).sort((a, b) => a - b);
		const seen = {};
		numbers.forEach(n => {
			assert.ok(!seen[n], 'Category ' + n + ' appears more than once');
			seen[n] = true;
		});
		for (let n = 1; n <= numbers.length; n++) {
			assert.ok(seen[n], 'Category ' + n + ' is missing');
		}
	});

	it('gives every category Advisories and Tests lines', function () {
		all.forEach(c => {
			const where = path.basename(c.file) + ':' + c.line + ' Category ' + c.number;
			assert.ok(c.meta.Advisories && c.meta.Advisories.trim(), where + ' has no **Advisories** line');
			assert.ok(c.meta.Tests && c.meta.Tests.trim(), where + ' has no **Tests** line');
		});
	});

	it('cites only advisories that have a test directory or are marked as duplicates', function () {
		all.forEach(c => {
			const ids = ghsaSet(c.meta.Advisories);
			ids.forEach(id => {
				const dir = path.join(__dirname, 'ghsa', id);
				const isDup = new RegExp(id + '[^,]*\\(dup of').test(c.meta.Advisories);
				assert.ok(fs.existsSync(dir) || isDup,
					'Category ' + c.number + ' cites ' + id + ' which has no test/ghsa/ directory and is not marked "(dup of ...)"');
			});
		});
	});

	it('lists every category in the index table with matching advisories', function () {
		const lines = read(INDEX);
		const rows = {};
		lines.forEach(line => {
			const m = /^\|\s*(\d+)\s*\|(.*)\|\s*$/.exec(line);
			if (m) rows[Number(m[1])] = m[2];
		});
		all.forEach(c => {
			assert.ok(rows[c.number], 'Category ' + c.number + ' has no row in the docs/ATTACKS.md index');
			assert.deepStrictEqual(ghsaSet(rows[c.number]), ghsaSet(c.meta.Advisories),
				'Category ' + c.number + ': index row advisories differ from the entry');
		});
	});

	it('resolves every link with an anchor or a .md target', function () {
		const slugCache = {};
		[INDEX].concat(files).forEach(file => {
			linksIn(file).forEach(link => {
				const hash = link.target.indexOf('#');
				const relPath = hash === -1 ? link.target : link.target.slice(0, hash);
				const anchor = hash === -1 ? null : link.target.slice(hash + 1);
				const target = relPath ? path.resolve(path.dirname(file), relPath) : file;
				const where = path.relative(DOCS, file) + ':' + link.line + ' -> ' + link.target;
				assert.ok(fs.existsSync(target), where + ' (file does not exist)');
				if (anchor === null) return;
				if (!slugCache[target]) slugCache[target] = headingSlugs(target);
				assert.ok(slugCache[target][anchor], where + ' (no heading with that anchor)');
			});
		});
	});

	it('links every category with its file name, never a bare anchor', function () {
		[INDEX].concat(files).forEach(file => {
			linksIn(file).forEach(link => {
				assert.ok(!/^#attack-category-/.test(link.target),
					path.relative(DOCS, file) + ':' + link.line + ' uses a bare anchor ' + link.target);
			});
		});
	});
});
```

- [ ] **Step 2: Run it and confirm it fails on the current layout**

Run: `npx mocha test/docs-catalog.js`
Expected: the first test fails with `ENOENT` on `docs/attacks` (the directory does not exist yet). That is the red state for this task.

- [ ] **Step 3: Lint**

Run: `npx eslint test/docs-catalog.js`
Expected: no output.

- [ ] **Step 4: Do not commit yet**

The test lands with the split in Task 2 so the suite is never red on `main`.

---

### Task 2: Mechanical split and baseline commit

**Files:**
- Create: `<scratchpad>/split-attacks.js`, `<scratchpad>/verify-split.js` (not committed)
- Create: `docs/attacks/*.md` (eight files)
- Rewrite: `docs/ATTACKS.md`
- Commit together with `test/docs-catalog.js` from Task 1

**Interfaces:**
- Consumes: `docs/ATTACKS.md` at HEAD, the FAMILIES table, `slug()`.
- Produces: the layout in File Structure; every entry begins `## Attack Category N: <title>`, blank, `**Advisories**: ...`, blank, `**Tests**: ...`, blank, then the original body. Tasks 3–11 rely on those two lines and on the `Categories in this file:` line in each family preamble.

- [ ] **Step 1: Write the split script**

Save as `<scratchpad>/split-attacks.js`:

```js
'use strict';

// One-off: splits docs/ATTACKS.md into docs/attacks/<family>.md + an index.
// Moves text; generates metadata from data already in the file; edits no prose.
// Usage: node split-attacks.js /Users/patriksimek/Projects/vm2

const fs = require('fs');
const path = require('path');

const ROOT = process.argv[2];
if (!ROOT) throw new Error('usage: node split-attacks.js <repo-root>');
const SRC_PATH = path.join(ROOT, 'docs', 'ATTACKS.md');
const OUT_DIR = path.join(ROOT, 'docs', 'attacks');
const GHSA_DIR = path.join(ROOT, 'test', 'ghsa');

const GHSA_RE = /GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}/g;
const CATEGORY_RE = /^## Attack Category (\d+): (.+)$/;
const EXPECTED_COUNT = 52;

const FAMILIES = [ /* paste the FAMILIES table from the plan verbatim */ ];

function slug(heading) {
	return heading.toLowerCase().replace(/[^\w\- ]/g, '').replace(/ /g, '-');
}

function kindOf(n) {
	return n <= 5 ? 'primitive' : n <= 15 ? 'technique' : 'compound';
}

function trimEdges(arr) {
	const a = arr.slice();
	while (a.length && a[0].trim() === '') a.shift();
	while (a.length && (a[a.length - 1].trim() === '' || a[a.length - 1].trim() === '---')) a.pop();
	return a;
}

function unique(list) {
	return list.filter((x, i) => list.indexOf(x) === i);
}

// ---------------------------------------------------------------- parse

const lines = fs.readFileSync(SRC_PATH, 'utf8').split('\n');

const headings = [];
lines.forEach((line, i) => {
	if (/^#{1,2} /.test(line)) headings.push({line: i, text: line});
});

function bodyAfter(headingLine) {
	const idx = headings.findIndex(h => h.line === headingLine);
	const end = idx + 1 < headings.length ? headings[idx + 1].line : lines.length;
	return trimEdges(lines.slice(headingLine + 1, end));
}

function namedSection(text) {
	const h = headings.find(x => x.text === text);
	if (!h) throw new Error('section not found: ' + text);
	return bodyAfter(h.line);
}

const categories = new Map();
headings.forEach(h => {
	const m = CATEGORY_RE.exec(h.text);
	if (!m) return;
	const n = Number(m[1]);
	if (categories.has(n)) throw new Error('duplicate category ' + n);
	if (m[2].indexOf('|') !== -1) throw new Error('category ' + n + ' title contains |');
	categories.set(n, {
		n: n,
		title: m[2],
		heading: h.text,
		slug: slug(h.text.replace(/^## /, '')),
		body: bodyAfter(h.line),
	});
});
if (categories.size !== EXPECTED_COUNT) throw new Error('expected ' + EXPECTED_COUNT + ' categories, found ' + categories.size);

const fileOf = new Map();
const familyOf = new Map();
FAMILIES.forEach(f => f.categories.forEach(n => {
	if (!categories.has(n)) throw new Error('family ' + f.file + ' lists unknown category ' + n);
	if (fileOf.has(n)) throw new Error('category ' + n + ' assigned twice');
	fileOf.set(n, f.file);
	familyOf.set(n, f);
}));
categories.forEach(c => {
	if (!fileOf.has(c.n)) throw new Error('category ' + c.n + ' has no family');
});

const titleBlock = trimEdges(lines.slice(0, headings[1].line)); // "# Sandbox Escape Attack Patterns" + intro
const howToUse = namedSection('## How to Use This Document');
const invariants = namedSection('## Defense Invariants');
const fundamentals = namedSection('## Fundamentals');
const runtime = namedSection('## Runtime-Dependent Attack Surface: Sandbox `Proxy` Availability');
const considered = namedSection('## Considered Attack Surfaces');
const future = namedSection('## Future Risks');
const checklist = namedSection('## Security Checklist for Bridge Changes');
const summaryAll = namedSection('## Summary');

// Pull "### Key Security Invariant: ..." out of Summary; it moves to promise-async.md.
const KSI = '### Key Security Invariant: Promise Species Resolution Timing';
const ksiStart = summaryAll.indexOf(KSI);
if (ksiStart === -1) throw new Error('Key Security Invariant subsection not found');
let ksiEnd = ksiStart + 1;
while (ksiEnd < summaryAll.length && !/^### /.test(summaryAll[ksiEnd])) ksiEnd++;
const keySecurityInvariant = trimEdges(summaryAll.slice(ksiStart, ksiEnd));
const summary = trimEdges(summaryAll.slice(0, ksiStart).concat(summaryAll.slice(ksiEnd)));

// ---------------------------------------------------------------- links

// Dead anchors whose number is wrong (past renumbering) or whose text is
// garbled. Keyed by the anchor as it appears in the file today. See the
// table under "Shared definition: the slug function" in the plan.
const LINK_OVERRIDES = {
	'attack-category-10-array-species-self-return-via-constructor-manipulation': 18,
	'attack-category-20-cross-realm-symbol-extraction-via-host-object-prototype-walk': 8,
	'attack-category-47x8': 8,
	'attack-category-30-nodevm-process-wide-observability-builtins-host-data-info-leak': 35,
	'attack-category-32-nodevm-nesting--non-configuration-require-value': 25,
	'attack-category-36-buffalloclimit-bypass-via-arraybuffer--typedarray--webassemblymemory': 36,
};

const slugToCategory = new Map();
categories.forEach(c => slugToCategory.set(c.slug, c));

// Resolution order: exact slug; truncated prefix of the numbered category's
// slug; explicit override; otherwise fail. Never trust the number alone.
// Anchors are lowercased first: GitHub anchors are always lowercase, so a
// mixed-case anchor in the source is dead by construction.
function resolveCategoryAnchor(rawAnchor, context) {
	const anchor = rawAnchor.toLowerCase();
	if (slugToCategory.has(anchor)) return slugToCategory.get(anchor);
	const m = /^attack-category-(\d+)-/.exec(anchor);
	const byNumber = m ? categories.get(Number(m[1])) : null;
	if (byNumber && byNumber.slug.indexOf(anchor) === 0) {
		console.log('repaired truncated anchor #' + anchor + ' -> Category ' + byNumber.n + ' (' + context + ')');
		return byNumber;
	}
	if (Object.prototype.hasOwnProperty.call(LINK_OVERRIDES, anchor)) {
		const c = categories.get(LINK_OVERRIDES[anchor]);
		console.log('OVERRIDE #' + anchor + ' -> Category ' + c.n + ' (' + context + '); fix the link text in review');
		return c;
	}
	throw new Error('unresolvable category anchor #' + anchor + ' (' + context + ')');
}

// familyPrefix: path from the destination file to docs/attacks/ ('' inside a family file, 'attacks/' from the index)
// rootPrefix:   path from the destination file to ATTACKS.md ('' inside the index, '../ATTACKS.md' from a family file)
function rewriteLinks(text, familyPrefix, rootPrefix, context) {
	return text
		.replace(/\]\(#(attack-category-[a-z0-9-]*)\)/gi, (m, anchor) => {
			const c = resolveCategoryAnchor(anchor, context);
			return '](' + familyPrefix + fileOf.get(c.n) + '#' + c.slug + ')';
		})
		.replace(/\]\(#([a-z0-9-]+)\)/g, (m, anchor) => '](' + rootPrefix + '#' + anchor + ')');
}

// ---------------------------------------------------------------- metadata

// Duplicate advisories are recorded in CHANGELOG.md as
// "**GHSA-primary** (dup: **GHSA-a**, **GHSA-b**)". They have no test
// directory of their own; the primary's tests cover them.
const changelog = fs.readFileSync(path.join(ROOT, 'CHANGELOG.md'), 'utf8');
const dupOf = new Map();
const dupRe = /\*\*(GHSA-[a-z0-9-]{14})\*\*\s*\((?:dup|dups|duplicate|duplicates):\s*([^)]*)\)/g;
let dm;
while ((dm = dupRe.exec(changelog)) !== null) {
	(dm[2].match(GHSA_RE) || []).forEach(id => dupOf.set(id, dm[1]));
}

function advisoriesOf(c) {
	return unique(c.body.join('\n').match(GHSA_RE) || []);
}

function advisoriesLine(c) {
	const ids = advisoriesOf(c);
	if (!ids.length) return 'none';
	return ids.map(id => {
		if (dupOf.has(id)) return id + ' (dup of ' + dupOf.get(id) + ')';
		return fs.existsSync(path.join(GHSA_DIR, id)) ? id : id + ' (no test directory)';
	}).join(', ');
}

function testsLine(c) {
	const dirs = advisoriesOf(c)
		.filter(id => fs.existsSync(path.join(GHSA_DIR, id)))
		.map(id => 'test/ghsa/' + id + '/');
	return dirs.length ? dirs.join(', ') : 'none linked';
}

// ---------------------------------------------------------------- family files

fs.mkdirSync(OUT_DIR, {recursive: true});

FAMILIES.forEach(f => {
	const out = [];
	out.push('# ' + f.title, '');
	out.push(f.scope, '');
	if (f.invariants.length) {
		out.push('Defense invariants enforced by fixes in this family: ' + f.invariants.join(', ') +
			' (see [Defense Invariants](../ATTACKS.md#defense-invariants)).', '');
	}
	out.push('Categories in this file: ' + f.categories.map(n =>
		'[' + n + '](' + f.file + '#' + categories.get(n).slug + ')').join(', ') + '.', '');
	if (f.file === 'promise-async.md') {
		out.push('---', '');
		out.push.apply(out, keySecurityInvariant);
		out.push('');
	}
	f.categories.forEach(n => {
		const c = categories.get(n);
		out.push('---', '');
		out.push(c.heading, '');
		out.push('**Advisories**: ' + advisoriesLine(c), '');
		out.push('**Tests**: ' + testsLine(c), '');
		out.push.apply(out, c.body);
		out.push('');
	});
	const text = rewriteLinks(out.join('\n'), '', '../ATTACKS.md', f.file);
	fs.writeFileSync(path.join(OUT_DIR, f.file), text.replace(/\n*$/, '\n'));
});

// ---------------------------------------------------------------- index

const ENTRY_FORMAT = [
	'## Category Entry Format',
	'',
	'Every category lives in exactly one family file under `docs/attacks/`. Category numbers are permanent identifiers: they are never reused, reassigned, or renumbered, because `CHANGELOG.md`, `test/ghsa/*/repro.js` and the skills refer to "Category N".',
	'',
	'Each entry uses the following structure:',
	'',
	'- **Heading**: `## Attack Category N: <Short title>`. N is the next unused number across all families.',
	'- **`**Advisories**:`** — required. Every GHSA ID the entry covers. Mark duplicates as `GHSA-xxxx (dup of GHSA-yyyy)`. Write `none` for categories that predate the advisory process.',
	'- **`**Tests**:`** — required. Paths to the regression tests: `test/ghsa/<id>/` directories, and suite tests cited as `test/vm.js ("<describe title>")`.',
	'- **`**Uses**:`** — required for techniques and compounds, absent for primitives. Linked list of prerequisite categories this attack composes.',
	'- **`**Supersedes**:`** — optional. Link to an earlier category whose mitigation was specific rather than structural and is now subsumed by this fix.',
	'- **`### Description`** — What the attacker can do and the underlying mechanism.',
	'- **`### Attack Flow`** — Numbered step-by-step breakdown.',
	'- **`### Canonical Example(s)`** — Code blocks. Include all known variants when multiple bypass paths exist.',
	'- **`### Why It Works`** — Why the existing defenses didn\'t prevent this. Reference V8 internals where relevant.',
	'- **`### Mitigation`** — The structural fix. Cite the file and function. Reference the [Defense Invariant](#defense-invariants) the fix enforces.',
	'- **`### Detection Rules`** — Bulleted heuristics for spotting similar patterns in code review.',
	'- **`### Considered Attack Surfaces`** — Optional. Adjacent surfaces analysed and ruled out, so future reviewers don\'t re-investigate.',
	'- **`### Known Residual`** — Optional. Must name the condition under which the residual becomes a bug, and once a later category closes it, a one-line pointer to that category replaces the section.',
	'',
	'Write in the present tense. An entry describes a closed hole and the structure that keeps it closed; the fix is the Mitigation section, so "NOW FIXED", "historically" and "was dangerous" do not appear.',
	'',
	'Links between categories always carry the file name (`family.md#anchor` from a family file, `attacks/family.md#anchor` from this index), and links to this document from a family file use `../ATTACKS.md#anchor`. `test/docs-catalog.js` fails the suite on a duplicate number, a gap in numbering, an unresolved link, or a missing metadata line.',
	'',
	'If a new vulnerability fits an existing category, add it as an additional canonical example, extend the Advisories and Tests lines, and update the Mitigation. Only create a new category for genuinely novel attack classes.',
	'',
	'After adding an entry:',
	'',
	'1. Place it in the family file whose mechanism matches. If none fits, add a family file and a row to the family table below; that should be rare.',
	'2. Add its row to the category index below.',
	'3. Add a row to **Summary → How The Bridge Defends** and, for a compound, an entry to **Summary → Compound Attack Patterns**.',
	'4. Run `npm test`; `test/docs-catalog.js` checks numbering, links, and metadata.',
	'5. Add a one-line entry to `CHANGELOG.md` under the next release.',
];

const familyTable = [
	'### Families',
	'',
	'| Family | Mechanism | Categories | Invariants |',
	'|---|---|---|---|',
].concat(FAMILIES.map(f =>
	'| [' + f.title + '](attacks/' + f.file + ') | ' + f.mechanism + ' | ' +
	f.categories.join(', ') + ' | ' + (f.invariants.length ? f.invariants.join(', ') : 'none yet') + ' |'
));

const categoryTable = [
	'### Categories',
	'',
	'`Kind` is `primitive` (no prerequisites), `technique` (a delivery mechanism for primitives), or `compound` (a complete chain closed by an advisory fix).',
	'',
	'| # | Category | Family | Kind | Advisories |',
	'|---|---|---|---|---|',
];
Array.from(categories.keys()).sort((a, b) => a - b).forEach(n => {
	const c = categories.get(n);
	const f = familyOf.get(n);
	categoryTable.push('| ' + n + ' | [' + c.title + '](attacks/' + f.file + '#' + c.slug + ') | [' +
		f.title + '](attacks/' + f.file + ') | ' + kindOf(n) + ' | ' + advisoriesLine(c) + ' |');
});

const index = [].concat(
	titleBlock, [''],
	['## How to Use This Document', ''], howToUse, ['', '---', ''],
	['## Category Index', ''], familyTable, [''], categoryTable, ['', '---', ''],
	ENTRY_FORMAT, ['', '---', ''],
	['## Fundamentals', ''], fundamentals, ['', '---', ''],
	['## Defense Invariants', ''], invariants, ['', '---', ''],
	['## Summary', ''], summary, ['', '---', ''],
	['## Security Checklist for Bridge Changes', ''], checklist, ['', '---', ''],
	['## Runtime-Dependent Attack Surface: Sandbox `Proxy` Availability', ''], runtime, ['', '---', ''],
	['## Considered Attack Surfaces', ''], considered, ['', '---', ''],
	['## Future Risks', ''], future, ['']
);
fs.writeFileSync(SRC_PATH, rewriteLinks(index.join('\n'), 'attacks/', '', 'ATTACKS.md').replace(/\n*$/, '\n'));

console.log('wrote ' + FAMILIES.length + ' family files and the index');
```

Paste the FAMILIES table from the top of this plan into the marked spot before running.

- [ ] **Step 2: Write the verifier**

Save as `<scratchpad>/verify-split.js`:

```js
'use strict';

// Compares the split catalog with the single-file catalog at a git ref.
// Usage: node verify-split.js <repo-root> <baseline-ref> [--no-body]
//   --no-body skips the per-category body-equality check (use after reviews).

const fs = require('fs');
const path = require('path');
const {execFileSync} = require('child_process');

const ROOT = process.argv[2];
const REF = process.argv[3];
const CHECK_BODY = process.argv.indexOf('--no-body') === -1;
if (!ROOT || !REF) throw new Error('usage: node verify-split.js <repo-root> <ref> [--no-body]');

const GHSA_RE = /GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}/g;
const CATEGORY_RE = /^## Attack Category (\d+): (.+)$/;

function categoriesOf(lines) {
	const map = new Map();
	for (let i = 0; i < lines.length; i++) {
		const m = CATEGORY_RE.exec(lines[i]);
		if (!m) continue;
		let j = i + 1;
		while (j < lines.length && !/^#{1,2} /.test(lines[j])) j++;
		map.set(Number(m[1]), {heading: lines[i], body: lines.slice(i + 1, j)});
	}
	return map;
}

// Link targets differ by design; generated metadata lines exist only in the new files.
function normalize(body) {
	return body
		.filter(l => !/^\*\*(Advisories|Tests)\*\*:/.test(l))
		.join('\n')
		.replace(/\]\([^)]*\)/g, ']()')
		.replace(/(?:\s*\n---)+\s*$/, '')
		.replace(/\s+$/g, '')
		.replace(/^\s+/g, '');
}

const baseline = execFileSync('git', ['show', REF + ':docs/ATTACKS.md'], {cwd: ROOT, encoding: 'utf8'}).split('\n');
const familyDir = path.join(ROOT, 'docs', 'attacks');
const newFiles = fs.readdirSync(familyDir).filter(f => /\.md$/.test(f)).map(f => path.join(familyDir, f));
newFiles.push(path.join(ROOT, 'docs', 'ATTACKS.md'));
const newText = newFiles.map(f => fs.readFileSync(f, 'utf8')).join('\n');
const newLines = newText.split('\n');

const oldCats = categoriesOf(baseline);
const newCats = categoriesOf(newLines);
const problems = [];

if (oldCats.size !== newCats.size) problems.push('category count ' + oldCats.size + ' -> ' + newCats.size);
oldCats.forEach((oc, n) => {
	const nc = newCats.get(n);
	if (!nc) { problems.push('category ' + n + ' missing'); return; }
	if (nc.heading !== oc.heading) problems.push('category ' + n + ' heading changed');
	if (CHECK_BODY && normalize(nc.body) !== normalize(oc.body)) problems.push('category ' + n + ' body differs');
});

const oldGhsa = new Set(baseline.join('\n').match(GHSA_RE) || []);
const newGhsa = new Set(newText.match(GHSA_RE) || []);
oldGhsa.forEach(id => { if (!newGhsa.has(id)) problems.push('GHSA lost: ' + id); });

const fences = text => text.split('\n').filter(l => /^\s*```/.test(l)).length;
if (fences(newText) < fences(baseline.join('\n'))) problems.push('code fences dropped: ' + fences(baseline.join('\n')) + ' -> ' + fences(newText));

if (problems.length) {
	console.error(problems.join('\n'));
	process.exit(1);
}
console.log('ok: ' + newCats.size + ' categories, ' + newGhsa.size + ' advisories, ' + fences(newText) + ' fence lines');
```

- [ ] **Step 3: Run the split**

Run:
```bash
cd /Users/patriksimek/Projects/vm2 && git status --porcelain
```
Expected: exactly three untracked paths and nothing modified: `test/docs-catalog.js` (Task 1), `docs/specs/2026-09-02-attacks-catalog-restructure-design.md`, and `docs/plans/2026-09-02-attacks-catalog-restructure.md`. If anything else is dirty, stop and ask.

Run:
```bash
node "<scratchpad>/split-attacks.js" /Users/patriksimek/Projects/vm2
```
Expected: one `repaired truncated anchor` line (Category 21), seven `OVERRIDE` lines (the six anchors in `LINK_OVERRIDES`; the Category 8 one appears twice, once in `host-reference-primitives.md` and once in `host-prototype-mutation.md`), then `wrote 8 family files and the index`. Any thrown error means a category is unmapped or an anchor resolves to nothing; fix the FAMILIES table or add the anchor to `LINK_OVERRIDES` only after reading its source line and confirming the intended target. Do not hand-edit the output.

- [ ] **Step 4: Verify the move is pure**

Run:
```bash
node "<scratchpad>/verify-split.js" /Users/patriksimek/Projects/vm2 HEAD
```
Expected: `ok: 52 categories, 61 advisories, <N> fence lines`. Any `body differs` line means the parser cut a block wrongly; inspect that category in both files before touching the script.

- [ ] **Step 5: Run the docs test and the lint**

Run: `npx mocha test/docs-catalog.js`
Expected: 8 passing. The only advisories without a `test/ghsa/` directory are two recorded duplicates (GHSA-59g5-pmg6-5gr4, GHSA-m3pp-qgq7-gwm6), which the script marks `(dup of ...)` from `CHANGELOG.md`. If the "cites only advisories that have a test directory" test fails, an ID with no test and no dup record exists; that is a real coverage gap and blocks the baseline until the user decides.

Run: `npm run lint`
Expected: clean.

- [ ] **Step 6: Eyeball three files**

Open `docs/ATTACKS.md`, `docs/attacks/promise-async.md`, and `docs/attacks/transformer-and-modules.md`. Confirm: the index has the two tables and no category bodies; the Promise file starts with the scope paragraph, the invariants line, the categories line, then the Key Security Invariant note, then Category 7; the transformer file has exactly two categories. Confirm `git diff -M --stat HEAD -- docs` shows `docs/ATTACKS.md` shrinking to roughly 600 lines.

- [ ] **Step 7: Commit the baseline**

```bash
git add docs/ATTACKS.md docs/attacks test/docs-catalog.js docs/specs/2026-09-02-attacks-catalog-restructure-design.md docs/plans/2026-09-02-attacks-catalog-restructure.md
git commit -m "docs: split ATTACKS.md into per-family files (pure move)

Eight mechanism-family files under docs/attacks/, ATTACKS.md becomes the
index plus common material. Category headings and numbers are unchanged;
links are rewritten to carry file names; Advisories and Tests lines are
generated from the GHSA IDs already present in each entry. No prose was
edited. test/docs-catalog.js guards numbering, links and metadata.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01QtbYDJQFjzpbFa6aVYaqqR"
```

Record the commit hash; Tasks 11 and 13 pass it to the verifier as the baseline.

---

## Family Review Procedure

Tasks 3 through 10 each apply this procedure to one family file. The task text names the file, its categories, and the stale items already known. Each of these tasks may run in parallel with the others because they touch disjoint files. The implementer prompt for these tasks must contain this whole section plus the task's own block.

**You may edit:** the one family file named in your task, and your report file at `<scratchpad>/reports/<family>.md`. **You may not edit:** `docs/ATTACKS.md`, any other family file, anything under `lib/` or `test/`, or `CHANGELOG.md`. You may create throwaway PoC harness files under `<scratchpad>/poc/`.

**You may not:** renumber, merge, split or delete a category; delete a code block; change a `### Mitigation` claim without running code that supports the change; add prose beyond what the checklist requires; change a `## Attack Category N:` heading line.

For every category in your file, in number order:

1. **Mitigation cites live code.** List every function, method, constant, option and file named in `### Mitigation`. For each, run `grep -rn "<name>" lib/`. A name with zero hits is a finding. If the defense clearly moved and you can point at the new name with a grep hit and a matching comment, correct the sentence and log the edit. If you cannot, leave the text and log it under "Findings needing a human".

2. **Advisories have tests.** For every GHSA ID on the `**Advisories**:` line, `ls test/ghsa/<id>` must succeed. If it fails, `grep -n "<id>" CHANGELOG.md`; a `(dup: ...)` mention means it is a duplicate: rewrite the ID as `GHSA-xxxx (dup of GHSA-yyyy)` on the Advisories line and drop the `(no test directory)` marker. Otherwise log a coverage gap and leave the marker in place.

3. **Tests line is complete.** Replace `none linked` or extend the list. Sources, in order:
   - `test/ghsa/<id>/` for each advisory. Read each `repro.js`, `adversarial.js`, `structural-leak*.js` in those directories.
   - `grep -n "describe(\|it(\|it.cond(" test/vm.js test/nodevm.js` and search the titles for the category's mechanism (constructor chain, `Symbol.species`, `prepareStackTrace`, `require.root`, and so on). Cite as `test/vm.js ("<exact describe or it title>")`.
   - Where a test file holds a variant the entry does not mention, add one line under `### Canonical Example(s)` of the form `- <one-sentence variant>: see test/ghsa/<id>/<file>.js`. Do not copy the test body.

4. **Canonical examples are blocked.** For every fenced code block that is a PoC (as opposed to a mitigation snippet or a diagram): either name the test that asserts it is blocked, or run it. To run it, write `<scratchpad>/poc/cat-<N>-<k>.js`:

   ```js
   'use strict';
   const {VM, NodeVM} = require('/Users/patriksimek/Projects/vm2');
   // Use the constructor and options the entry's text specifies. Default: new VM({timeout: 2000}).
   const vm = new VM({timeout: 2000});
   const code = `
   /* paste the PoC here; replace any execSync/child_process payload with: return typeof process === 'undefined' ? 'no-process' : process.pid */
   `;
   try {
   	const r = vm.run(code);
   	console.log('returned:', r === process.pid ? 'HOST PID (ESCAPE)' : String(r));
   } catch (e) {
   	console.log('threw:', e && e.constructor && e.constructor.name, '-', e && e.message);
   }
   ```

   Run with `node <that file>`. "Blocked" means: it threw a `VMError`, `TypeError`, `ReferenceError` or `RangeError` originating in vm2 or the sandbox, or it returned a sandbox value. "HOST PID (ESCAPE)", a host `process` object, host `require`, or a host-realm error with a host stack path means not blocked: stop the review of that file immediately and log it under a top-level `### NOT BLOCKED` heading in your report with the exact PoC file path. For DoS entries (22, 23, 36, 41, 42) "blocked" means the documented limit or throw fires; keep `bufferAllocLimit`-style options exactly as the entry states them and use sizes a laptop survives.

   A PoC that needs a Node version other than the current one (check `node -v`; use `nvm ls` if it exists, else you have only the current version) is logged under "Unverified" with the version it needs. Do not mark it passed.

5. **Residuals are still residual.** For every `### Known Residual`, `### Residual Risk`, `### Accepted Residual` section: re-run its scenario the same way as step 4. If it is still open, add a line `Re-verified <YYYY-MM-DD> on Node <version>.` at the end of the section. If a later category closed it (`grep -n "Category <N>" docs/attacks/*.md` to find claimants), replace the section body with one line: `Closed by [Category M](<file>#<anchor>).` and log the edit.

6. **Tense and markers.** `grep -n "NOW FIXED\|historically\|Was Dangerous\|was dangerous\|previously\b" <your file>`. Rewrite each hit in present tense. A subsection titled "Why X Was Dangerous (NOW FIXED)" becomes "Why X Leaks" and keeps its body. Inline `(NOW FIXED)` markers are deleted. Content is preserved; only framing changes. Log each edit.

7. **Cross-references are intact.** For every `**Uses**:`, `**Supersedes**:`, `### Related Categories` line and every inline `[Category N](...)` link, confirm N is the category the sentence describes. `npx mocha test/docs-catalog.js` must pass after your edits; run it before writing your report.

8. **Version claims.** `grep -n "Node [0-9]\|Node >= \|since ~Node\|enabled by default on Node" <your file>`. Compare each against the CI matrix in `.github/workflows/test.yml` (Node 8 through 26) and `test/bun-skips.js`. If a claim is contradicted by a test gate you can point at (an `it.cond` condition or a skip entry), correct it and log the edit. Otherwise leave it and log it under "Unverified".

Write your report to `<scratchpad>/reports/<family>.md` in exactly this shape:

```
## <family file>

### Edits made
- Category N: <one line>

### Findings needing a human
- Category N: <what, evidence (grep output or PoC path), suggested action>

### Unverified
- Category N: <PoC or claim, why it could not be checked>

### Coverage gaps
- GHSA-xxxx-xxxx-xxxx: no test directory (Category N)

### PoCs run
- Category N, block k: <scratchpad>/poc/cat-N-k.js -> blocked (<how>)
```

Every section must be present even if its body is `- none`.

Final step for every family task: run `npx mocha test/docs-catalog.js` (expected: 8 passing) and `git diff --stat -- docs/attacks/<your file>` and put the stat line at the end of your report. Do not commit.

---

### Task 3: Review `host-reference-primitives.md`

**Files:**
- Modify: `docs/attacks/host-reference-primitives.md`
- Create: `<scratchpad>/reports/host-reference-primitives.md`

**Categories:** 1, 2, 3, 5, 8, 10, 15, 18.

**Known items to handle:**
- Categories 1, 2, 3, 5, 10, 15 predate the advisory process and carry `**Advisories**: none` and `**Tests**: none linked`. The Tests line must be filled from `test/vm.js`: the suites there are the regression tests for these primitives. Search titles for `constructor`, `__proto__`, `Symbol`, `caller`, `getOwnPropertyDescriptor`, `Buffer`, `Reflect`.
- Category 8 references `Symbol.for('nodejs.util.inspect.custom')`; confirm the filter function it names still exists in `lib/bridge.js` or `lib/setup-sandbox.js`.
- Category 18 is "Supersedes"-referenced by Category 28 in `bridge-internals.md`. Confirm the link target in your file was rewritten to `bridge-internals.md#...` and resolves.
- Two links in this file had wrong numbers before the split and were retargeted by the script; the visible text is still wrong. In Category 3's Description, "See also [Category 10: Array Species Self-Return](...)" must read "Category 18: Array Species Self-Return" (the target already points at Category 18 in this file). In Category 8's Mitigation, "[Category 8 / Category 20](...)" must read "[Category 8](...)"; the link points at Category 8 itself.

- [ ] **Step 1:** Apply the Family Review Procedure to each category in order.
- [ ] **Step 2:** Run `npx mocha test/docs-catalog.js`. Expected: 8 passing.
- [ ] **Step 3:** Write the report. Do not commit.

---

### Task 4: Review `error-sanitization.md`

**Files:**
- Modify: `docs/attacks/error-sanitization.md`
- Create: `<scratchpad>/reports/error-sanitization.md`

**Categories:** 4, 16, 17, 38, 39, 48, 49.

**Known items to handle:**
- Category 4 predates advisories: fill its Tests line from `test/vm.js` (search `prepareStackTrace`, `error.name`, `Symbol`, `stack`).
- Categories 39 and 48 have a `### Fix shape` section and 48 has `### Delivery paths (why one chokepoint is insufficient)`. These are not in the entry format. Leave the headings; they are content, and the format change is out of scope. Log under "Findings needing a human" that the format lists no such section.
- Category 38's canonical examples span roughly 130 lines with several variants; each variant needs a test citation or a run.
- Category 17 says `WebAssembly.JSTag` is "available since ~Node 23". Check the `it.cond` gate in the matching `test/ghsa/` directory and correct the version if the gate says otherwise.

- [ ] **Step 1:** Apply the Family Review Procedure to each category in order.
- [ ] **Step 2:** Run `npx mocha test/docs-catalog.js`. Expected: 8 passing.
- [ ] **Step 3:** Write the report. Do not commit.

---

### Task 5: Review `promise-async.md`

**Files:**
- Modify: `docs/attacks/promise-async.md`
- Create: `<scratchpad>/reports/promise-async.md`

**Categories:** 7, 19, 29, 31, 33, 43, 51.

**Known items to handle:**
- The file preamble contains the "Key Security Invariant: Promise Species Resolution Timing" note moved from the Summary. Check that every function it names (`resetPromiseSpecies` and the others) exists in `lib/` the same way as a Mitigation section.
- Category 7 predates advisories: fill its Tests line from `test/vm.js` (search `Promise`, `then`, `species`, `async`).
- Category 33 cites GHSA-m3pp-qgq7-gwm6, which has no test directory. `CHANGELOG.md` records it as a duplicate of GHSA-wjwh-qqvp-g4p4 and the split script should have written `GHSA-m3pp-qgq7-gwm6 (dup of GHSA-wjwh-qqvp-g4p4)` on the Advisories line. Confirm; if the marker is missing, add it.
- Category 33 has `**Supersedes**: None directly. Strengthens ...`. Keep it; it is informative. Do not convert it to a link.
- Category 33 (JSPI) and 51 (`allowAsync: false`) PoCs may need flags or Node versions; log what you cannot run under "Unverified" with the exact requirement.
- Category 31 says "extends Category 22"; 22 now lives in `host-resources.md`. Confirm the link resolves there.

- [ ] **Step 1:** Apply the Family Review Procedure to each category in order.
- [ ] **Step 2:** Run `npx mocha test/docs-catalog.js`. Expected: 8 passing.
- [ ] **Step 3:** Write the report. Do not commit.

---

### Task 6: Review `host-prototype-mutation.md`

**Files:**
- Modify: `docs/attacks/host-prototype-mutation.md`
- Create: `<scratchpad>/reports/host-prototype-mutation.md`

**Categories:** 20, 26, 30, 32, 37, 50.

**Known items to handle:**
- Category 20 was "extended" by GHSA-3vgf-8m4q-q4qr (binary-data and iterator prototypes; see `CHANGELOG.md`). Confirm the entry's Mitigation names `globalsList` and `thisGlobalPrototypes` in `lib/bridge.js` and that the Advisories line carries both GHSA-3vgf-8m4q-q4qr and `GHSA-59g5-pmg6-5gr4 (dup of GHSA-3vgf-8m4q-q4qr)`; the split script writes the dup marker from `CHANGELOG.md`, so confirm it and add it only if missing.
- Category 26 has a `**Supersedes**` line that names a commit hash (`b57ac2d`). Confirm with `git log --oneline | grep b57ac2d` that it exists; if not, log a finding.
- Category 37 has a subsection "Follow-Up Bypass: Host-Side Laundering via `bind` + Host Higher-Order Method (GHSA-cfcw-xp6x-25gj, 2026-05-25)". It is a canonical example of the same category; the date stays, but check the Advisories line includes GHSA-cfcw-xp6x-25gj.
- Categories 30 and 37 both have "Related Categories" sections with cross-file links; verify each.
- Two links in this file were retargeted by the split script and need their visible text fixed. In Category 20's Mitigation, "[Category 47x8](...)" is a garbled reference to the GHSA-47x8-96vw-5wg6 fix: make it "[Category 8 (GHSA-47x8-96vw-5wg6)](...)"; the target already points at `host-reference-primitives.md` Category 8. In Category 32, "Interaction with [Category 8 / Category 20 / GHSA-m5q2-4fm3-vfqp](...)" becomes "Interaction with [Category 8 / GHSA-m5q2-4fm3-vfqp](...)".

- [ ] **Step 1:** Apply the Family Review Procedure to each category in order.
- [ ] **Step 2:** Run `npx mocha test/docs-catalog.js`. Expected: 8 passing.
- [ ] **Step 3:** Write the report. Do not commit.

---

### Task 7: Review `bridge-internals.md`

**Files:**
- Modify: `docs/attacks/bridge-internals.md`
- Create: `<scratchpad>/reports/bridge-internals.md`

**Categories:** 6, 9, 11, 14, 27, 28, 44.

**Known items to handle:**
- Category 9 has three subsections titled "Why fromOtherWithContext Was Dangerous (NOW FIXED)", "Why handler.get() Direct Call Was Dangerous (NOW FIXED)", "Why Handler Class Reconstruction Was Dangerous (NOW FIXED, GHSA-v37h-5mfm-c47c)" and inline `(NOW FIXED)` comments in its code blocks. Apply procedure step 6: retitle to "Why fromOtherWithContext Leaks", "Why handler.get() Direct Call Leaks", "Why Handler Class Reconstruction Leaks (GHSA-v37h-5mfm-c47c)"; delete the inline markers; keep every code block.
- Categories 6, 11, 14 predate advisories: fill Tests lines from `test/vm.js` (search `Proxy`, `apply`, `call`, `defineProperty`, `in operator`, `has`).
- Category 27 "Supersedes" GHSA-wp5r-2gw5-m7q7, which has its own test directory. Both IDs belong on the Advisories line.
- Category 28 has a `| Variant | Site | ... |` table inside the Description; the split must not have broken it (check the file renders the table, that is, the table lines are contiguous).
- Category 44 concerns `vm.freeze()`; the PoC needs a host object with an accessor property passed via `freeze`. Build that in the harness rather than skipping it.
- Note for the report: `docs/ATTACKS.md` has a "Runtime-Dependent Attack Surface: Sandbox `Proxy` Availability" section that says sandbox `Proxy` is `undefined` on Node 10 and later. Category 6's canonical examples construct proxies inside the sandbox. State in your findings whether those examples still run as written on the current Node, and what they demonstrate if `Proxy` is undefined.

- [ ] **Step 1:** Apply the Family Review Procedure to each category in order.
- [ ] **Step 2:** Run `npx mocha test/docs-catalog.js`. Expected: 8 passing.
- [ ] **Step 3:** Write the report. Do not commit.

---

### Task 8: Review `transformer-and-modules.md`

**Files:**
- Modify: `docs/attacks/transformer-and-modules.md`
- Create: `<scratchpad>/reports/transformer-and-modules.md`

**Categories:** 12, 13.

**Known items to handle:**
- Both predate advisories. Fill Tests lines from `test/vm.js` (search `transformer`, `catch`, `with`, `import`, `VM2_INTERNAL_STATE`) and from any `test/ghsa/` directory whose `repro.js` mentions `import(` or the transformer (`grep -ln "import(\|transformer" test/ghsa/*/*.js`).
- Category 12 is the base for 16, 17 and 27 (they list it under `**Uses**`). Its Detection Rules should still describe the `ecmaVersion: 2022` blind spot; confirm the number against `lib/transformer.js`.
- Category 13 says `import()` throws `VMError` unconditionally. Run it.

- [ ] **Step 1:** Apply the Family Review Procedure to each category in order.
- [ ] **Step 2:** Run `npx mocha test/docs-catalog.js`. Expected: 8 passing.
- [ ] **Step 3:** Write the report. Do not commit.

---

### Task 9: Review `nodevm-require.md`

**Files:**
- Modify: `docs/attacks/nodevm-require.md`
- Create: `<scratchpad>/reports/nodevm-require.md`

**Categories:** 21, 24, 25, 34, 35, 40, 45, 46, 47, 52.

**Known items to handle:**
- Categories 45 and 46 have `### Residual Risk`; 47 has `### Accepted Residual — require.external Without require.root (by design; warn-only until the next major)`. Apply procedure step 5 to all three. For 47, "accepted by design" still needs the re-verified line; do not remove it.
- Category 21 has a `**Supersedes**` line about GHSA-947f-4v7f-x2v8; that ID belongs on the Advisories line too.
- Category 24 (`require.root` symlink) PoCs need a temp directory with a symlink. Build it under `<scratchpad>/poc/` and clean up.
- Category 34 has a `### Supersedes` subsection (an H3, not the metadata line). Leave the heading; log the format mismatch as a finding.
- Category 47's title is a sentence of 20 words. Do not shorten it; the anchor is load-bearing.
- Category 40 lists `crypto.setEngine` and `node:sqlite` `loadExtension`; do not run those PoCs with a real shared library. Verify only that the documented guard throws before the native call (the entry's Mitigation names the mechanism), using a nonexistent path.
- Two links in this file were retargeted by the split script and need their visible text fixed. In Category 21's Considered Attack Surfaces, "see [Category 30](...)" must read "see [Category 35](...)"; the target already points at Category 35 in this file. In Category 47's "Closing the Nesting-Default Bypass" subsection, "the shipped [Category 32](...)" must read "the shipped [Category 25](...)"; the target already points at Category 25 in this file.

- [ ] **Step 1:** Apply the Family Review Procedure to each category in order.
- [ ] **Step 2:** Run `npx mocha test/docs-catalog.js`. Expected: 8 passing.
- [ ] **Step 3:** Write the report. Do not commit.

---

### Task 10: Review `host-resources.md`

**Files:**
- Modify: `docs/attacks/host-resources.md`
- Create: `<scratchpad>/reports/host-resources.md`

**Categories:** 22, 23, 36, 41, 42.

**Known items to handle:**
- Category 22 has `### Known Residual — async function / async generator / await using` and a `### Sibling — ignored host-promise rejection (host→sandbox direction) — GHSA-gjq8-xm47-88rc` subsection. Re-verify the residual per step 5. The sibling's GHSA belongs on the Advisories line.
- Category 23's `### Considered Attack Surfaces` has an inline "**Now capped** — see Category 36" note. Rewrite that bullet in present tense so it states the current fact and links to Category 36, per step 6.
- Category 23 also has `### Canonical Bypass Example (GHSA-gmc2-2x9w-cgh9)`; that ID belongs on the Advisories line.
- Category 36 has `### Known Residual` and a `### Tests` H3 (an older way of doing what the `**Tests**:` line now does). Move its content into the `**Tests**:` line and delete the H3; log the edit.
- Category 22's canonical PoC crashes the host process if the defense fails. Run it as a child process: `node -e` in a `try` with `execFileSync` from a wrapper, and treat a non-zero exit with `unhandledRejection` in stderr as NOT BLOCKED.
- Category 42 (`FinalizationRegistry`): the PoC depends on GC timing. Run it with `node --expose-gc` and call `gc()` as the entry's test does; log as unverified if the run is inconclusive rather than guessing.

- [ ] **Step 1:** Apply the Family Review Procedure to each category in order.
- [ ] **Step 2:** Run `npx mocha test/docs-catalog.js`. Expected: 8 passing.
- [ ] **Step 3:** Write the report. Do not commit.

---

### Task 11: Cross-cutting review and the review commit

**Files:**
- Modify: `docs/ATTACKS.md`
- Modify: any `docs/attacks/*.md` only where a family report's "Findings needing a human" was resolved by the maintainer's decision in this task
- Create: `docs/specs/2026-09-02-attacks-catalog-review-findings.md`
- Read: `<scratchpad>/reports/*.md` (eight files)

**Interfaces:**
- Consumes: the eight reports, the baseline commit hash from Task 2, `verify-split.js`.
- Produces: the review commit. Task 12 starts from it.

- [ ] **Step 1: Stop on escapes**

Run: `grep -l "### NOT BLOCKED" "<scratchpad>"/reports/*.md`
Expected: no output. If any file matches, stop this plan and report the PoC path to the user; an unblocked PoC is a security incident, not a docs task.

- [ ] **Step 2: Reconcile the index advisories with the entries**

Run: `npx mocha test/docs-catalog.js`
Expected: the "lists every category in the index table with matching advisories" test fails for every category whose Advisories line a reviewer changed (dup markers, added IDs). For each failing category, edit its row in the `### Categories` table of `docs/ATTACKS.md` so the Advisories cell is the entry's `**Advisories**:` value verbatim. Rerun until 8 passing.

- [ ] **Step 3: Update "How to Use This Document"**

In `docs/ATTACKS.md`, replace the paragraph after the numbered list that begins `When documenting a new advisory, follow the` with:

```
The catalog is split by mechanism family: this file is the index and the common material, and each family under `docs/attacks/` holds the numbered entries. Start from the [Category Index](#category-index) when you have a number, and from the family table when you have a mechanism. When documenting a new advisory, follow the [Category Entry Format](#category-entry-format) and verify the fix against the [Defense Invariants](#defense-invariants).
```

And change item 1 of the numbered list from `matches the patterns below` to `matches the patterns in the family files`.

- [ ] **Step 4: Remove "(NOW FIXED)" from the Compound Attack Patterns**

Run: `grep -n "NOW FIXED" docs/ATTACKS.md`
Expected: about 14 hits, all in `### Compound Attack Patterns`. Delete each ` (NOW FIXED)` token. Then `grep -c "NOW FIXED" docs/ATTACKS.md docs/attacks/*.md` must print 0 for every file.

- [ ] **Step 5: Correct the two appendix contradictions**

In `## Considered Attack Surfaces`, replace the `**Error.cause**` bullet with:

```
- **Error.cause on sandbox-created errors**: Set by sandbox code on sandbox-realm errors, so `ensureThis` handles it through normal property access on proxied errors. `Error.cause` on a *host* error carrying a live host reference is a different surface and is closed by [Category 38](attacks/error-sanitization.md#attack-category-38-errorcause-host-reference-leak-to-sandbox) and [Category 39](attacks/error-sanitization.md#attack-category-39-host-promise-rejection-sanitizer-bypass-via-callapply-indirection).
```

In `## Future Risks`, delete the `**WASM JSPI**` bullet and add at the end of the list:

```
- **Any primitive that returns a sandbox-realm object with a host-realm prototype**: WebAssembly JSPI and the streaming compile APIs were the first (see [Category 33](attacks/promise-async.md#attack-category-33-webassembly-jspi-cross-realm-promise-prototype)). Every new Node API that hands the sandbox a Promise or iterator must be checked for this shape at bootstrap.
```

Then read every remaining bullet in both appendices against the category titles in the index table. For each bullet that names a surface a category now covers, either delete it (if the category supersedes it) or add a "see Category N" link. Log what you changed in the findings document.

- [ ] **Step 6: Check the defense table and the compound patterns cover every category**

Run:
```bash
node -e "
const s = require('fs').readFileSync('docs/ATTACKS.md', 'utf8');
const summary = s.slice(s.indexOf('\n## Summary'), s.indexOf('\n## Security Checklist'));
for (let n = 1; n <= 52; n++) {
	if (!new RegExp('Categor(?:y|ies)[^\\\\n]*\\\\b' + n + '\\\\b').test(summary)) console.log('no summary mention of Category ' + n);
}"
```
Expected: mostly numbers 1 through 15, whose defense-table rows predate numbering and name the attack instead of the category. For each number printed: find the `### How The Bridge Defends` row that describes that entry's mechanism (compare against the entry's title and Mitigation) and append ` (Category N)` to its attack cell. If no row describes it, add one in the form `| <attack, one phrase> (Category N) | <defense, one sentence naming the function> |`, taken from the entry's Mitigation. A compound (16 and above) with no `### Compound Attack Patterns` line gets one, in the existing numbered style with the bracketed category list. Rerun until the command prints nothing.

- [ ] **Step 7: Apply the human decisions from the reports**

Read each report's "Findings needing a human". For each item, decide and act:
- A mitigation name that moved: fix the sentence in the family file and note it.
- A format mismatch (`### Fix shape`, `### Supersedes` as H3, and so on): leave the content, add the section name to the `## Category Entry Format` list only if it appears in two or more entries; otherwise leave it.
- A version claim the reviewer could not confirm: leave it, list it in the findings document.
- Anything else: list it in the findings document with the reviewer's evidence.

- [ ] **Step 8: Compile the findings document**

Create `docs/specs/2026-09-02-attacks-catalog-review-findings.md`:

```markdown
# Attack catalog review findings

Date: 2026-09-02
Baseline: <split commit hash>. Reviewed on Node <node -v>.
Scope: the staleness review from docs/specs/2026-09-02-attacks-catalog-restructure-design.md, section 6.

## Findings needing follow-up

<merge every report's "Findings needing a human" that Task 11 did not resolve, grouped by family file, keeping the reviewer's evidence>

## Unverified

<merge every report's "Unverified" list; each line names the Node version or flag needed>

## Coverage gaps

<merge every report's "Coverage gaps": advisories cited with no test directory>

## PoCs run

<merge every report's "PoCs run" list>

## Edits made

<merge every report's "Edits made" list plus Task 11 steps 3 to 7>
```

Every section is present. If a section is empty, write `None.`

- [ ] **Step 9: Verify against the baseline**

Run:
```bash
node "<scratchpad>/verify-split.js" /Users/patriksimek/Projects/vm2 <split commit hash> --no-body
npx mocha test/docs-catalog.js
npm run lint
```
Expected: `ok: 52 categories, 61 advisories, ...`, 8 passing, clean. A `GHSA lost` line means a reviewer deleted an ID; restore it from `git show <split commit hash>:docs/attacks/<file>`.

Run: `grep -rn "none linked" docs/attacks/`
Expected: no output. Any hit is a category whose reviewer did not fill the Tests line; fill it from that family's report or, if the report says no test exists, replace with `none (see docs/specs/2026-09-02-attacks-catalog-review-findings.md, Coverage gaps)`.

- [ ] **Step 10: Commit**

```bash
git add docs/ATTACKS.md docs/attacks docs/specs/2026-09-02-attacks-catalog-review-findings.md
git commit -m "docs: staleness review of the attack catalog

Every category checked against main: mitigation names grepped in lib/,
advisories matched to test/ghsa/, canonical PoCs matched to a test or run,
residual sections re-verified, retrospective framing rewritten in present
tense. Tests lines filled for every entry. Index, defense table, compound
patterns and the two appendices reconciled with the entries. Findings that
need follow-up are in docs/specs/2026-09-02-attacks-catalog-review-findings.md.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01QtbYDJQFjzpbFa6aVYaqqR"
```

---

### Task 12: Consumer updates

**Files:**
- Modify: `CLAUDE.md`
- Modify: `.claude/skills/fix-vulnerability/SKILL.md`
- Modify: `.claude/skills/hacker/SKILL.md`
- Modify: `.claude/skills/maintainer/SKILL.md`
- Modify: `.claude/skills/merge-fix/SKILL.md`
- Verify only: `README.md`, `test/ghsa/*/repro.js`

Line numbers below are from the tree at the start of this plan; locate by the quoted text, not the number.

- [ ] **Step 1: `CLAUDE.md`**

Replace the paragraph under `## Security` that begins `See [`docs/ATTACKS.md`](docs/ATTACKS.md) for the full catalog` with:

```
The attack catalog is [`docs/ATTACKS.md`](docs/ATTACKS.md) (category index, fundamentals, defense invariants, defense table, checklist) plus one file per mechanism family under [`docs/attacks/`](docs/attacks/). Every category has a permanent number; the index table resolves a number to its file.
```

In the `## Tests` list, replace the line
```
- `test/escape-scanner.js` -- Automated escape scanner. Serializable, runs inside `vm.run()`.
```
with
```
- `test/ghsa/<GHSA-id>/` -- One directory per advisory: `repro.js` holds the PoC asserted blocked, with `adversarial.js` and `structural-leak*.js` variants where they exist.
- `test/docs-catalog.js` -- Guards the attack catalog: unique sequential category numbers, resolvable links, required `Advisories` and `Tests` lines, index parity.
```

Replace the whole `## Updating ATTACKS.md` section with:

```
## Updating the attack catalog

**Every time the library is patched**, update the catalog following the [Category Entry Format](docs/ATTACKS.md#category-entry-format):

- Add the entry to the family file under `docs/attacks/` whose mechanism matches, with the next unused number across all families, or extend an existing category's canonical examples if the fix is a variant.
- Fill `**Advisories**:` and `**Tests**:`; document attack flow, canonical example, why it works, mitigation (naming the Defense Invariant it restores), detection rules.
- Add the row to the category index in `docs/ATTACKS.md`, the "How The Bridge Defends" table, and for compounds the "Compound Attack Patterns" list.
- Add new APIs or features to "Considered Attack Surfaces" or "Future Risks" in `docs/ATTACKS.md`.
- `npm test` runs `test/docs-catalog.js`, which fails on a renumbering, a dead link, or a missing metadata line.
```

- [ ] **Step 2: `.claude/skills/fix-vulnerability/SKILL.md`**

Edit A, in `### 1. Orient`, replace the sentence beginning `Re-read `CLAUDE.md` and `docs/ATTACKS.md` cover-to-cover.` through `you'll use later.` with:

```
Re-read `CLAUDE.md`, then `docs/ATTACKS.md` (the category index, the [Defense Invariants](../../../docs/ATTACKS.md#defense-invariants), and the [Category Entry Format](../../../docs/ATTACKS.md#category-entry-format) you'll use later), then every family file under `docs/attacks/` whose mechanism could match the advisory. CLAUDE.md has the file roles and architectural map.
```

Edit B, replace `Classify the vulnerability against ATTACKS.md's Tier 1 primitives (categories 1–5) and Tier 2 techniques (6–15).` with:

```
Classify the vulnerability against the catalog's primitives (entries with no `**Uses**` line, marked `primitive` in the category index of `docs/ATTACKS.md`) and techniques (marked `technique`).
```

Edit C, replace the line `ATTACKS.md: category <N> (<new | updated>)` in the summary template with `Catalog: category <N> (<new | updated>) in docs/attacks/<family>.md`.

Edit D, in `### 10. Document`, replace `Update `docs/ATTACKS.md` following the [Category Entry Format](../../../docs/ATTACKS.md#category-entry-format) at the top of the doc:` with `Update the attack catalog following the [Category Entry Format](../../../docs/ATTACKS.md#category-entry-format):`, and replace the first bullet `- New entry placed under the appropriate tier with the next sequential number, **or** added as a new canonical example to an existing category if the vulnerability is a variant.` with:

```
- New entry placed in the matching family file under `docs/attacks/` with the next unused number across all families, plus a row in the category index of `docs/ATTACKS.md`, **or** added as a new canonical example to an existing category if the vulnerability is a variant. Fill the `**Advisories**:` and `**Tests**:` lines.
```

Edit E, replace the checklist item `- [ ] **Is `docs/ATTACKS.md` updated?** New entry follows the format, references the relevant Invariant, cross-referenced.` with:

```
- [ ] **Is the attack catalog updated?** New entry in its family file with `**Advisories**` and `**Tests**` lines, a row in the `docs/ATTACKS.md` index, references the relevant Invariant, cross-referenced; `test/docs-catalog.js` passes.
```

Leave the remaining `ATTACKS.md` mentions (lines about "institutional memory", composition, and cross-referencing) as they are; they refer to the catalog as a whole and stay true.

- [ ] **Step 3: `.claude/skills/hacker/SKILL.md`**

Replace `1. Read `docs/ATTACKS.md` -- the full catalog of attack patterns, fundamentals, and defense table.` with:

```
1. Read `docs/ATTACKS.md` -- the category index, fundamentals, defense invariants, and defense table -- then every family file under `docs/attacks/`.
```

Replace the Phase 2 paragraph `Run through all attack categories from `docs/ATTACKS.md` against the modified code. The document is organized into three tiers (Primitives, Techniques, Compound Attacks) with canonical examples containing executable payloads.` with:

```
Run through all attack categories in `docs/attacks/*.md` against the modified code. The catalog is organized by mechanism family (host reference primitives, error sanitization, Promise and async, host prototype mutation, bridge internals, transformer and modules, NodeVM require, host resources); the index table in `docs/ATTACKS.md` marks each category as primitive, technique, or compound, and every entry has canonical examples containing executable payloads.
```

- [ ] **Step 4: `.claude/skills/maintainer/SKILL.md`**

Replace the table cell `Write fixes, tests, `ATTACKS.md` entries` with `Write fixes, tests, attack-catalog entries (`docs/attacks/`)`. Replace `testing across Node majors, `ATTACKS.md`, and the fork push` with `testing across Node majors, the attack catalog, and the fork push`. Replace `the context belongs in the code, the tests, and `ATTACKS.md`, not in the message` with `the context belongs in the code, the tests, and the attack catalog, not in the message`.

- [ ] **Step 5: `.claude/skills/merge-fix/SKILL.md`**

Edit A, replace `mirror the full ATTACKS.md write-up. That is redundant — ATTACKS.md and the per-advisory tests are the source of truth.` with `mirror the full attack-catalog write-up. That is redundant — the catalog (`docs/attacks/*.md`) and the per-advisory tests are the source of truth.`

Edit B, replace the heading `#### 5b. `docs/ATTACKS.md`` and its first paragraph through the three bullets with:

```
#### 5b. The attack catalog (`docs/ATTACKS.md` and `docs/attacks/`)

The fix-vulnerability skill assigns each new attack class the next unused category number across all family files. If two advisories both grew from the same base and both claimed the same number, you must renumber:

- The category that lands first keeps its number.
- The category landing now (this branch) takes the next free number on current `main` — i.e. `(max category number on main) + 1`.
- Update **all cross-references** to the renumbered category: `Category N` mentions and `#attack-category-N-` anchors in every `docs/attacks/*.md` and in `docs/ATTACKS.md`, its row in the category index, and its Compound Attack Patterns / How The Bridge Defends rows. `test/docs-catalog.js` fails on a duplicate number, a gap, or an unresolved anchor, so run `npm test` before considering the renumbering done.
```

Keep the following paragraph about merging Summary rows as it is.

Edit C, replace `- Renumbering in `ATTACKS.md` broke an anchor that a test asserts on.` with `- Renumbering in the attack catalog broke a link (`test/docs-catalog.js` fails) or an anchor that a test asserts on.`

Edit D, replace `Renumbered:    <none | ATTACKS.md Category N -> Category M>` with `Renumbered:    <none | Category N -> Category M in docs/attacks/<family>.md>`.

Leave `3. A pointer: `See ATTACKS.md Category N and test/ghsa/<GHSA-id>/`.` unchanged: the index resolves the number.

- [ ] **Step 6: Verify `README.md` and the repro comments need no change**

Run: `grep -n "ATTACKS" README.md test/ghsa/*/repro.js`
Expected: two README links to `docs/ATTACKS.md` (still the entry point) and four repro comments citing `Category N` (numbers unchanged). No edits.

- [ ] **Step 7: Check nothing still says "tier"**

Run: `grep -rn -i "tier" CLAUDE.md .claude/skills/*/SKILL.md docs/ATTACKS.md docs/attacks/`
Expected: hits only inside the prose of entries under `docs/attacks/` (for example a Description that says "Tier 1 primitive"); leave those. Any hit in `CLAUDE.md`, a skill, or `docs/ATTACKS.md` is a leftover. Rewrite: "Tier 1 primitives" becomes "primitives", "Tier 2 techniques" becomes "techniques", "Tier 3 compound attacks" becomes "compound attacks", "Tiers 1 and 2" becomes "the primitives and techniques", and a sentence that only exists to explain the tier system is deleted. The `Kind` column in the category index is the reference for the distinction.

- [ ] **Step 8: Lint and commit**

Run: `npm run lint`
Expected: clean.

```bash
git add CLAUDE.md .claude/skills/fix-vulnerability/SKILL.md .claude/skills/hacker/SKILL.md .claude/skills/maintainer/SKILL.md .claude/skills/merge-fix/SKILL.md
git commit -m "docs: point CLAUDE.md and the skills at the split attack catalog

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01QtbYDJQFjzpbFa6aVYaqqR"
```

---

### Task 13: Final verification

**Files:** none modified.

- [ ] **Step 1: Full suite on the current Node**

Run: `npm test 2>&1 | tail -15`
Expected: the summary line shows 0 failing. `docs catalog` shows 8 passing inside it.

- [ ] **Step 2: Node 8 compatibility of the docs test**

If `nvm ls` lists an 8.x, run `nvm exec 8 npx mocha test/docs-catalog.js` and expect 8 passing. If no Node 8 is available, run:

```bash
node -e "require('acorn').parse(require('fs').readFileSync('test/docs-catalog.js','utf8'),{ecmaVersion:2017})" && echo parses-as-es2017
```

Expected: `parses-as-es2017`. (`acorn` is a dependency of vm2.) If it throws, the test uses syntax newer than Node 8 supports; fix the syntax, not the CI matrix.

- [ ] **Step 3: Pure-move proof still holds for headings and advisories**

Run:
```bash
node "<scratchpad>/verify-split.js" /Users/patriksimek/Projects/vm2 <split commit hash>~1 --no-body
git diff -M --stat <split commit hash>~1 HEAD -- docs | tail -3
```
Expected: `ok: 52 categories, 61 advisories, ...`; the stat shows `docs/ATTACKS.md` and eight new files.

- [ ] **Step 4: Report**

Give the user: the three commit hashes, the count of edits, findings, unverified items and coverage gaps from the findings document, and the family files' line counts (`wc -l docs/attacks/*.md docs/ATTACKS.md`). Then stop; publishing or pushing is the user's call.
