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

	it('cites only test paths that exist on the Tests lines', function () {
		const TEST_PATH_RE = /test\/[A-Za-z0-9_./-]+/g;
		all.forEach(c => {
			const tokens = c.meta.Tests.match(TEST_PATH_RE) || [];
			tokens.forEach(token => {
				const cleaned = token.charAt(token.length - 1) === '/' ? token.slice(0, -1) : token;
				assert.ok(fs.existsSync(path.join(__dirname, '..', cleaned)),
					'Category ' + c.number + ' cites test path ' + cleaned + ' which does not exist');
			});
		});
	});

	it('has no index row without an entry', function () {
		const lines = read(INDEX);
		const rows = {};
		lines.forEach(line => {
			const m = /^\|\s*(\d+)\s*\|(.*)\|\s*$/.exec(line);
			if (m) rows[Number(m[1])] = m[2];
		});
		Object.keys(rows).forEach(n => {
			assert.ok(byNumber[n], 'Index row ' + n + ' has no matching category entry');
		});
	});
});
