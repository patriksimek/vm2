'use strict';

/**
 * GHSA-rp36-8xq3-r6c4 — NodeVM builtin denylist bypass via `process` and `inspector/promises`
 *
 * ## Vulnerability
 *
 * The DANGEROUS_BUILTINS denylist in `lib/builtin.js` blocks `inspector`,
 * `module`, `worker_threads`, `cluster`, `vm`, `repl`, `trace_events`, `wasi`.
 *
 * Two families are missed:
 *   - `process`              — exposes `process.getBuiltinModule(name)`, which
 *                              reloads ANY core module (including ones the
 *                              embedder explicitly excluded with `-name`),
 *                              plus `process.binding(...)`, `process.dlopen(...)`,
 *                              and the host `process.env`.
 *   - `inspector/promises`   — exact-match denylist on `inspector` does not
 *                              cover subpath builtins; `Session().post(
 *                              'Runtime.evaluate', { expression })` evaluates
 *                              attacker JS in the host realm.
 *
 * Both are reachable as soon as the embedder allows them — typically via
 * `builtin: ['*']` or an explicit allow-list that does not enumerate the
 * subpath variant.
 *
 * ## Fix
 *
 * 1. Add `process` to DANGEROUS_BUILTINS (host process module is never safe
 *    to expose; it carries `getBuiltinModule`, `binding`, `dlopen`, etc.).
 * 2. Treat the denylist as a *family* check: any key whose `<family>/...`
 *    prefix names a dangerous builtin is also blocked. This covers
 *    `inspector/promises`, future `inspector/*` subpaths, and any future
 *    subpaths under other dangerous families (`module/*`, `vm/*`, ...).
 * 3. Normalize the optional `node:` prefix before checking, so
 *    `require('node:process')` and `require('node:inspector/promises')`
 *    cannot bypass via the alternative spelling.
 */

const assert = require('assert');
const {NodeVM} = require('../../../');

describe('GHSA-rp36-8xq3-r6c4 — NodeVM builtin denylist bypass', () => {

	function makeVm() {
		return new NodeVM({
			require: {
				external: false,
				// The advisory's threat model: embedder allows the broad builtin
				// surface and tries to surgically subtract the obviously-dangerous
				// pieces.  The denylist must hold even under '*'.
				builtin: ['*']
			}
		});
	}

	function expectBlocked(vm, expr, label) {
		const result = vm.run(`
			try {
				const m = ${expr};
				module.exports = { ok: false, type: typeof m };
			} catch (e) {
				module.exports = { ok: true, message: e && e.message };
			}
		`);
		assert.strictEqual(result.ok, true,
			`${label}: expected require to be blocked, but got module of type ${result.type}`);
	}

	it('require("process") is blocked', () => {
		expectBlocked(makeVm(), "require('process')", "require('process')");
	});

	it('require("node:process") is blocked', () => {
		expectBlocked(makeVm(), "require('node:process')", "require('node:process')");
	});

	it('require("inspector/promises") is blocked', () => {
		expectBlocked(makeVm(), "require('inspector/promises')", "require('inspector/promises')");
	});

	it('require("node:inspector/promises") is blocked', () => {
		expectBlocked(makeVm(), "require('node:inspector/promises')", "require('node:inspector/promises')");
	});

	it('require("inspector") remains blocked (regression guard)', () => {
		expectBlocked(makeVm(), "require('inspector')", "require('inspector')");
	});

	it('process.getBuiltinModule bypass to child_process does not return a usable module', () => {
		const vm = new NodeVM({
			require: {
				external: false,
				builtin: ['*', '-child_process', '-inspector']
			}
		});
		const result = vm.run(`
			let processBlocked = false;
			let bypassReached = false;
			let execSyncReachable = false;
			try {
				const p = require('process');
				try {
					const cp = p.getBuiltinModule('child_process');
					bypassReached = true;
					execSyncReachable = typeof cp.execSync === 'function';
				} catch (e) {}
			} catch (e) {
				processBlocked = true;
			}
			module.exports = { processBlocked, bypassReached, execSyncReachable };
		`);
		assert.strictEqual(result.processBlocked, true,
			"require('process') must be blocked so the getBuiltinModule pivot cannot run");
		assert.strictEqual(result.bypassReached, false,
			"sandbox code must not reach process.getBuiltinModule()");
		assert.strictEqual(result.execSyncReachable, false,
			"sandbox code must not obtain a callable host child_process.execSync");
	});

	it('inspector/promises Session().post("Runtime.evaluate") is not reachable', () => {
		const vm = new NodeVM({
			require: {
				external: false,
				builtin: ['*', '-child_process', '-inspector']
			}
		});
		const result = vm.run(`
			let inspectorBlocked = false;
			let sessionType = null;
			try {
				const ip = require('inspector/promises');
				sessionType = typeof ip.Session;
			} catch (e) {
				inspectorBlocked = true;
			}
			module.exports = { inspectorBlocked, sessionType };
		`);
		assert.strictEqual(result.inspectorBlocked, true,
			"require('inspector/promises') must be blocked");
		assert.strictEqual(result.sessionType, null,
			"sandbox must not obtain inspector/promises Session");
	});

	it('explicit allow-list naming a dangerous builtin is rejected', () => {
		// makeBuiltins([...]) path: even if the embedder writes
		// builtin: ['process'] explicitly, the denylist must still hold.
		const vm = new NodeVM({
			require: {
				external: false,
				builtin: ['process', 'inspector/promises']
			}
		});
		expectBlocked(vm, "require('process')", "explicit process allowlist");
		expectBlocked(vm, "require('inspector/promises')", "explicit inspector/promises allowlist");
	});

	// `fs/promises` requires Node 14+, `stream/promises` is Node 15+. The
	// regression we're guarding against (family-prefix check shadowing sibling
	// subpath builtins) can only manifest on Node versions that actually expose
	// those subpaths, so this test is gated accordingly. NOTE: `dns/promises`
	// was a sibling example here originally, but it is now intentionally denied
	// as a host-process builtin (GHSA-m5w8-4gq2-6f8x), so the safe-sibling check
	// uses `fs/promises` and `stream/promises`.
	const NODE_MAJOR = parseInt(process.versions.node.split('.')[0], 10);
	if (typeof it.cond !== 'function') {
		it.cond = function (name, cond, fn) {
			return cond ? it(name, fn) : it.skip(name, fn);
		};
	}
	it.cond('safe builtins still load under "*"', NODE_MAJOR >= 15, () => {
		// Regression guard: the family-prefix check must not break sibling
		// builtins like fs/promises, stream/promises, etc.
		const vm = makeVm();
		const result = vm.run(`
			const fsp = require('fs/promises');
			const sp = require('stream/promises');
			module.exports = {
				fsp: typeof fsp.readFile,
				sp: typeof sp.pipeline
			};
		`);
		assert.strictEqual(result.fsp, 'function');
		assert.strictEqual(result.sp, 'function');
	});
});
