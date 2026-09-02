/**
 * GHSA-pq68-rvw4-xp4r — NodeVM host RCE: `child_process` reachable through the
 * default builtin loader.
 *
 * ## Vulnerability
 * `child_process` was not in `DANGEROUS_BUILTINS`, so it was admitted into the
 * builtins map both by the `builtin: ['*']` wildcard and by an explicit
 * `builtin: ['child_process']` (and `['*', '-fs']`, `['node:child_process']`).
 * The read-only wrap forwards every method to the host module, so sandbox code
 * runs `require('child_process').execSync('...')` / `spawn` / `fork` and
 * executes arbitrary host commands with full host authority — a complete
 * sandbox escape to host RCE, from a sandbox with no `fs`/`process` of its own.
 *
 * `child_process` is a process-spawning primitive of the same class as
 * `cluster` (`cluster.fork()`), `worker_threads` (`new Worker(..., {eval:true})`)
 * and `node:test` (`run({execArgv})`) — all already in `DANGEROUS_BUILTINS` with
 * the "spawns a host process" rationale. Its omission was the glaring gap.
 *
 * ## Fix
 * `lib/builtin.js`: add `child_process` to `DANGEROUS_BUILTINS`. It is now
 * excluded from `'*'` wildcard expansion, rejected on an explicit
 * `builtin: ['child_process']` request (`isDangerousBuiltin` gate in
 * `addDefaultBuiltin`), and absent from the builtins map so the resolver's
 * `node:` fast-path finds nothing to load; the family-prefix + `node:`
 * normalization in `isDangerousBuiltin` covers `node:child_process` and the
 * `node:node:child_process` double spelling. Embedders who genuinely need a
 * controlled child-process facade can still register a sandbox-safe wrapper
 * under the same name via `require.mock`.
 *
 * ## Sound oracle
 * The escape runs a host command that writes a marker file in the OS temp dir.
 * The tests assert (a) `require('child_process')` is denied inside the sandbox
 * for every spelling and every builtin config, and (b) no marker file appears —
 * unambiguous proof no host command ran.
 */

'use strict';

const assert = require('assert');
const os = require('os');
const fs = require('fs');
const path = require('path');
const { NodeVM } = require('../../../lib/main.js');

// Probe every spelling of child_process from inside the sandbox; returns a map
// spelling -> 'LOADED' | 'denied'.
const PROBE_SRC = `
	const out = {};
	for (const spec of ['child_process', 'node:child_process', 'node:node:child_process']) {
		try { require(spec); out[spec] = 'LOADED'; } catch (e) { out[spec] = 'denied'; }
	}
	module.exports = out;
`;

describe('GHSA-pq68-rvw4-xp4r (child_process reachable through the default builtin loader → host RCE)', function () {

	it('denies child_process (all spellings) under explicit builtin: ["child_process"]', function () {
		const res = new NodeVM({ require: { external: false, builtin: ['child_process'] } }).run(PROBE_SRC);
		assert.strictEqual(res['child_process'], 'denied', 'child_process exposed on explicit request');
		assert.strictEqual(res['node:child_process'], 'denied', 'node:child_process exposed on explicit request');
		assert.strictEqual(res['node:node:child_process'], 'denied', 'double-prefixed node:node:child_process exposed');
	});

	it('does not expose child_process under the wildcard builtin: ["*"]', function () {
		const res = new NodeVM({ require: { external: false, builtin: ['*'] } }).run(PROBE_SRC);
		assert.strictEqual(res['child_process'], 'denied', 'child_process reachable via wildcard builtin');
		assert.strictEqual(res['node:child_process'], 'denied', 'node:child_process reachable via wildcard builtin');
	});

	it('does not expose child_process under builtin: ["*", "-fs"] (reporter vector)', function () {
		const res = new NodeVM({ require: { external: false, builtin: ['*', '-fs'] } }).run(PROBE_SRC);
		assert.strictEqual(res['child_process'], 'denied', 'child_process reachable under ["*","-fs"]');
	});

	it('the execSync host-RCE PoC runs no host command', function () {
		const MARKER = path.join(os.tmpdir(), 'pq68-' + process.pid + '-' + Date.now() + '.txt');
		try { fs.unlinkSync(MARKER); } catch (e) {}
		const vm = new NodeVM({ require: { external: false, builtin: ['*'] } });
		let threw = false;
		try {
			vm.run(`require('child_process').execSync(${JSON.stringify('echo pwned > ' + MARKER)});`);
		} catch (e) { threw = true; /* require denied — the intended outcome */ }
		const markerExists = fs.existsSync(MARKER);
		try { fs.unlinkSync(MARKER); } catch (e) {}
		assert.strictEqual(markerExists, false, 'a host command ran — child_process reached the sandbox');
		assert.ok(threw, 'expected require("child_process") to be denied inside the sandbox');
	});

	// --- over-block controls: the fix must not break legitimate configurations ---

	it('does not over-block: a controlled child_process facade via require.mock is still reachable', function () {
		const vm = new NodeVM({ require: {
			external: false,
			builtin: ['child_process'],
			mock: { child_process: { execSync: function () { return 'from-mock'; } } }
		}});
		const res = vm.run(`module.exports = require('child_process').execSync('id').toString();`);
		assert.strictEqual(res, 'from-mock', 'embedder mock facade for child_process was not honored');
	});

	it('upgrade path: an embedder that truly needs it can re-expose the real module via require.mock', function () {
		// The documented migration for trusted-script embedders who relied on the
		// old default: deliberately mock the name with the genuine host module.
		// This forces `require('child_process')` into the embedder's OWN host code,
		// making the choice explicit and auditable rather than an implicit config flag.
		const vm = new NodeVM({ require: {
			external: false,
			mock: { child_process: require('child_process') }
		}});
		const res = vm.run(`module.exports = require('child_process').execSync('echo ok').toString().trim();`);
		assert.strictEqual(res, 'ok', 'require.mock upgrade path did not deliver a working child_process');
	});

	it('does not over-block: a benign builtin (events) is still reachable under builtin: ["*"]', function () {
		const res = new NodeVM({ require: { external: false, builtin: ['*'] } }).run(
			`module.exports = typeof require('events').EventEmitter;`);
		assert.strictEqual(res, 'function', 'a benign builtin regressed under the wildcard');
	});
});
