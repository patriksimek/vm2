/**
 * GHSA-qhwx-74w5-xhxq — NodeVM host RCE via `node:test`'s process-spawning
 * `run({ execArgv })`.
 *
 * ## Vulnerability
 * On Node 18+, `require('module').builtinModules` lists `node:test` (and
 * `node:test/reporters`) WITH the `node:` prefix, and `test` was not in
 * `DANGEROUS_BUILTINS`. So `builtin: ['node:test']` — and even `builtin: ['*']`
 * — admitted `node:test` into the builtins map and handed the sandbox the real
 * host module. `node:test`'s `run({ files, execArgv: ['--eval=<js>'] })` spawns
 * a SEPARATE host Node process that executes attacker JS with full host
 * authority (`require('fs').writeFileSync(...)`, `child_process`, …) — a host
 * RCE from a sandbox that has no `fs`/`child_process`/`process` of its own.
 * `require('node:node:test')` (double prefix) reached the same stored module.
 *
 * `node:test` is a process-spawning primitive of the same class as
 * `worker_threads` (`new Worker(..., {eval:true})`) and `cluster`
 * (`cluster.fork()`), which are already in `DANGEROUS_BUILTINS`.
 *
 * ## Fix
 * `lib/builtin.js`: add `test` to `DANGEROUS_BUILTINS` (family-matched, so
 * `node:test` and `node:test/reporters` are covered), and harden
 * `isDangerousBuiltin` to strip ALL leading `node:` prefixes so a double-
 * prefixed spelling normalizes correctly. `node:test` is now excluded from the
 * `'*'` wildcard, rejected on explicit `builtin: ['node:test']`, and absent from
 * the builtins map (so the resolver's `node:` fast-path finds nothing to load).
 * Embedders who genuinely need a test runner can register a safe wrapper via
 * `mock` / `override`.
 *
 * ## Sound oracle
 * The escape spawns a host process that writes a marker file in the OS temp dir.
 * The test asserts (a) `require` is denied inside the sandbox, and (b) no marker
 * file appears — unambiguous proof no host process ran.
 */

'use strict';

const assert = require('assert');
const os = require('os');
const fs = require('fs');
const path = require('path');
const { NodeVM } = require('../../../lib/main.js');

if (typeof it.cond !== 'function') {
	it.cond = function (name, cond, fn) {
		return cond ? it(name, fn) : it.skip(name, fn);
	};
}

const HAS_NODE_TEST = require('module').builtinModules.indexOf('node:test') !== -1;

describe('GHSA-qhwx-74w5-xhxq (node:test run({execArgv}) host RCE)', function () {
	it('denies require("node:test") / double-prefix / subpath under explicit builtin allow', function () {
		const vm = new NodeVM({ require: { external: false, builtin: ['node:test'] } });
		const res = vm.run(`
			const out = {};
			for (const spec of ['node:test', 'node:node:test', 'node:test/reporters', 'test']) {
				try { require(spec); out[spec] = 'LOADED'; } catch (e) { out[spec] = 'denied'; }
			}
			module.exports = out;
		`);
		assert.strictEqual(res['node:test'], 'denied', 'node:test was exposed to the sandbox');
		assert.strictEqual(res['node:node:test'], 'denied', 'double-prefixed node:node:test was exposed');
		assert.strictEqual(res['node:test/reporters'], 'denied', 'node:test/reporters was exposed');
		assert.strictEqual(res['test'], 'denied', 'bare test was exposed');
	});

	it('does not expose node:test under the wildcard builtin: ["*"]', function () {
		const vm = new NodeVM({ require: { external: false, builtin: ['*'] } });
		const res = vm.run(`
			try { require('node:test'); module.exports = 'LOADED'; } catch (e) { module.exports = 'denied'; }
		`);
		assert.strictEqual(res, 'denied', 'node:test reachable via wildcard builtin');
	});

	it.cond('the run({execArgv}) host-RCE PoC spawns no host process', HAS_NODE_TEST, function (done) {
		this.timeout(6000);
		const MARKER = path.join(os.tmpdir(), 'qhwx-test-' + process.pid + '-' + Date.now() + '.txt');
		const TESTFILE = path.join(os.tmpdir(), 'qhwx-tf-' + process.pid + '-' + Date.now() + '.js');
		try { fs.unlinkSync(MARKER); } catch (e) {}
		fs.writeFileSync(TESTFILE, '// inert\n');
		const vm = new NodeVM({ sandbox: { TESTFILE, MARKER }, require: { external: false, builtin: ['node:test'] } });
		try {
			vm.run(`
				let t; try { t = require('node:node:test'); } catch (e) { t = require('node:test'); }
				const payload = 'require("fs").writeFileSync(' + JSON.stringify(MARKER) + ', "PWNED")';
				const s = t.run({ files: [TESTFILE], execArgv: ['--eval=' + payload] });
				if (s && s.on) { s.on('data', () => {}); s.on('error', () => {}); }
			`);
		} catch (e) { /* require denied — expected */ }
		setTimeout(() => {
			const exists = fs.existsSync(MARKER);
			try { fs.unlinkSync(MARKER); } catch (e) {}
			try { fs.unlinkSync(TESTFILE); } catch (e) {}
			assert.strictEqual(exists, false, 'node:test.run spawned a host process that executed attacker code');
			done();
		}, 2500);
	});

	it('a benign explicitly-allowed builtin still loads', function () {
		const vm = new NodeVM({ require: { external: false, builtin: ['path'] } });
		const ok = vm.run(`const p = require('path'); module.exports = typeof p.join === 'function';`);
		assert.strictEqual(ok, true, 'a benign builtin (path) was wrongly denied');
	});
});
