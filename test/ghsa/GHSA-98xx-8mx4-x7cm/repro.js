/**
 * GHSA-98xx-8mx4-x7cm — NodeVM can replace the host TLS trust store
 *
 * ## Vulnerability
 * A NodeVM allowing `tls` (+ `url`) exposes host `tls` read-only. Read-only
 * blocks assignment but forwards calls, so sandbox code can call
 * `tls.setDefaultCACertificates(list)` and replace the host thread's process-wide
 * default CA trust store — subsequent host TLS clients then accept attacker-signed
 * certificates. The native function needs a real host array, which the sandbox
 * forges with `url`'s `URLSearchParams.getAll()` (the bridge unwraps it back to a
 * host array).
 *
 * ## Fix
 * lib/builtin.js sanitizes `tls` before the read-only wrap, replacing
 * `setDefaultCACertificates` with a stub that throws — the host trust store can
 * no longer be mutated from the sandbox.
 *
 * Sound oracle: the host-side `tls.getCACertificates('default')` snapshot must be
 * identical before and after the sandbox attack.
 */

'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const tls = require('tls');
const { NodeVM } = require('../../../lib/main.js');

const hasApi = typeof tls.setDefaultCACertificates === 'function'
	&& typeof tls.getCACertificates === 'function';

function makeCa(dir) {
	const cert = path.join(dir, 'ca.pem');
	const key = path.join(dir, 'ca.key');
	try {
		execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes',
			'-keyout', key, '-out', cert, '-days', '1', '-subj', '/CN=vm2-98xx-test'],
			{ stdio: 'ignore' });
	} catch (e) { return null; }
	try { return fs.readFileSync(cert, 'utf8'); } catch (e) { return null; }
}

(hasApi ? describe : describe.skip)('GHSA-98xx-8mx4-x7cm — tls.setDefaultCACertificates', function () {
	this.timeout(20000);
	let dir, caPem, original;

	before(function () {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vm2-98xx-'));
		caPem = makeCa(dir);
		if (!caPem) this.skip();
		original = tls.getCACertificates('default');
	});

	after(function () {
		// Defensive: restore the host default trust store if anything changed it.
		try { if (original) tls.setDefaultCACertificates(original); } catch (e) {}
		if (dir) try { fs.rmSync(dir, { recursive: true, force: true }); } catch (e) {}
	});

	it('cannot replace the host default CA trust store', function () {
		const before = tls.getCACertificates('default').join('|');
		const vm = new NodeVM({ require: { builtin: ['tls', 'url'] }, sandbox: { CA: caPem } });
		let threw = false;
		try {
			vm.run(`
				const tls = require('tls');
				const { URLSearchParams } = require('url');
				const hostArray = new URLSearchParams('ca=' + encodeURIComponent(CA)).getAll('ca');
				tls.setDefaultCACertificates(hostArray);
			`, 'attack.js');
		} catch (e) { threw = true; }
		const after = tls.getCACertificates('default').join('|');
		assert.strictEqual(threw, true, 'setDefaultCACertificates should be neutralized (throw)');
		assert.strictEqual(after, before, 'host default CA trust store was mutated from the sandbox');
		// And the attacker CA specifically must not be present.
		assert.strictEqual(tls.getCACertificates('default').some(c => c.includes('vm2-98xx-test') || c === caPem), false,
			'attacker CA leaked into the host trust store');
	});

	it('does not over-block: the rest of tls still works', function () {
		const vm = new NodeVM({ require: { builtin: ['tls'] } });
		const out = vm.run(`const tls = require('tls');
			module.exports = { ciphers: Array.isArray(tls.getCiphers()), ctx: typeof tls.createSecureContext, setter: typeof tls.setDefaultCACertificates };`, 'ok.js');
		assert.strictEqual(out.ciphers, true);
		assert.strictEqual(out.ctx, 'function');
		assert.strictEqual(out.setter, 'function'); // present but throws, not silently removed
	});
});
