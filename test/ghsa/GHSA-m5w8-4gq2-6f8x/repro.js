/**
 * GHSA-m5w8-4gq2-6f8x -- NodeVM `os` and `dns` builtins leak host state and
 * hijack the host process (sibling class of GHSA-9g8x-92q2-p28f)
 *
 *
 * ## Vulnerability
 * GHSA-9g8x-92q2-p28f added `diagnostics_channel`, `async_hooks`, `perf_hooks`,
 * and `v8` to `DANGEROUS_BUILTINS` as "process-wide observability builtins"
 * whose state belongs to the host process, not the sandbox. Two builtins in the
 * same class were left reachable under `builtin: ['*']` and any explicit
 * allowlist that named them:
 *
 *   - `os`  -- `os.userInfo()` returns the host process owner (uid/gid/username/
 *     homedir/shell); `os.networkInterfaces()` returns the host's full network
 *     topology; `os.hostname()`/`os.loadavg()`/`os.uptime()`/`os.freemem()` are
 *     host-wide telemetry. `os.setPriority()` is a *write* -- setpriority(2) on
 *     the host process.
 *   - `dns` -- `dns.setServers(['attacker:53'])` replaces the host's
 *     process-wide DNS resolver list in one line of sandbox code, hijacking
 *     every subsequent lookup the host makes. `dns.setDefaultResultOrder()` is a
 *     second process-wide write knob. `dns.getServers()`/`lookup()`/`resolve()`
 *     read and act from the host network identity.
 *
 * The `vm.readonly()` proxy cannot localise these: the data source is the host
 * kernel / host process, and the write APIs mutate global host state regardless
 * of how the call is proxied. Reaching the host module at all is the escape.
 *
 * ## Fix
 * Add `os` and `dns` to `DANGEROUS_BUILTINS` in lib/builtin.js. Same two-layer
 * enforcement as GHSA-9g8x: filtered out of `BUILTIN_MODULES` (closes the `'*'`
 * wildcard) and rejected inside `addDefaultBuiltin` (closes explicit names, the
 * object-map form, and the low-level `makeBuiltins(['name'])` API). The
 * `isDangerousBuiltin` family-prefix matcher normalises the `node:` prefix and
 * covers the `dns/promises` subpath automatically. `mock`/`override` escape
 * hatches are preserved.
 *
 * Invariant: "Any Node builtin that exposes host-process state rather than
 * sandbox-local state is not reachable from sandbox `require()` under the
 * default loader." (Defense Invariant #13 -- the NodeVM builtin allowlist is a
 * closed system.)
 */

'use strict';

const assert = require('assert');
const {NodeVM} = require('../../../lib/main.js');
const {makeBuiltins} = require('../../../lib/builtin.js');

function expectBuiltinBlocked(name, requireOpts, sandboxCode) {
	const vm = new NodeVM({require: Object.assign({external: false}, requireOpts)});
	let escaped = null;
	let thrown = null;
	try {
		escaped = vm.run(sandboxCode, 'poc.js');
	} catch (e) {
		thrown = e;
	}
	assert.ok(
		thrown || escaped === 'BLOCKED',
		`[${name}] expected denial, got: ${typeof escaped === 'string' ? escaped.slice(0, 200) : escaped}`
	);
}

const HOST_STATE_BUILTINS = ['os', 'dns'];

describe('GHSA-m5w8-4gq2-6f8x -- os/dns host-process builtins are denied', () => {
	for (const name of HOST_STATE_BUILTINS) {
		describe(name, () => {
			it("blocked under ['*']", () => {
				expectBuiltinBlocked(
					`${name}-wildcard`,
					{builtin: ['*']},
					`
					try {
						const m = require('${name}');
						module.exports = m ? 'ESCAPED' : 'BLOCKED';
					} catch (e) { module.exports = 'BLOCKED'; }
				`
				);
			});

			it("blocked under ['*', '-fs'] wildcard-with-exclusion", () => {
				expectBuiltinBlocked(
					`${name}-wildcard-exclusion`,
					{builtin: ['*', '-fs']},
					`
					try {
						require('${name}');
						module.exports = 'ESCAPED';
					} catch (e) { module.exports = 'BLOCKED'; }
				`
				);
			});

			it(`blocked under explicit ['${name}']`, () => {
				expectBuiltinBlocked(
					`${name}-explicit`,
					{builtin: [name]},
					`
					try {
						require('${name}');
						module.exports = 'ESCAPED';
					} catch (e) { module.exports = 'BLOCKED'; }
				`
				);
			});

			it('blocked under node: prefix', () => {
				expectBuiltinBlocked(
					`${name}-node-prefix`,
					{builtin: ['*']},
					`
					try {
						require('node:${name}');
						module.exports = 'ESCAPED';
					} catch (e) { module.exports = 'BLOCKED'; }
				`
				);
			});

			it('blocked when builtin is an object map', () => {
				const opts = {};
				opts[name] = true;
				expectBuiltinBlocked(
					`${name}-object-map`,
					{builtin: opts},
					`
					try {
						require('${name}');
						module.exports = 'ESCAPED';
					} catch (e) { module.exports = 'BLOCKED'; }
				`
				);
			});
		});
	}

	describe('dns/promises subpath is covered by the family-prefix matcher', () => {
		it("blocked under ['*']", () => {
			expectBuiltinBlocked(
				'dns/promises-wildcard',
				{builtin: ['*']},
				`
				try {
					require('dns/promises');
					module.exports = 'ESCAPED';
				} catch (e) { module.exports = 'BLOCKED'; }
			`
			);
		});

		it('blocked under node:dns/promises', () => {
			expectBuiltinBlocked(
				'dns/promises-node-prefix',
				{builtin: ['*']},
				`
				try {
					require('node:dns/promises');
					module.exports = 'ESCAPED';
				} catch (e) { module.exports = 'BLOCKED'; }
			`
			);
		});

		it("blocked under explicit ['dns/promises']", () => {
			expectBuiltinBlocked(
				'dns/promises-explicit',
				{builtin: ['dns/promises']},
				`
				try {
					require('dns/promises');
					module.exports = 'ESCAPED';
				} catch (e) { module.exports = 'BLOCKED'; }
			`
			);
		});
	});

	describe('confirmed exploitation paths from the advisory PoC', () => {
		// SECURITY: these assert the *primitive* each PoC depends on is
		// unreachable. If `require('os')` / `require('dns')` itself fails, the
		// whole `userInfo()` / `setServers()` chain is unreachable too.
		it('os.userInfo (host identity read) is unreachable', () => {
			expectBuiltinBlocked(
				'os-userInfo',
				{builtin: ['*']},
				`
				try {
					const os = require('os');
					if (typeof os.userInfo === 'function') module.exports = 'ESCAPED';
					else module.exports = 'BLOCKED';
				} catch (e) { module.exports = 'BLOCKED'; }
			`
			);
		});

		it('os.networkInterfaces (host topology read) is unreachable', () => {
			expectBuiltinBlocked(
				'os-networkInterfaces',
				{builtin: ['*']},
				`
				try {
					const os = require('os');
					if (typeof os.networkInterfaces === 'function') module.exports = 'ESCAPED';
					else module.exports = 'BLOCKED';
				} catch (e) { module.exports = 'BLOCKED'; }
			`
			);
		});

		it('os.setPriority (host process write) is unreachable', () => {
			expectBuiltinBlocked(
				'os-setPriority',
				{builtin: ['*']},
				`
				try {
					const os = require('os');
					if (typeof os.setPriority === 'function') module.exports = 'ESCAPED';
					else module.exports = 'BLOCKED';
				} catch (e) { module.exports = 'BLOCKED'; }
			`
			);
		});

		it('dns.setServers (host DNS hijack write) is unreachable', () => {
			expectBuiltinBlocked(
				'dns-setServers',
				{builtin: ['*']},
				`
				try {
					const dns = require('dns');
					if (typeof dns.setServers === 'function') module.exports = 'ESCAPED';
					else module.exports = 'BLOCKED';
				} catch (e) { module.exports = 'BLOCKED'; }
			`
			);
		});

		it('dns.setDefaultResultOrder (host process write) is unreachable', () => {
			expectBuiltinBlocked(
				'dns-setDefaultResultOrder',
				{builtin: ['*']},
				`
				try {
					const dns = require('dns');
					if (typeof dns.setDefaultResultOrder === 'function') module.exports = 'ESCAPED';
					else module.exports = 'BLOCKED';
				} catch (e) { module.exports = 'BLOCKED'; }
			`
			);
		});
	});

	describe('the advisory PoC cannot mutate real host state', () => {
		// SECURITY: the strongest regression -- run the literal advisory writes
		// and assert the host realm is unchanged afterwards. Pre-fix these
		// persisted past the bridge; post-fix the require() throws first.
		it('dns.setServers from the sandbox does not change the host resolver list', () => {
			const dnsHost = require('dns');
			const before = dnsHost.getServers();
			const vm = new NodeVM({require: {builtin: ['*'], external: false}});
			try {
				vm.run("require('dns').setServers(['127.0.0.1:5353', '8.8.4.4']);", 'dns.js');
			} catch (e) { /* expected: require denied */ }
			assert.deepStrictEqual(dnsHost.getServers(), before, 'host DNS resolver list must be unchanged');
		});
	});

	describe('low-level makeBuiltins API', () => {
		// SECURITY: covers consumers that build their own resolver via
		// `makeBuiltins([...])`. The `addDefaultBuiltin` denial closes this path.
		it('makeBuiltins([os, dns, dns/promises]) registers none of them', () => {
			const map = makeBuiltins(['os', 'dns', 'dns/promises'], require);
			for (const name of ['os', 'dns', 'dns/promises']) {
				assert.strictEqual(map.has(name), false, `${name} must be absent from the builtins map`);
			}
		});
	});

	describe('non-host-state builtins still load', () => {
		// Regression guard: the denylist must not over-fire onto unrelated names.
		it('fs is reachable', () => {
			const vm = new NodeVM({require: {builtin: ['fs'], external: false}});
			assert.strictEqual(vm.run("module.exports = typeof require('fs').readFileSync"), 'function');
		});

		it("path is reachable under ['*']", () => {
			const vm = new NodeVM({require: {builtin: ['*'], external: false}});
			assert.strictEqual(vm.run("module.exports = typeof require('path').join"), 'function');
		});
	});

	describe('mocks/overrides escape hatch is preserved', () => {
		// SECURITY: embedders who genuinely need a sandbox-local `os`/`dns`
		// (typically os.platform()/os.EOL/os.constants) can still register one.
		// The denylist rejects the *default host-passthrough loader*, not wrappers.
		it('mock os is honored', () => {
			const vm = new NodeVM({
				require: {builtin: ['*'], external: false, mock: {os: {EOL: '\n', tag: 'sandbox-safe'}}}
			});
			assert.strictEqual(vm.run("module.exports = require('os').tag"), 'sandbox-safe');
		});

		it('mock dns is honored', () => {
			const vm = new NodeVM({
				require: {builtin: ['*'], external: false, mock: {dns: {tag: 'sandbox-safe'}}}
			});
			assert.strictEqual(vm.run("module.exports = require('dns').tag"), 'sandbox-safe');
		});
	});
});
