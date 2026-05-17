/**
 * GHSA-r9pm-gxmw-wv6p — NodeVM network builtin exclusions bypass via internal _http_client / _http_server
 *
 *
 * ## Vulnerability
 * `BUILTIN_MODULES` in `lib/builtin.js` is sourced from
 * `require('module').builtinModules` filtered by `s => !s.startsWith('internal/') &&
 * !DANGEROUS_BUILTINS.has(s)`. This source feeds the `'*'` wildcard expansion in
 * `makeBuiltinsFromLegacyOptions` — so every Node builtin that survives the filter
 * is implicitly handed to the sandbox.
 *
 * Node exposes a parallel family of underscored builtins (`_http_client`,
 * `_http_server`, `_http_agent`, `_http_common`, `_http_incoming`,
 * `_http_outgoing`, `_tls_common`, `_tls_wrap`, `_stream_*`). These are the
 * private implementation modules that back `http`, `https`, and `tls`. They are
 * not documented public API but they ARE in `require('module').builtinModules`
 * and they DO expose the network primitives directly:
 *
 *   require('_http_client').ClientRequest(opts)  -> outbound HTTP request
 *   require('_http_server').Server(...).listen() -> listening HTTP socket
 *
 * Pre-fix, `builtin: ['*', '-http', '-https', '-net', '-dgram', '-tls',
 * '-dns', '-dns/promises', '-http2']` — the documented "allow everything
 * except network" pattern — silently allowed every `_http_*` and `_tls_*`
 * sibling, fully bypassing the embedder's network restriction. SSRF-class
 * impact (CVSS 8.6: localhost services, cloud metadata endpoints, internal
 * admin panels).
 *
 * ## Fix
 * Filter out modules whose name starts with `_` from `BUILTIN_MODULES`. The
 * `'*'` wildcard no longer expands to any underscored sibling, so excluding
 * `http` / `net` / `tls` via `-name` is once again coherent. Explicit
 * opt-in (`builtin: ['_http_client']`) and `mock`/`override` registrations
 * remain functional — power users who genuinely need an internal sibling
 * can still name it. The `node:_http_client` form also stops working under
 * the wildcard because the builtins map is the single source of truth and
 * `loadBuiltinModule` returns undefined for any key not in the map.
 *
 * Invariant enforced: "The `'*'` wildcard expands only to documented public
 * Node builtins. Undocumented underscored siblings of network modules MUST
 * NOT be reachable from sandbox code under the wildcard expansion."
 */

'use strict';

const assert = require('assert');
const {NodeVM} = require('../../../lib/main.js');
const {makeBuiltins} = require('../../../lib/builtin.js');

// Underscored builtins that wrap public network modules. These must never be
// reachable from the sandbox under the `'*'` wildcard expansion.
const UNDERSCORED_NETWORK = [
	'_http_agent',
	'_http_client',
	'_http_common',
	'_http_incoming',
	'_http_outgoing',
	'_http_server',
	'_tls_common',
	'_tls_wrap'
];

function runRequire(vm, name) {
	return vm.run(`
		try {
			const m = require(${JSON.stringify(name)});
			module.exports = {ok: true, hasClientRequest: typeof (m && m.ClientRequest) === 'function', hasServer: typeof (m && m.Server) === 'function'};
		} catch (e) {
			module.exports = {ok: false, code: e && e.code, message: e && e.message};
		}
	`);
}

describe('GHSA-r9pm-gxmw-wv6p -- underscored network builtins bypass via wildcard', () => {

	describe('underscored network builtins are blocked under wildcard', () => {

		it("`builtin: ['*']` does NOT expose _http_client", () => {
			const vm = new NodeVM({require: {builtin: ['*'], external: false}});
			const r = runRequire(vm, '_http_client');
			assert.strictEqual(r.ok, false, `_http_client must NOT load, got ${JSON.stringify(r)}`);
		});

		it("`builtin: ['*']` does NOT expose _http_server", () => {
			const vm = new NodeVM({require: {builtin: ['*'], external: false}});
			const r = runRequire(vm, '_http_server');
			assert.strictEqual(r.ok, false, `_http_server must NOT load, got ${JSON.stringify(r)}`);
		});

		it("`builtin: ['*', '-http', '-https', '-net', '-tls']` does NOT expose any _http_*/_tls_* sibling (canonical PoC scenario)", () => {
			const vm = new NodeVM({
				require: {
					builtin: ['*', '-http', '-https', '-net', '-dgram', '-tls', '-dns', '-dns/promises', '-http2'],
					external: false
				}
			});
			for (const name of UNDERSCORED_NETWORK) {
				const r = runRequire(vm, name);
				assert.strictEqual(r.ok, false, `${name} must NOT load under network-excluded wildcard, got ${JSON.stringify(r)}`);
			}
		});

		it("`builtin: ['*']` does NOT expose underscored network builtins via the `node:` prefix", () => {
			const vm = new NodeVM({require: {builtin: ['*'], external: false}});
			for (const name of UNDERSCORED_NETWORK) {
				const r = runRequire(vm, `node:${name}`);
				assert.strictEqual(r.ok, false, `node:${name} must NOT load, got ${JSON.stringify(r)}`);
			}
		});

		it('underscored stream internals are also excluded from the wildcard', () => {
			const vm = new NodeVM({require: {builtin: ['*'], external: false}});
			for (const name of ['_stream_readable', '_stream_writable', '_stream_duplex', '_stream_transform', '_stream_wrap']) {
				const r = runRequire(vm, name);
				assert.strictEqual(r.ok, false, `${name} must NOT load under wildcard, got ${JSON.stringify(r)}`);
			}
		});

	});

	describe('canonical PoC: ClientRequest / Server primitives are unreachable', () => {

		// Direct reproduction of the canonical PoC: load _http_client and
		// verify the `ClientRequest` constructor — the actual escape primitive
		// — is not handed to the sandbox.
		it('_http_client.ClientRequest is not callable from the sandbox', () => {
			const vm = new NodeVM({
				require: {
					builtin: ['*', '-http', '-https', '-net', '-dgram', '-tls', '-dns', '-dns/promises', '-http2'],
					external: false
				}
			});
			const r = runRequire(vm, '_http_client');
			assert.strictEqual(r.ok, false);
		});

		it('_http_server.Server is not callable from the sandbox', () => {
			const vm = new NodeVM({
				require: {
					builtin: ['*', '-http', '-https', '-net', '-dgram', '-tls', '-dns', '-dns/promises', '-http2'],
					external: false
				}
			});
			const r = runRequire(vm, '_http_server');
			assert.strictEqual(r.ok, false);
		});

	});

	describe('low-level makeBuiltins API', () => {

		// Wildcard expansion happens in makeBuiltinsFromLegacyOptions. The
		// invariant is enforced at the source list, so a wildcard-equivalent
		// caller building from `BUILTIN_MODULES` should never receive an
		// underscored entry. We test the observable surface: `makeBuiltins`
		// with the underscored names still produces an entry (explicit opt-in
		// is preserved), but the wildcard-style `builtin: ['*']` path does not.
		it('explicit opt-in via makeBuiltins still works (power-user escape hatch)', () => {
			// SECURITY: do not over-block. A user who explicitly types
			// `builtin: ['_http_client']` is opting in knowingly. Only the
			// wildcard expansion is tightened.
			const map = makeBuiltins(['_http_client'], require);
			assert.strictEqual(map.has('_http_client'), true);
		});

	});

	describe('non-underscored builtins still load under wildcard', () => {

		it("fs loads under ['*']", () => {
			const vm = new NodeVM({require: {builtin: ['*'], external: false}});
			assert.strictEqual(vm.run("module.exports = typeof require('fs').readFileSync"), 'function');
		});

		it("path loads under ['*']", () => {
			const vm = new NodeVM({require: {builtin: ['*'], external: false}});
			assert.strictEqual(vm.run("module.exports = typeof require('path').join"), 'function');
		});

		it("events loads under ['*']", () => {
			const vm = new NodeVM({require: {builtin: ['*'], external: false}});
			assert.strictEqual(vm.run("module.exports = typeof require('events').EventEmitter"), 'function');
		});

	});

	describe('mocks/overrides escape hatch is preserved for underscored names', () => {

		it('mock _http_client is honored', () => {
			const vm = new NodeVM({
				require: {
					builtin: ['*'],
					external: false,
					mock: {_http_client: {safe: 7}}
				}
			});
			assert.strictEqual(vm.run("module.exports = require('_http_client').safe"), 7);
		});

	});

});
