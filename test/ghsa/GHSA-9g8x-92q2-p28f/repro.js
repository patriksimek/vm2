/**
 * GHSA-9g8x-92q2-p28f -- NodeVM process-wide observability builtins leak host state
 *
 *
 * ## Vulnerability
 * NodeVM allowed `require('diagnostics_channel')`, `require('async_hooks')`, and
 * `require('perf_hooks')` (and -- found during this fix -- `require('v8')`) to
 * resolve to the host module under the `builtin: ['*']` wildcard and any
 * explicit allowlist that named them. Unlike most Node builtins, these surface
 * state of the *entire host process*, not sandbox-local state:
 *
 *   - `diagnostics_channel.channel('http.server.request.start').subscribe(cb)`
 *     hands the sandbox raw host IncomingMessage objects -- Authorization /
 *     session-token headers included -- for every request the embedder receives.
 *   - `async_hooks.executionAsyncResource()` reveals the host's current
 *     AsyncResource; embedders routinely pin per-request user/auth state on it.
 *   - `perf_hooks.performance.getEntriesByType('mark')` reads every host
 *     `performance.mark(name)` value (often request/user IDs).
 *   - `v8.getHeapSnapshot()` / `v8.writeHeapSnapshot()` / `v8.queryObjects(Ctor)`
 *     enumerate the entire host V8 heap.
 *
 * The bridge cannot usefully proxy these away -- the data is host data by
 * definition. Reaching the host module at all is the escape.
 *
 * ## Fix
 * Treat process-wide observability builtins as `DANGEROUS_BUILTINS` in
 * lib/builtin.js. Same two-layer enforcement as GHSA-947f-4v7f-x2v8 / -r9pm:
 * filtered out of `BUILTIN_MODULES` (closes `'*'` wildcard) and rejected inside
 * `addDefaultBuiltin` (closes explicit names, object-map form, low-level
 * `makeBuiltins(['name'])`). `node:` prefix is normalized before lookup.
 * `SPECIAL_MODULES`, `mocks`, and `overrides` escape hatches are preserved so
 * embedders can register a sandbox-local wrapper under the same name.
 *
 * Invariant: "Any Node builtin that exposes host-process state rather than
 * sandbox-local state is not reachable from sandbox `require()` under the
 * default loader." Same structural test as the dangerous-builtins denylist:
 * regardless of how the embedder phrases the allowlist, the sandbox cannot
 * obtain a host-passthrough proxy for these modules.
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

const OBSERVABILITY_BUILTINS = ['diagnostics_channel', 'async_hooks', 'perf_hooks', 'v8'];

describe('GHSA-9g8x-92q2-p28f -- process-wide observability builtins are denied', () => {
	for (const name of OBSERVABILITY_BUILTINS) {
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

	describe('confirmed exploitation paths from the advisory PoC', () => {
		// SECURITY: these tests assert the *primitive* the advisory PoC depends
		// on is unreachable. We don't actually wire up an HTTP server inside the
		// test -- if `require('diagnostics_channel')` itself fails, the entire
		// `channel(...).subscribe(cb)` chain is unreachable too.
		it('diagnostics_channel.channel().subscribe is unreachable', () => {
			expectBuiltinBlocked(
				'diagnostics_channel-subscribe',
				{builtin: ['*']},
				`
				try {
					const dc = require('diagnostics_channel');
					const ch = dc.channel('http.server.request.start');
					if (typeof ch.subscribe === 'function') module.exports = 'ESCAPED';
					else module.exports = 'BLOCKED';
				} catch (e) { module.exports = 'BLOCKED'; }
			`
			);
		});

		it('async_hooks.executionAsyncResource is unreachable', () => {
			expectBuiltinBlocked(
				'async_hooks-executionAsyncResource',
				{builtin: ['*']},
				`
				try {
					const ah = require('async_hooks');
					if (typeof ah.executionAsyncResource === 'function') module.exports = 'ESCAPED';
					else module.exports = 'BLOCKED';
				} catch (e) { module.exports = 'BLOCKED'; }
			`
			);
		});

		it('perf_hooks.performance.getEntriesByType is unreachable', () => {
			expectBuiltinBlocked(
				'perf_hooks-getEntriesByType',
				{builtin: ['*']},
				`
				try {
					const ph = require('perf_hooks');
					if (ph.performance && typeof ph.performance.getEntriesByType === 'function') module.exports = 'ESCAPED';
					else module.exports = 'BLOCKED';
				} catch (e) { module.exports = 'BLOCKED'; }
			`
			);
		});

		it('v8.getHeapSnapshot / writeHeapSnapshot are unreachable', () => {
			expectBuiltinBlocked(
				'v8-heap-snapshot',
				{builtin: ['*']},
				`
				try {
					const v8 = require('v8');
					if (typeof v8.getHeapSnapshot === 'function' || typeof v8.writeHeapSnapshot === 'function') module.exports = 'ESCAPED';
					else module.exports = 'BLOCKED';
				} catch (e) { module.exports = 'BLOCKED'; }
			`
			);
		});
	});

	describe('low-level makeBuiltins API', () => {
		// SECURITY: covers `makeBuiltins([...])` consumers that build their own
		// resolver. The `addDefaultBuiltin` denial closes this path too.
		it('makeBuiltins([...observability]) registers none of them', () => {
			const map = makeBuiltins(OBSERVABILITY_BUILTINS, require);
			for (const name of OBSERVABILITY_BUILTINS) {
				assert.strictEqual(map.has(name), false, `${name} must be absent from the builtins map`);
			}
		});
	});

	describe('non-observability builtins still load', () => {
		// Regression guard: the denylist must not over-fire onto unrelated names
		// that happen to share a prefix or namespace.
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
		// SECURITY: embedders who genuinely need a sandbox-local replacement
		// (e.g. a controlled perf_hooks stub that only exposes sandbox-internal
		// timing) can still register one. The denylist rejects the *default
		// host-passthrough loader*, not user-supplied wrappers.
		it('mock diagnostics_channel is honored', () => {
			const vm = new NodeVM({
				require: {
					builtin: ['*'],
					external: false,
					mock: {diagnostics_channel: {safe: 42}}
				}
			});
			assert.strictEqual(vm.run("module.exports = require('diagnostics_channel').safe"), 42);
		});

		it('mock v8 is honored', () => {
			const vm = new NodeVM({
				require: {
					builtin: ['*'],
					external: false,
					mock: {v8: {tag: 'sandbox-safe'}}
				}
			});
			assert.strictEqual(vm.run("module.exports = require('v8').tag"), 'sandbox-safe');
		});
	});
});
