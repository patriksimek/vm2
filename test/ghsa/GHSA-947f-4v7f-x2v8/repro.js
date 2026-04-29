/**
 * GHSA-947f-4v7f-x2v8 — NodeVM builtin allowlist bypass via host-passthrough builtins
 *
 *
 * ## Vulnerability
 * NodeVM allowed `require('module')` (and several other host-passthrough
 * builtins) under the `'*'` wildcard expansion. The bridge's ReadOnlyHandler
 * forwards `apply` calls to the host realm, so sandbox code could call
 * `Module._load('child_process')` and bypass the entire allowlist — full host
 * RCE. The same applies to `worker_threads`, `cluster`, `vm`, `repl`, and
 * `inspector`.
 *
 * ## Fix
 * Two-layer denylist in lib/builtin.js: a `DANGEROUS_BUILTINS` Set is filtered
 * out of `BUILTIN_MODULES` (closes the `'*'` wildcard expansion) and rejected
 * inside `addDefaultBuiltin` (closes explicit-name and `makeBuiltins(...)`
 * paths). `SPECIAL_MODULES`, `mocks`, and `overrides` escape hatches are
 * preserved.
 */

// SECURITY REGRESSION TEST -- GHSA-947f-4v7f-x2v8
//
// Vulnerability: NodeVM `builtin` allowlist bypass via sandbox-bypass primitive
// builtins.
//
// Several Node.js builtins are sandbox-bypass primitives by design -- their
// primary capability is to reach host code regardless of the vm2 boundary:
//
//   - module          -> Module._load(name) loads ANY host builtin/external
//                        module, completely ignoring the `builtin` allowlist.
//                        Canonical PoC: `Module._load('child_process')` -> RCE.
//   - worker_threads  -> `new Worker(src, {eval: true})` runs arbitrary JS in
//                        a fresh thread that has no vm2 sandbox at all.
//   - cluster         -> `cluster.fork()` spawns a host child process.
//   - vm              -> `vm.runInThisContext(src)` evaluates code in the
//                        host realm, bypassing every bridge proxy.
//   - repl            -> `repl.start()` exposes an interactive evaluator on
//                        host streams.
//   - inspector       -> attaches a debugger to the host process.
//
// Pre-fix, `BUILTIN_MODULES` (sourced from `require('module').builtinModules`)
// contained all of these, so `builtin: ['*', '-child_process']` -- the
// documented "allow everything except dangerous ones" pattern -- silently
// allowed `require('module')` and via `Module._load` ANY other builtin.
//
// Structural fix (lib/builtin.js):
//   1. `DANGEROUS_BUILTINS` denylist filtered out of `BUILTIN_MODULES` so the
//      `'*'` wildcard never expands to them.
//   2. `addDefaultBuiltin` rejects dangerous keys even when explicitly named
//      (`builtin: ['module']`, `makeBuiltins(['worker_threads'])`).
//   3. `SPECIAL_MODULES` and `mocks`/`overrides` are still honored, so a user
//      who genuinely needs e.g. a stubbed `module` can register one.
//
// Invariant enforced: "The `builtin` allowlist is the single source of truth
// for which Node builtins the sandbox can reach. No allowed builtin may itself
// expose a primitive that loads, spawns, or evaluates host code outside the
// allowlist."

'use strict';

const assert = require('assert');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { NodeVM } = require('../../../lib/main.js');
const { makeBuiltins } = require('../../../lib/builtin.js');

// Use a benign filesystem marker as the "RCE" payload. If the sandbox can
// reach `child_process.execSync` on the host, the marker file gets written
// to the OS tmpdir; the test fails by detecting the file. No live RCE
// strings or secrets are involved.
function freshMarker() {
	const p = path.join(
		os.tmpdir(),
		`vm2-ghsa-947f-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}.marker`,
	);
	try {
		fs.unlinkSync(p);
	} catch (e) {
		/* ignore */
	}
	return p;
}

function noMarker(p) {
	try {
		fs.statSync(p);
		return false;
	} catch (e) {
		return true;
	}
}

function expectBuiltinBlocked(name, requireOpts, sandboxCode) {
	const vm = new NodeVM({ require: Object.assign({ external: false }, requireOpts) });
	let escaped = null;
	let thrown = null;
	try {
		escaped = vm.run(sandboxCode, 'poc.js');
	} catch (e) {
		thrown = e;
	}
	// Either `require()` throws "Cannot find module ..." (preferred) or the
	// returned module is undefined / lacks the dangerous primitive. What MUST
	// NOT happen is that the sandbox observed a working `Module._load`,
	// `new Worker`, etc.
	assert.ok(
		thrown || escaped === 'BLOCKED',
		`[${name}] expected denial, got: ${typeof escaped === 'string' ? escaped.slice(0, 200) : escaped}`,
	);
}

describe('GHSA-947f-4v7f-x2v8 -- builtin allowlist bypass via dangerous builtins', () => {
	describe('module', () => {
		it("blocked under ['*', '-child_process']", () => {
			const marker = freshMarker();
			expectBuiltinBlocked(
				'module-wildcard-exclusion',
				{ builtin: ['*', '-child_process'] },
				`
				try {
					const M = require('module');
					const cp = M._load('child_process');
					cp.execSync('touch ${marker}');
					module.exports = 'ESCAPED';
				} catch (e) {
					module.exports = 'BLOCKED';
				}
			`,
			);
			assert.ok(noMarker(marker), 'host filesystem marker must NOT have been written');
		});

		it("blocked under ['*']", () => {
			const marker = freshMarker();
			expectBuiltinBlocked(
				'module-pure-wildcard',
				{ builtin: ['*'] },
				`
				try {
					const cp = require('module')._load('child_process');
					cp.execSync('touch ${marker}');
					module.exports = 'ESCAPED';
				} catch (e) { module.exports = 'BLOCKED'; }
			`,
			);
			assert.ok(noMarker(marker), 'host filesystem marker must NOT have been written');
		});

		it("blocked under explicit ['module']", () => {
			expectBuiltinBlocked(
				'module-explicit',
				{ builtin: ['module'] },
				`
				try {
					require('module');
					module.exports = 'ESCAPED';
				} catch (e) { module.exports = 'BLOCKED'; }
			`,
			);
		});

		it('blocked under node: prefix', () => {
			expectBuiltinBlocked(
				'module-node-prefix',
				{ builtin: ['*'] },
				`
				try {
					require('node:module');
					module.exports = 'ESCAPED';
				} catch (e) { module.exports = 'BLOCKED'; }
			`,
			);
		});

		it('blocked when builtins is an object map', () => {
			expectBuiltinBlocked(
				'module-object-map',
				{ builtin: { module: true } },
				`
				try {
					require('module');
					module.exports = 'ESCAPED';
				} catch (e) { module.exports = 'BLOCKED'; }
			`,
			);
		});
	});

	describe('worker_threads', () => {
		it("blocked under ['*']", () => {
			expectBuiltinBlocked(
				'worker_threads-wildcard',
				{ builtin: ['*'] },
				`
				try {
					const W = require('worker_threads').Worker;
					if (typeof W === 'function') module.exports = 'ESCAPED';
					else module.exports = 'BLOCKED';
				} catch (e) { module.exports = 'BLOCKED'; }
			`,
			);
		});

		it("blocked under explicit ['worker_threads']", () => {
			expectBuiltinBlocked(
				'worker_threads-explicit',
				{ builtin: ['worker_threads'] },
				`
				try {
					require('worker_threads');
					module.exports = 'ESCAPED';
				} catch (e) { module.exports = 'BLOCKED'; }
			`,
			);
		});
	});

	describe('cluster', () => {
		it("blocked under ['*']", () => {
			expectBuiltinBlocked(
				'cluster-wildcard',
				{ builtin: ['*'] },
				`
				try {
					const c = require('cluster');
					if (typeof c.fork === 'function') module.exports = 'ESCAPED';
					else module.exports = 'BLOCKED';
				} catch (e) { module.exports = 'BLOCKED'; }
			`,
			);
		});
	});

	describe('vm', () => {
		it("runInThisContext blocked under ['*']", () => {
			expectBuiltinBlocked(
				'vm-wildcard',
				{ builtin: ['*'] },
				`
				try {
					const v = require('vm');
					const out = v.runInThisContext('typeof process');
					module.exports = (out === 'object') ? 'ESCAPED' : 'BLOCKED';
				} catch (e) { module.exports = 'BLOCKED'; }
			`,
			);
		});
	});

	describe('repl', () => {
		it("blocked under ['*']", () => {
			expectBuiltinBlocked(
				'repl-wildcard',
				{ builtin: ['*'] },
				`
				try {
					const r = require('repl');
					if (typeof r.start === 'function') module.exports = 'ESCAPED';
					else module.exports = 'BLOCKED';
				} catch (e) { module.exports = 'BLOCKED'; }
			`,
			);
		});
	});

	describe('inspector', () => {
		it("blocked under explicit ['inspector']", () => {
			expectBuiltinBlocked(
				'inspector-explicit',
				{ builtin: ['inspector'] },
				`
				try {
					require('inspector');
					module.exports = 'ESCAPED';
				} catch (e) { module.exports = 'BLOCKED'; }
			`,
			);
		});
	});

	describe('low-level makeBuiltins API', () => {
		// SECURITY: also covers the lower-level `makeBuiltins(['module'])`
		// entry point used by `makeResolverFromLegacyOptions` consumers that
		// build their own resolver. The `addDefaultBuiltin` denial closes
		// this path too.
		it("makeBuiltins(['module']) does not register module", () => {
			const map = makeBuiltins(['module'], require);
			assert.strictEqual(map.has('module'), false, 'module must be absent from the builtins map');
		});

		it("makeBuiltins(['worker_threads', 'cluster', 'vm', 'repl', 'inspector']) registers none of them", () => {
			const map = makeBuiltins(['worker_threads', 'cluster', 'vm', 'repl', 'inspector'], require);
			assert.strictEqual(map.has('worker_threads'), false);
			assert.strictEqual(map.has('cluster'), false);
			assert.strictEqual(map.has('vm'), false);
			assert.strictEqual(map.has('repl'), false);
			assert.strictEqual(map.has('inspector'), false);
		});

		// SECURITY (post-GHSA-947f hardening): trace_events was found during
		// pre-tag red-team to abort the host process when createTracing is
		// called with a sandbox-Proxy array (C++ IsArray() assertion fails).
		// Added to the denylist so builtin: ['*'] no longer surfaces it.
		it("makeBuiltins(['trace_events']) does not register trace_events", () => {
			const map = makeBuiltins(['trace_events'], require);
			assert.strictEqual(map.has('trace_events'), false);
		});
	});

	describe('trace_events host-process abort DoS', () => {
		it("trace_events is denied under builtin: ['*']", () => {
			expectBuiltinBlocked(
				'trace_events-wildcard',
				{ builtin: ['*'] },
				`
				try {
					require('trace_events');
					module.exports = 'ESCAPED';
				} catch (e) { module.exports = 'BLOCKED'; }
			`,
			);
		});

		it("trace_events is denied under explicit ['trace_events']", () => {
			expectBuiltinBlocked(
				'trace_events-explicit',
				{ builtin: ['trace_events'] },
				`
				try {
					require('trace_events');
					module.exports = 'ESCAPED';
				} catch (e) { module.exports = 'BLOCKED'; }
			`,
			);
		});
	});

	describe('non-dangerous builtins still load', () => {
		it('fs', () => {
			const vm = new NodeVM({ require: { builtin: ['fs'], external: false } });
			assert.strictEqual(vm.run("module.exports = typeof require('fs').readFileSync"), 'function');
		});

		it('events', () => {
			const vm = new NodeVM({ require: { builtin: ['events'], external: false } });
			assert.strictEqual(vm.run("module.exports = typeof require('events').EventEmitter"), 'function');
		});

		it("path under ['*']", () => {
			const vm = new NodeVM({ require: { builtin: ['*'], external: false } });
			assert.strictEqual(vm.run("module.exports = typeof require('path').join"), 'function');
		});
	});

	describe('mocks/overrides escape hatch is preserved', () => {
		// SECURITY: deliberately allow users to register a SAFE wrapper under a
		// dangerous name. The denylist only blocks the default host-pass-through
		// loader; explicit `mock`/`override` entries set on the resolver bypass
		// `addDefaultBuiltin` entirely.
		it('mock module is honored', () => {
			const vm = new NodeVM({
				require: {
					builtin: ['*'],
					external: false,
					mock: { module: { safe: 42 } },
				},
			});
			assert.strictEqual(vm.run("module.exports = require('module').safe"), 42);
		});
	});
});
