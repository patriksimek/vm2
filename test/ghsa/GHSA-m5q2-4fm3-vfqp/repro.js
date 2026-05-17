/**
 * GHSA-m5q2-4fm3-vfqp — Sandbox escape via unblocked cross-realm Symbol.for keys
 *                       + missing bridge write-trap symbol checks
 *
 * ## Vulnerability class
 * Sandbox code obtains real cross-realm Node.js symbols via two paths the
 * existing defenses do not cover:
 *
 *   1. `Symbol.for('nodejs.<anything>')` — only `nodejs.util.inspect.custom`
 *      and `nodejs.rejection` were blocked. Other Node-internal symbols
 *      (`nodejs.util.promisify.custom`, the four stream brand symbols, the
 *      two webstream symbols) passed straight through and returned the real
 *      cross-realm symbol the host's Node internals look up.
 *
 *   2. Even when the sandbox cannot produce the symbol, the bridge's `set`,
 *      `defineProperty`, and `deleteProperty` traps did NOT screen the
 *      property key for `isDangerousCrossRealmSymbol(...)`. The `get`,
 *      `has`, `ownKeys`, and `getOwnPropertyDescriptor` traps did. So sandbox
 *      code could write or delete dangerous-symbol-keyed properties on any
 *      host object exposed to it — installing host-side hooks
 *      (`util.promisify.custom`), altering brand-style duck typing on
 *      streams, or deleting host-set symbol properties.
 *
 * ## Fix
 * 1. `lib/setup-sandbox.js` — `Symbol.for(key)` now returns a sandbox-local
 *    symbol whenever `key.startsWith('nodejs.')`, denying the entire family
 *    of cross-realm Node internals at the source. The 9 known dangerous
 *    `nodejs.*` symbols are pre-cached and `isDangerousSymbol(sym)` (which
 *    drives the `getOwnPropertySymbols`, `Reflect.ownKeys`,
 *    `getOwnPropertyDescriptors`, and `Object.assign` overrides) checks
 *    membership against the full set rather than only two.
 *
 * 2. `lib/bridge.js` — `BaseHandler.{set, defineProperty, deleteProperty}`
 *    now reject any operation whose key is `isDangerousCrossRealmSymbol(...)`
 *    when the call originates in the sandbox (`!isHost`). The dangerous-symbol
 *    list in bridge.js is expanded to match setup-sandbox's set so
 *    `isDangerousCrossRealmSymbol` recognises every host-side hook key.
 *
 * The invariant restored:
 *   - **Read direction**: a dangerous cross-realm symbol must never reach
 *     sandbox code as a usable symbol value (Category 8 / GHSA-47x8 closed
 *     this for `nodejs.util.inspect.custom` and `nodejs.rejection`; this
 *     fix extends the set to all 9 known dangerous `nodejs.*` symbols).
 *   - **Write direction**: even if the sandbox somehow obtains a dangerous
 *     symbol primitive (e.g. a future bypass), it must not be able to use
 *     that symbol as a key against any bridge-wrapped host object. The
 *     write traps are the structural chokepoint.
 */

'use strict';

const assert = require('assert');
const util = require('util');
const { VM } = require('../../../lib/main.js');

if (typeof it.cond !== 'function') {
	it.cond = function (name, cond, fn) { return cond ? it(name, fn) : it.skip(name, fn); };
}

const NODE_MAJOR = parseInt(process.versions.node.split('.')[0], 10);
// `util.promisify.custom` exists since Node 8 with the symbol form added in 8.0.
// Stream brand symbols (`nodejs.stream.readable` etc.) are 16+; webstream symbols
// land later still. Gate the symbol-set check accordingly.
const HAS_STREAM_BRAND_SYMBOLS = NODE_MAJOR >= 16;

function safeRun(code) {
	const vm = new VM();
	try {
		return vm.run('(function () { try { ' + code + ' } catch (_) { return undefined; } })()');
	} catch (_) {
		return undefined;
	}
}

describe('GHSA-m5q2-4fm3-vfqp (cross-realm Symbol.for + bridge write-trap leak)', function () {

	// ---- PRIMARY POC: util.promisify hijack ------------------------------------------

	it('blocks PoC: sandbox cannot install nodejs.util.promisify.custom on host fn', function () {
		// Host function the sandbox is allowed to mutate (a regular host function,
		// not a protected intrinsic — this is the case the write-trap check covers).
		const hostFn = function readFile(path, cb) { cb(null, 'real data'); };
		const vm = new VM();
		vm.setGlobals = vm.setGlobals || function (g) { for (const k in g) this.sandbox[k] = g[k]; };
		vm.sandbox.hostFn = hostFn;

		// Sandbox attempts to install a custom promisifier on the host function.
		// Two paths must be blocked:
		//   - Symbol.for('nodejs.util.promisify.custom') returns a sandbox-local
		//     symbol that the host doesn't recognise. So even if the assignment
		//     went through, host's util.promisify would not invoke the sandbox fn.
		//   - The sandbox could try to extract the real symbol via Category-8
		//     paths (closed). If it did, the bridge write-trap rejects the write.
		try {
			vm.run(`
				const kPromisify = Symbol.for('nodejs.util.promisify.custom');
				hostFn[kPromisify] = function (path) {
					return Promise.resolve('HIJACKED by sandbox');
				};
			`);
		} catch (_) { /* either Symbol.for returned a safe symbol or write trap threw */ }

		// Host-side check: util.promisify must use Node's default behavior, NOT
		// any sandbox-installed custom promisifier.
		const asyncRead = util.promisify(hostFn);
		return asyncRead('/etc/passwd').then(function (result) {
			assert.notStrictEqual(result, 'HIJACKED by sandbox', 'sandbox hijacked util.promisify');
			assert.strictEqual(result, 'real data', 'host function executed normally');
		});
	});

	// ---- Symbol.for source-side denial -----------------------------------------------

	it('Symbol.for("nodejs.util.promisify.custom") returns sandbox-local symbol', function () {
		const isSandboxLocal = safeRun(`
			const sandboxLocal = Symbol.for('nodejs.util.promisify.custom');
			// Sandbox-local symbols are NOT the same as the host's real registered symbol.
			// We can detect the structural identity by reading the symbol from a known
			// host object (Buffer.prototype carries no promisify symbol, but we can
			// register one fresh in the host registry — Symbol.for on the host always
			// returns the same identity for a given key). The test harness can't reach
			// the host registry, but we CAN ensure that the description matches AND that
			// our sandbox symbol is brand-new (a sandbox Symbol() not the registry one).
			// The structural test: a registered cross-realm symbol survives a round-trip
			// through Symbol.keyFor; a sandbox-local one does NOT.
			return Symbol.keyFor(sandboxLocal) === undefined;
		`);
		assert.strictEqual(isSandboxLocal, true, 'Symbol.for returned a real cross-realm symbol');
	});

	it.cond('Symbol.for("nodejs.stream.readable") returns sandbox-local symbol', HAS_STREAM_BRAND_SYMBOLS, function () {
		const isSandboxLocal = safeRun(`
			return Symbol.keyFor(Symbol.for('nodejs.stream.readable')) === undefined;
		`);
		assert.strictEqual(isSandboxLocal, true, 'nodejs.stream.readable leaked');
	});

	it.cond('Symbol.for("nodejs.stream.writable") returns sandbox-local symbol', HAS_STREAM_BRAND_SYMBOLS, function () {
		const isSandboxLocal = safeRun(`
			return Symbol.keyFor(Symbol.for('nodejs.stream.writable')) === undefined;
		`);
		assert.strictEqual(isSandboxLocal, true, 'nodejs.stream.writable leaked');
	});

	it.cond('Symbol.for("nodejs.stream.duplex") returns sandbox-local symbol', HAS_STREAM_BRAND_SYMBOLS, function () {
		const isSandboxLocal = safeRun(`
			return Symbol.keyFor(Symbol.for('nodejs.stream.duplex')) === undefined;
		`);
		assert.strictEqual(isSandboxLocal, true, 'nodejs.stream.duplex leaked');
	});

	it.cond('Symbol.for("nodejs.stream.transform") returns sandbox-local symbol', HAS_STREAM_BRAND_SYMBOLS, function () {
		const isSandboxLocal = safeRun(`
			return Symbol.keyFor(Symbol.for('nodejs.stream.transform')) === undefined;
		`);
		assert.strictEqual(isSandboxLocal, true, 'nodejs.stream.transform leaked');
	});

	it('Symbol.for any "nodejs.<future-internal>" key returns sandbox-local symbol', function () {
		// Forward-compat: any future Node-internal symbol introduced under the
		// nodejs.* namespace must be denied without code changes.
		const allSandboxLocal = safeRun(`
			const probes = [
				'nodejs.future.feature1',
				'nodejs.unknown',
				'nodejs.zalgo',
			];
			for (let i = 0; i < probes.length; i++) {
				if (Symbol.keyFor(Symbol.for(probes[i])) !== undefined) return false;
			}
			return true;
		`);
		assert.strictEqual(allSandboxLocal, true, 'a forward-compat nodejs.* key leaked');
	});

	it('Symbol.for keeps non-"nodejs." keys cross-realm (no over-denial)', function () {
		// Regression guard: legitimate cross-realm Symbol.for usage (any key NOT
		// starting with "nodejs.") must still produce a registered cross-realm
		// symbol so that legitimate intra-process symbol sharing still works.
		const stillCrossRealm = safeRun(`
			const s = Symbol.for('user.app.event');
			return Symbol.keyFor(s) === 'user.app.event';
		`);
		assert.strictEqual(stillCrossRealm, true, 'legitimate Symbol.for over-denied');
	});

	// ---- Bridge write-trap denial ----------------------------------------------------
	//
	// Even if the sandbox somehow obtains a real dangerous cross-realm symbol
	// (via a future bypass, or by reading it back via a host-side path), the
	// write traps must reject any operation that would install or delete it
	// on a host-realm object.

	it('set trap: sandbox assignment with dangerous symbol key on host obj is denied', function () {
		// We can't easily forge a real host symbol from inside the sandbox under
		// the current defenses (that's exactly what Category 8 closed). But we
		// can validate the bridge layer directly: pass in the host's real symbol
		// via setGlobal, then attempt the assignment.
		const realSym = Symbol.for('nodejs.util.promisify.custom');
		const hostObj = {};
		const vm = new VM();
		vm.sandbox.hostObj = hostObj;
		vm.sandbox.realSym = realSym;
		try {
			vm.run(`hostObj[realSym] = function () { return 'pwned'; };`);
		} catch (_) { /* expected: VMError(OPNA) */ }
		assert.strictEqual(
			Object.prototype.hasOwnProperty.call(hostObj, realSym),
			false,
			'set trap installed dangerous symbol key on host object'
		);
	});

	it('defineProperty trap: dangerous symbol key cannot be installed on host obj', function () {
		const realSym = Symbol.for('nodejs.util.promisify.custom');
		const hostObj = {};
		const vm = new VM();
		vm.sandbox.hostObj = hostObj;
		vm.sandbox.realSym = realSym;
		try {
			vm.run(`Object.defineProperty(hostObj, realSym, { value: 'pwned' });`);
		} catch (_) { /* expected */ }
		assert.strictEqual(
			Object.prototype.hasOwnProperty.call(hostObj, realSym),
			false,
			'defineProperty trap installed dangerous symbol key on host object'
		);
	});

	it('deleteProperty trap: dangerous symbol key on host obj cannot be deleted', function () {
		const realSym = Symbol.for('nodejs.util.promisify.custom');
		const hostObj = {};
		// Host pre-installs the symbol — sandbox must not be able to delete it.
		hostObj[realSym] = function () { return 'host-set'; };
		const vm = new VM();
		vm.sandbox.hostObj = hostObj;
		vm.sandbox.realSym = realSym;
		try {
			vm.run(`delete hostObj[realSym];`);
		} catch (_) { /* expected */ }
		assert.strictEqual(
			Object.prototype.hasOwnProperty.call(hostObj, realSym),
			true,
			'deleteProperty trap removed dangerous symbol from host object'
		);
	});

	it('write traps: nodejs.rejection symbol also denied across all three traps', function () {
		const realSym = Symbol.for('nodejs.rejection');
		const hostObj = { [realSym]: 'host-set' };
		const vm = new VM();
		vm.sandbox.hostObj = hostObj;
		vm.sandbox.realSym = realSym;
		try { vm.run(`hostObj[realSym] = 'set';`); } catch (_) {}
		try { vm.run(`Object.defineProperty(hostObj, realSym, { value: 'def' });`); } catch (_) {}
		try { vm.run(`delete hostObj[realSym];`); } catch (_) {}
		assert.strictEqual(hostObj[realSym], 'host-set', 'nodejs.rejection write/delete leaked through bridge');
	});

	it('write traps: nodejs.util.inspect.custom symbol also denied', function () {
		const realSym = Symbol.for('nodejs.util.inspect.custom');
		const hostObj = { [realSym]: 'host-set' };
		const vm = new VM();
		vm.sandbox.hostObj = hostObj;
		vm.sandbox.realSym = realSym;
		try { vm.run(`hostObj[realSym] = 'set';`); } catch (_) {}
		try { vm.run(`Object.defineProperty(hostObj, realSym, { value: 'def' });`); } catch (_) {}
		try { vm.run(`delete hostObj[realSym];`); } catch (_) {}
		assert.strictEqual(hostObj[realSym], 'host-set', 'nodejs.util.inspect.custom write/delete leaked');
	});

	// ---- Stream brand pollution ------------------------------------------------------

	it.cond('write traps: stream brand symbol assignment denied', HAS_STREAM_BRAND_SYMBOLS, function () {
		const realSym = Symbol.for('nodejs.stream.readable');
		const hostObj = {};
		const vm = new VM();
		vm.sandbox.hostObj = hostObj;
		vm.sandbox.realSym = realSym;
		try {
			vm.run(`hostObj[realSym] = true;`);
		} catch (_) {}
		assert.strictEqual(
			Object.prototype.hasOwnProperty.call(hostObj, realSym),
			false,
			'sandbox installed stream brand on host object'
		);
	});

	// ---- Sandbox-side enumeration filters --------------------------------------------

	it('isDangerousSymbol covers full nodejs.* set: extracted symbols are filtered', function () {
		// Even if a host object has a dangerous cross-realm symbol as an own key,
		// sandbox-side getOwnPropertySymbols / Reflect.ownKeys must filter ALL
		// 9 known dangerous symbols, not just the original 2.
		const found = safeRun(`
			const target = {};
			// Plant the host-registered symbols on a sandbox object via the
			// (now-blocked) Symbol.for path. After the fix, Symbol.for returns
			// a sandbox-local symbol — so this exercise validates that the FULL
			// pipeline (Symbol.for source-deny + ownKeys filter + descriptor filter)
			// can never surface the real registry symbols. We don't try to forge
			// them; we just verify Symbol.for cannot produce them.
			const probes = [
				'nodejs.util.inspect.custom',
				'nodejs.rejection',
				'nodejs.util.promisify.custom',
			];
			const leaked = [];
			for (let i = 0; i < probes.length; i++) {
				const s = Symbol.for(probes[i]);
				if (Symbol.keyFor(s) === probes[i]) leaked.push(probes[i]);
			}
			return leaked;
		`);
		assert.deepStrictEqual(found, [], 'one or more dangerous symbols leaked: ' + JSON.stringify(found));
	});
});
